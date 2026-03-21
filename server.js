const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');

// 🛡️ ESCUDOS DE SEGURANÇA BANCÁRIA
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// 🛡️ TRAVA DE SEGURANÇA: EXIGE CHAVE NO AMBIENTE
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("🚨 ERRO FATAL: JWT_SECRET não configurada!");
    process.exit(1); 
}

app.use(helmet());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));
app.use(express.json({ limit: '10mb' })); 
app.use(mongoSanitize());

// =========================================================
// 🛡️ MOTOR DE QUALIDADE E SEGURANÇA DE DADOS (CORRIGIDO)
// =========================================================

const SCHEMAS_PERMITIDOS = {
    alunos: ['id', 'escolaId', 'donoId', 'nome', 'nascimento', 'rg', 'cpf', 'cep', 'rua', 'numero', 'bairro', 'cidade', 'estado', 'nomePai', 'nomeMae', 'telEmergencia', 'whatsapp', 'curso', 'turma', 'modulo', 'dataMatricula', 'diaVencimento', 'valorMensalidade', 'obs'],
    turmas: ['id', 'escolaId', 'donoId', 'nome', 'curso', 'dia', 'horario', 'professor', 'maxAlunos'],
    cursos: ['id', 'escolaId', 'donoId', 'nome', 'carga', 'modulos'],
    financeiro: ['id', 'escolaId', 'donoId', 'idCarne', 'idAluno', 'alunoNome', 'valor', 'vencimento', 'status', 'descricao', 'tipo', 'dataGeracao', 'pagamentoData', 'formaPagamento'],
    eventos: ['id', 'escolaId', 'donoId', 'data', 'tipo', 'descricao', 'inicio', 'fim'],
    chamadas: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'data', 'status', 'duracao'],
    avaliacoes: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'disciplina', 'data', 'tipo', 'valorMax', 'nota', 'bimestre', 'dataLancamento'],
    planejamentos: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'curso', 'aulas']
};

// 🚀 FIX: Função declarada explicitamente para evitar ReferenceError
function purificarDados(colecao, dadosBrutos) {
    const schema = SCHEMAS_PERMITIDOS[colecao];
    if (!schema) return dadosBrutos; 
    
    const dadosLimpos = {};
    for (const campo of schema) {
        if (dadosBrutos[campo] !== undefined) {
            dadosLimpos[campo] = dadosBrutos[campo];
        }
    }
    return dadosLimpos;
}

// =========================================================
// LIMITADORES E SANITIZAÇÃO GERAL
// =========================================================

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 800, 
    message: { error: 'Tráfego excessivo detetado.' }
});
app.use(globalLimiter);

const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/</g, '&lt;').replace(/>/g, '&gt;'); 
};

const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        if (['senha', 'senhaAtual', 'novaSenha', 'pin'].includes(key)) sanitized[key] = value;
        else sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
};

app.use((req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    next();
});

// =========================================================
// CONEXÃO DB E MIDDLEWARE JWT
// =========================================================

const uri = process.env.MONGODB_URI;
let client;
let clientPromise;

async function connectDB() {
    if (!clientPromise) {
        client = new MongoClient(uri);
        clientPromise = client.connect();
    }
    await clientPromise;
    return client.db('sistema-escolar');
}

app.use((req, res, next) => {
    if (req.path.startsWith('/auth/') || req.path.startsWith('/master/')) return next();
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Token não fornecido.' });
    const token = authHeader.split(' ')[1]; 
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada.' });
        req.userId = decoded.id; req.escolaId = decoded.escolaId; 
        next();
    });
});

// =========================================================
// ROTAS DE AUTENTICAÇÃO E ESCOLA
// =========================================================

const codigosAtivos = new Map();
app.post('/auth/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    try {
        await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Código de Verificação',
            html: `<h2>Código: ${codigoGerado}</h2>`
        });
        codigosAtivos.set(email, codigoGerado);
        setTimeout(() => codigosAtivos.delete(email), 600000);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro e-mail' }); }
});

app.post('/auth/login', async (req, res) => {
    const { login, senha } = req.body;
    try {
        const database = await connectDB();
        const usuario = await database.collection('usuarios').findOne({ login });
        if (!usuario) return res.status(401).json({ error: 'Incorreto' });
        const match = await bcrypt.compare(senha, usuario.senha);
        if (match) {
            const token = jwt.sign({ id: usuario.id, escolaId: usuario.escolaId }, JWT_SECRET, { expiresIn: '12h' });
            delete usuario.senha;
            res.json({ success: true, usuario, token });
        } else res.status(401).json({ error: 'Incorreto' });
    } catch (e) { res.status(500).json({ error: 'Erro' }); }
});

app.get('/escola', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('escola').findOne({ escolaId: req.escolaId }) || {};
    delete data._id; res.json(data);
});

app.put('/escola', async (req, res) => {
    const database = await connectDB();
    const body = purificarDados('escola', req.body);
    await database.collection('escola').updateOne({ escolaId: req.escolaId }, { $set: body }, { upsert: true });
    res.json(body);
});

// =========================================================
// ROTAS GENÉRICAS (ALUNOS, FINANC, ETC)
// =========================================================

const COLECOES_PERMITIDAS = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos'];
const validarColecao = (req, res, next) => {
    if (!COLECOES_PERMITIDAS.includes(req.params.collection)) return res.status(403).json({ error: 'Bloqueado' });
    next();
};

app.get('/:collection', validarColecao, async (req, res) => {
    const database = await connectDB();
    const data = await database.collection(req.params.collection).find({ escolaId: req.escolaId }).toArray();
    res.json(data.map(i => { delete i._id; return i; }));
});

app.post('/:collection', validarColecao, async (req, res) => {
    const database = await connectDB();
    let body = { ...req.body, escolaId: req.escolaId };
    if (!body.id) body.id = Date.now().toString();
    body = purificarDados(req.params.collection, body);
    await database.collection(req.params.collection).insertOne(body);
    res.json(body);
});

app.put('/:collection/:id', validarColecao, async (req, res) => {
    const database = await connectDB();
    let body = purificarDados(req.params.collection, req.body);
    await database.collection(req.params.collection).updateOne({ id: req.params.id, escolaId: req.escolaId }, { $set: body }, { upsert: true });
    res.json(body);
});

app.delete('/:collection/:id', validarColecao, async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id, escolaId: req.escolaId });
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`🚀 API SaaS Blindada na porta ${PORT}`); });