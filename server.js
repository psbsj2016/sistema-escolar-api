const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');
const cron = require('node-cron'); // Importação essencial

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// Ensina o Express a confiar no proxy do Render
app.set('trust proxy', 1);

// =========================================================
// 🛡️ PROTEÇÃO MÁXIMA DE VARIÁVEIS DE AMBIENTE
// =========================================================
const JWT_SECRET = process.env.JWT_SECRET;
const uri = process.env.MONGODB_URI; 
const SENHA_DONO = process.env.SENHA_DONO;

if (!JWT_SECRET || !uri) {
    console.error("❌ ERRO FATAL DE SEGURANÇA: JWT_SECRET ou MONGODB_URI ausentes!");
    process.exit(1); 
}

// 1. HELMET: Proteção de Headers
app.use(helmet({ crossOriginResourcePolicy: false }));

// =========================================================
// 2. 🛡️ CORS BLINDADO (Domínios Oficiais + Reforço Manual)
// =========================================================
const dominiosPermitidos = [
    'https://www.sistemaptt.com.br',
    'https://sistemaptt.com.br',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'null'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || dominiosPermitidos.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`🛑 Bloqueado pelo CORS: ${origin}`);
            callback(new Error('Acesso negado (CORS).'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true 
}));

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && dominiosPermitidos.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
    } else {
        res.header("Access-Control-Allow-Origin", "*");
    }
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json({ limit: '10mb' })); 
app.use(mongoSanitize());

// =========================================================
// 🛡️ RATE LIMIT
// =========================================================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 800, 
    message: { error: 'Tráfego excessivo.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 15, 
    message: { error: 'Tentativas excessivas. Tente mais tarde.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use((req, res, next) => {
    if (req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/escola/') || req.path === '/') {
        return next();
    }
    return globalLimiter(req, res, next);
});

app.use('/auth/login', authLimiter);

// =========================================================
// 🧹 SANITIZAÇÃO XSS
// =========================================================
const sanitizeString = (str) => (typeof str !== 'string' ? str : str.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = (['senha', 'pin', 'novaSenha'].includes(key)) ? value : sanitizeObject(value);
    }
    return sanitized;
};

app.use((req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    next();
});

// =========================================================
// 📦 CONEXÃO MONGODB
// =========================================================
let dbInstance = null;
async function connectDB() {
    if (dbInstance) return dbInstance;
    try {
        const client = new MongoClient(uri);
        await client.connect();
        dbInstance = client.db('sistema-escolar');
        console.log("📦 MongoDB Conectado!");
        return dbInstance;
    } catch (error) {
        console.error("❌ Erro MongoDB:", error);
        throw error;
    }
}

// =========================================================
// 🔑 ROTA DE STATUS (PARA O CRON-JOB)
// =========================================================
app.get('/', (req, res) => {
    res.status(200).json({ status: "online", message: "API Sistema Escolar PTT 🚀" });
});

// =========================================================
// 🔑 MIDDLEWARE JWT
// =========================================================
app.use((req, res, next) => {
    // Adicionamos a liberação para rotas que começam com '/public/'
    if (req.path === '/' || req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/public/')) return next();
    
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Token não fornecido.' });
    const token = authHeader.split(' ')[1]; 
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada.' });
        req.userId = decoded.id; 
        req.escolaId = decoded.escolaId; 
        req.userTipo = decoded.tipo;
        next();
    });
});

// =========================================================
// 📄 ÁREA PÚBLICA (Matrículas Externas Automáticas)
// =========================================================

app.post('/public/receber-matricula', async (req, res) => {
    try {
        const { escolaId, ...dadosAluno } = req.body;

        if (!escolaId) {
            return res.status(400).json({ error: 'ID da escola não fornecido no formulário.' });
        }

        const database = await connectDB();

        // 🧠 O SEGREDO AQUI: O payload já vem pronto do HTML igualzinho ao seu app.js
        const novoAluno = {
            ...dadosAluno,
            id: Date.now().toString(),
            escolaId: escolaId,
            status: 'Ativo', // 🟢 Já entra "Ativo" para habilitar Carnês, Frequência e WhatsApp no painel!
            dataMatricula: new Date().toISOString()
        };

        // Salva diretamente na coleção que o seu painel lê!
        await database.collection('alunos').insertOne(novoAluno);

        console.log(`✅ Novo aluno matriculado automaticamente: ${dadosAluno.nome} (Escola: ${escolaId})`);

        res.status(200).json({ success: true, message: 'Matrícula ativada com sucesso!' });
    } catch (error) {
        console.error("❌ Erro ao salvar matrícula:", error);
        res.status(500).json({ error: 'Erro interno ao processar a matrícula.' });
    }
});

// =========================================================
// 📩 AUTH & CADASTRO
// =========================================================
const codigosAtivos = new Map();

app.post('/auth/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
    email = email.toLowerCase().trim();
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    try {
        await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email, subject: '🔐 Seu Código',
            html: `<div style="text-align:center;"><h2>Código: ${codigoGerado}</h2></div>`
        });
        codigosAtivos.set(email, codigoGerado);
        setTimeout(() => codigosAtivos.delete(email), 600000);
        const database = await connectDB();
        await database.collection('ativacoes').updateOne({ email }, { $set: { email, status: 'Pendente', dataRequisicao: new Date().toLocaleDateString('pt-BR') } }, { upsert: true });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro no servidor' }); }
});

app.post('/auth/validar-cadastro', async (req, res) => {
    let { email, codigo, pin } = req.body;
    email = email.toLowerCase().trim();
    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: new RegExp(`^${email}$`, 'i') });
    if (!ativacao || ativacao.pinAtivacao?.toUpperCase() !== pin.toUpperCase()) return res.status(401).json({ error: 'PIN incorreto.' });
    if (codigosAtivos.get(email) !== codigo) return res.status(401).json({ error: 'Código inválido.' });

    const escolaId = 'ESC-' + Date.now().toString(36).toUpperCase();
    const dataVencimento = new Date(); dataVencimento.setDate(dataVencimento.getDate() + 30);

    await database.collection('escola').updateOne({ email }, { $set: { escolaId, email, plano: ativacao.plano || 'Profissional', dataExpiracao: dataVencimento.toISOString() } }, { upsert: true });
    const senhaHash = await bcrypt.hash("123", 10);
    await database.collection('usuarios').insertOne({ id: Date.now().toString(), escolaId, login: email, senha: senhaHash, tipo: "Gestor", isDono: true });
    res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
    let { login, senha, deviceId } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: new RegExp(`^${login.replace('*FORCAR','')}$`, 'i') });
    if (!user || !(await bcrypt.compare(senha, user.senha))) return res.status(401).json({ error: 'Credenciais inválidas.' });
    
    const token = jwt.sign({ id: user.id, tipo: user.tipo, escolaId: user.escolaId }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ success: true, usuario: user, token });
});

// =========================================================
// 👑 MASTER
// =========================================================

// Middleware para verificar se é o Master
const verifyMaster = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Token não fornecido.' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded.master) return res.status(401).json({ error: 'Acesso não autorizado.' });
        next();
    });
};

app.post('/master/login', (req, res) => {
    if (req.body.senha === SENHA_DONO) {
        const token = jwt.sign({ master: true }, JWT_SECRET, { expiresIn: '2h' });
        return res.json({ success: true, token });
    }
    res.status(401).json({ error: 'Senha incorreta.' });
});

app.post('/master/gerar-pin', verifyMaster, async (req, res) => {
    const { email, plano } = req.body;
    const pin = 'PRO-' + Math.random().toString(36).substring(2, 6).toUpperCase();
    const database = await connectDB();
    await database.collection('ativacoes').updateOne({ email: email.toLowerCase() }, { $set: { email: email.toLowerCase(), pinAtivacao: pin, status: 'Pendente', plano } }, { upsert: true });
    res.json({ success: true, pin });
});

// NOVA ROTA: Listar todas as ativações (Escolas)
app.get('/master/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        // Remove object IDs to send clean JSON
        res.json(ativacoes.map(({ _id, ...rest }) => rest));
    } catch (error) {
        console.error("Erro ao buscar ativações:", error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// NOVA ROTA: Bloquear uma escola
app.post('/master/bloquear', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });

        const database = await connectDB();
        
        // Atualiza a coleção 'ativacoes'
        await database.collection('ativacoes').updateOne(
            { email: email.toLowerCase() },
            { $set: { status: 'Bloqueado' } }
        );

        // Opcional: Atualiza o status na coleção 'escola' também, se você usar isso lá
        await database.collection('escola').updateOne(
            { email: email.toLowerCase() },
            { $set: { plano: 'Bloqueado' } }
        );

        res.json({ success: true, message: 'Conta bloqueada' });
    } catch (error) {
        console.error("Erro ao bloquear:", error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// =========================================================
// 🏫 ESCOLA & USUÁRIOS (LEITURA E ESCRITA)
// =========================================================

// Rota para ler os dados da escola
app.get('/escola', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('escola').findOne({ escolaId: req.escolaId });
    if (data) delete data._id;
    res.json(data || {});
});

// 🚀 ADICIONA ESTA ROTA: Para salvar os dados da escola (Resolve o 404)
app.put('/escola', async (req, res) => {
    try {
        const database = await connectDB();
        const { _id, ...body } = req.body; // Remove o _id do MongoDB para não dar erro no update
        
        await database.collection('escola').updateOne(
            { escolaId: req.escolaId }, 
            { $set: body }, 
            { upsert: true }
        );
        
        res.json({ success: true, ...body });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao salvar dados da escola.' });
    }
});

// =========================================================
// 👥 ROTAS EXCLUSIVAS DE USUÁRIOS E SEGURANÇA
// =========================================================

// 1. Atualizar a própria conta (PRECISA VIR ANTES DO CRUD DINÂMICO)
app.put('/usuarios/atualizar-conta', async (req, res) => {
    const { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
    const database = await connectDB();
    
    const user = await database.collection('usuarios').findOne({ id: req.userId, escolaId: req.escolaId });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
    
    // Verifica se a senha atual está correta antes de deixar alterar
    const senhaValida = await bcrypt.compare(senhaAtual, user.senha);
    if (!senhaValida) return res.status(401).json({ error: 'Senha atual incorreta.' });
    
    const updateData = { login: novoLogin };
    if (novoEmail) updateData.email = novoEmail;
    
    // Se digitou uma nova senha, criptografa ela antes de salvar
    if (novaSenha) {
        updateData.senha = await bcrypt.hash(novaSenha, 10);
    }
    
    await database.collection('usuarios').updateOne({ id: req.userId }, { $set: updateData });
    res.json({ success: true });
});

// 2. Listar Usuários (Para preencher a tabela em "Minha Conta")
app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('usuarios').find({ escolaId: req.escolaId }).toArray();
    
    // Retorna a lista de usuários, mas REMOVE a hash da senha por segurança
    res.json(data.map(({ _id, senha, ...rest }) => rest));
});

// 3. Criar Novo Usuário (Equipe)
app.post('/usuarios', async (req, res) => {
    const database = await connectDB();
    const { senha, ...body } = req.body;
    
    const novoUsuario = { ...body, id: Date.now().toString(), escolaId: req.escolaId };
    
    // Criptografa a senha do novo membro da equipe
    if (senha) {
        novoUsuario.senha = await bcrypt.hash(senha, 10);
    }
    
    await database.collection('usuarios').insertOne(novoUsuario);
    delete novoUsuario.senha; 
    res.json(novoUsuario);
});

// 4. Editar Usuário da Equipe
app.put('/usuarios/:id', async (req, res) => {
    const database = await connectDB();
    const { _id, senha, ...body } = req.body;
    
    const updateData = { ...body };
    if (senha) {
        updateData.senha = await bcrypt.hash(senha, 10);
    }
    
    await database.collection('usuarios').updateOne({ id: req.params.id, escolaId: req.escolaId }, { $set: updateData });
    res.json({ success: true });
});

// 5. Excluir Usuário
app.delete('/usuarios/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection('usuarios').deleteOne({ id: req.params.id, escolaId: req.escolaId });
    res.json({ success: true });
});

// =========================================================
// 🔄 CRUD DINÂMICO (NoSQL SAFE)
// =========================================================
const COLECOES_OK = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'estoques'];

app.get('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).find({ escolaId: req.escolaId }).toArray();
    res.json(data.map(({_id, ...rest}) => rest));
});

app.get('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({ id: req.params.id, escolaId: req.escolaId });
    if (data) delete data._id;
    res.json(data || {});
});

app.post('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const body = { ...req.body, id: Date.now().toString(), escolaId: req.escolaId };
    await database.collection(req.params.collection).insertOne(body);
    res.json(body);
});

app.put('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    const { _id, ...body } = req.body;
    await database.collection(req.params.collection).updateOne({ id: req.params.id, escolaId: req.escolaId }, { $set: body });
    res.json(body);
});

app.delete('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id, escolaId: req.escolaId });
    res.json({ success: true });
});


// =========================================================
// 🚀 INICIALIZAÇÃO & CRON
// =========================================================
connectDB().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 API Sistema Escolar na porta ${PORT}`));
});