const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const crypto = require('crypto'); 

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.set('trust proxy', 1);

// =========================================================
// 🛡️ PROTEÇÃO MÁXIMA DE VARIÁVEIS DE AMBIENTE
// =========================================================
const JWT_SECRET = process.env.JWT_SECRET;
const uri = process.env.MONGODB_URI; 
const SENHA_DONO = process.env.SENHA_DONO;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://www.sistemaptt.com.br';

if (!JWT_SECRET || !uri) {
    console.error("❌ ERRO FATAL DE SEGURANÇA: JWT_SECRET ou MONGODB_URI ausentes!");
    process.exit(1); 
}

app.use(helmet({ crossOriginResourcePolicy: false }));

const dominiosPermitidos = [
    'https://www.sistemaptt.com.br',
    'https://sistemaptt.com.br',
    'http://localhost:3000',
    'http://localhost:5173',
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
        res.header("Access-Control-Allow-Origin", origin || "https://www.sistemaptt.com.br");
    }
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json({ limit: '10mb' })); 
app.use(cookieParser());
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
app.use('/master/login', authLimiter); 

// =========================================================
// 🧹 SANITIZAÇÃO XSS
// =========================================================
const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/onerror\s*=/gi, '')
        .replace(/onclick\s*=/gi, '')
        .replace(/onload\s*=/gi, '')
        .replace(/onmouseover\s*=/gi, '')
        .replace(/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, '')
        .replace(/<object[\s\S]*?>[\s\S]*?<\/object>/gi, '')
        .replace(/<embed[\s\S]*?>[\s\S]*?<\/embed>/gi, '')
        .replace(/<link[\s\S]*?>/gi, '')
        .replace(/<meta[\s\S]*?>/gi, '')
        .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
        .replace(/expression\s*\(/gi, '')
        .trim();
};

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
    if (req.path === '/' || req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/public/')) return next();
    
   const token = req.cookies.token_acesso;

if (!token) {
    return res.status(403).json({
        error: 'Sessão não encontrada.'
    });
}
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada.' });
        req.userId = decoded.id;
req.escolaId = decoded.escolaId || decoded.id;
req.userTipo = decoded.tipo;
next();
    });
});

function filtroTenant(req) {
    const ids = [];

    if (req.escolaId) ids.push(req.escolaId);
    if (req.userId) ids.push(req.userId);

    return {
        $or: [
            { escolaId: { $in: ids } },
            { donoId: { $in: ids } }
        ]
    };
}

// =========================================================
// 📄 ÁREA PÚBLICA (Matrículas Externas Automáticas)
// =========================================================

app.get('/public/escola/:id', async (req, res) => {
    try {
        const escolaId = req.params.id;
        const database = await connectDB();
        
        const escola = await database.collection('escola').findOne({ escolaId: escolaId });
        
        if (!escola) {
            return res.status(404).json({ error: 'Escola não encontrada.' });
        }

        res.status(200).json({
            escolaId: escola.escolaId,
            configMatricula: escola.configMatricula || null
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno ao carregar a página de matrícula.' });
    }
});

app.post('/public/receber-matricula', async (req, res) => {
    try {
        let { escolaId, ...dadosBrutos } = req.body;

if (!escolaId) {
    return res.status(400).json({ 
        success: false,
        error: 'ID da escola não fornecido no formulário.' 
    });
}

escolaId = String(escolaId).trim();

const database = await connectDB();

// ✅ Garante que o escolaId enviado pelo link existe de verdade
const escolaExiste = await database.collection('escola').findOne({ escolaId });

if (!escolaExiste) {
    return res.status(404).json({
        success: false,
        error: 'Escola não encontrada. Gere um novo link de matrícula dentro do sistema.',
        escolaIdRecebido: escolaId
    });
}

// ✅ Usa sempre o escolaId oficial encontrado no banco
escolaId = escolaExiste.escolaId;

const dadosPermitidos = {
            nome: dadosBrutos.nome || '',
            whatsapp: dadosBrutos.whatsapp || '',
            email: dadosBrutos.email || '',
            cpf: dadosBrutos.cpf || '',
            rg: dadosBrutos.rg || '',
            nascimento: dadosBrutos.nascimento || '',
            sexo: dadosBrutos.sexo || '',
            profissao: dadosBrutos.profissao || '',
            rua: dadosBrutos.rua || '',
            numero: dadosBrutos.numero || '',
            bairro: dadosBrutos.bairro || '',
            cidade: dadosBrutos.cidade || '',
            planoCurso: dadosBrutos.planoCurso || '',
            diaVencimento: dadosBrutos.diaVencimento || '',
            estado: dadosBrutos.estado || 'BA',
            pais: dadosBrutos.pais || 'Brasil',
            curso: dadosBrutos.curso || 'A definir',
            turma: dadosBrutos.turma || 'A definir',
            refLink: dadosBrutos.refLink || 'Direto',
            resp_nome: dadosBrutos.resp_nome || null,
            resp_parentesco: dadosBrutos.resp_parentesco || null,
            resp_cpf: dadosBrutos.resp_cpf || null,
            resp_zap: dadosBrutos.resp_zap || null,
            conteudoHTML: sanitizeString(dadosBrutos.conteudoHTML || '<p>Contrato não gerado.</p>')
        };

        const idAlunoGerado = crypto.randomUUID(); 

        const novoAluno = {
            ...dadosPermitidos,
            id: idAlunoGerado,
            escolaId: escolaId,
            status: 'Ativo', 
            dataMatricula: new Date().toISOString()
        };

        await database.collection('alunos').insertOne(novoAluno);
        
        const carimboDeTempo = new Date().toISOString();
        const enderecoFormatado = `${dadosPermitidos.rua || ''}, ${dadosPermitidos.numero || ''} - ${dadosPermitidos.bairro || ''}, ${dadosPermitidos.cidade || ''} - ${dadosPermitidos.estado || ''}, ${dadosPermitidos.pais || 'Brasil'}`;

        const novoContrato = {
            id: "DOC_" + crypto.randomUUID(),
            escolaId: escolaId,
            idAluno: idAlunoGerado,
            nomeAluno: dadosPermitidos.nome || 'Nome não informado',
            cpf: dadosPermitidos.cpf || 'Não informado',
            rg: dadosPermitidos.rg || 'Não informado',
            nascimento: dadosPermitidos.nascimento || 'Não informado',
            sexo: dadosPermitidos.sexo || 'Não informado',
            profissao: dadosPermitidos.profissao || 'Não informada',
            whatsapp: dadosPermitidos.whatsapp || 'Não informado',
            email: dadosPermitidos.email || 'Não informado',
            enderecoCompleto: enderecoFormatado,
            curso: dadosPermitidos.curso || 'Não informado',
            turma: dadosPermitidos.turma || 'Não informada',
            planoCurso: dadosPermitidos.planoCurso || 'Não informado',
            diaVencimento: dadosPermitidos.diaVencimento || 'Não informado',
            resp_nome: dadosPermitidos.resp_nome || 'O Próprio / Não informado',
            resp_parentesco: dadosPermitidos.resp_parentesco || 'Não informado',
            resp_cpf: dadosPermitidos.resp_cpf || 'Não informado',
            resp_zap: dadosPermitidos.resp_zap || 'Não informado',
            conteudoHTML: dadosPermitidos.conteudoHTML,
            dataHoraRegistro: carimboDeTempo,
            tipoDocumento: 'Termo de Matrícula Digital'
        };

        await database.collection('contratos').insertOne(novoContrato);

        // =======================================================
        // 🔔 NOTIFICAÇÃO OFICIAL PARA O SININHO (Apenas UMA vez)
        // =======================================================
        await database.collection('notificacoes').insertOne({
            id: "NOTI_" + crypto.randomUUID(),
            escolaId: escolaId,
            tipo: "matricula",
            titulo: "🎉 Nova Matrícula!",
            mensagem: `${dadosPermitidos.nome || 'Novo aluno'} acabou de garantir uma vaga.`,
            nomeAluno: dadosPermitidos.nome || '',
            idAlunoReferencia: idAlunoGerado,
            idContrato: novoContrato.id,
            refLink: dadosPermitidos.refLink || 'Direto',
            lida: false,
            dataCriacao: new Date().toISOString()
        });

        res.status(200).json({ 
    success: true, 
    message: 'Matrícula ativada com sucesso!',
    escolaId,
    alunoId: idAlunoGerado,
    contratoId: novoContrato.id
});
    } catch (error) {
        res.status(500).json({ error: 'Erro interno ao processar a matrícula.' });
    }
});

// =========================================================
// 🔓 LOGOUT SEGURO
// =========================================================
app.post('/auth/logout', (req, res) => {
    res.clearCookie('token_acesso', {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        domain: '.sistemaptt.com.br',
        path: '/'
    });
    res.json({ success: true });
});

// =========================================================
// 📩 AUTH & CADASTRO
// =========================================================

app.post('/auth/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
    
    email = email.toLowerCase().trim();
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    
    const validade = new Date();
    validade.setMinutes(validade.getMinutes() + 10);

    try {
        const { data, error } = await resend.emails.send({
            from: 'Sistema PTT <não responda @sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Seu Código de Acesso',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2>Seu código de verificação é:</h2>
                    <h1 style="color: #3498db; letter-spacing: 5px;">${codigoGerado}</h1>
                    <p>Este código expira em 10 minutos.</p>
                </div>
            `
        });

        if (error) {
            return res.status(400).json({ error: 'Falha ao enviar e-mail. Verifique o endereço.' });
        }

        const database = await connectDB();
        await database.collection('ativacoes').updateOne(
            { email }, 
            { 
                $set: { 
                    email, 
                    codigoValidacao: codigoGerado, 
                    expiracaoCodigo: validade,     
                    status: 'Pendente', 
                    dataRequisicao: new Date().toISOString() 
                } 
            }, 
            { upsert: true }
        );
        
        res.json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro interno ao tentar enviar o código.' }); 
    }
});

// 🚀 AQUI O STATUS MUDA PARA "VERIFICADO" QUANDO O CLIENTE FINALIZA O CADASTRO!
app.post('/auth/validar-cadastro', async (req, res) => {
    let { email, codigo, pin } = req.body;
    email = email.toLowerCase().trim();
    
    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: new RegExp(`^${email}$`, 'i') });
    
    if (!ativacao) return res.status(404).json({ error: 'Nenhuma solicitação encontrada para este e-mail.' });
    if (ativacao.pinAtivacao?.toUpperCase() !== pin.toUpperCase()) {
        return res.status(401).json({ error: 'PIN incorreto.' });
    }
    if (ativacao.codigoValidacao !== codigo) {
        return res.status(401).json({ error: 'Código inválido.' });
    }
    if (new Date() > new Date(ativacao.expiracaoCodigo)) {
         return res.status(401).json({ error: 'O código expirou. Solicite um novo.' });
    }

    const escolaId = 'ESC-' + crypto.randomUUID().split('-')[0].toUpperCase();
    const dataVencimento = new Date(); 
    dataVencimento.setDate(dataVencimento.getDate() + 30);

    await database.collection('escola').updateOne(
        { email }, 
        { $set: { escolaId, email, plano: ativacao.plano || 'Profissional', dataExpiracao: dataVencimento.toISOString() } }, 
        { upsert: true }
    );
    
    const senhaHash = await bcrypt.hash("123", 10);
    
    // 🔥 "QUEIMA" O PIN E SINALIZA ATIVO NO ADMIN
    await database.collection('ativacoes').updateOne(
        { email }, 
        { 
            $unset: { codigoValidacao: "", expiracaoCodigo: "" },
            $set: { 
                status: 'Ativo', 
                dataAtivacao: new Date().toISOString() 
            }
        }
    );

    await database.collection('usuarios').insertOne({ id: crypto.randomUUID(), escolaId, login: email, senha: senhaHash, tipo: "Gestor", isDono: true });
    
    res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
    let { login, senha, deviceId } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: new RegExp(`^${login.replace('*FORCAR','')}$`, 'i') });
    if (!user || !(await bcrypt.compare(senha, user.senha))) return res.status(401).json({ error: 'Credenciais inválidas.' });
    
    // ✅ Compatibilidade entre usuários antigos e novo padrão escolaId
let escolaIdFinal = user.escolaId;

// Procura uma escola oficial vinculada ao usuário, mesmo que ele já tenha escolaId antigo como "1"
const escolaVinculada = await database.collection('escola').findOne({
    $or: [
        { escolaId: user.escolaId },
        { email: new RegExp(`^${user.login}$`, 'i') },
        { email: new RegExp(`^${user.email || user.login}$`, 'i') },
        { donoId: user.id }
    ]
});

// Se encontrou uma escola oficial com escolaId tipo ESC-..., prioriza ela
if (escolaVinculada && escolaVinculada.escolaId) {
    escolaIdFinal = escolaVinculada.escolaId;

    await database.collection('usuarios').updateOne(
        { id: user.id },
        { $set: { escolaId: escolaIdFinal } }
    );

    user.escolaId = escolaIdFinal;
}

// Fallback final para não quebrar contas antigas sem escola cadastrada
if (!escolaIdFinal) {
    escolaIdFinal = user.id;
}

const usuarioSeguro = {
    ...user,
    escolaId: escolaIdFinal
};

delete usuarioSeguro.senha;

const token = jwt.sign(
    { id: user.id, tipo: user.tipo, escolaId: escolaIdFinal },
    JWT_SECRET,
    { expiresIn: '12h' }
);

res.cookie('token_acesso', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    domain: '.sistemaptt.com.br',
    maxAge: 12 * 60 * 60 * 1000,
    path: '/'
});

res.json({ success: true, usuario: usuarioSeguro });

});

// =========================================================
// ROTA: Recuperação de Senha por Link Temporário
// =========================================================
app.post('/auth/recuperar-senha', authLimiter, async (req, res) => {
    // ... Código mantido idêntico ao original (já estava perfeito) ...
    try {
        let { email } = req.body;
        if (!email) return res.status(400).json({ success: false, error: "Informe um e-mail." });
        email = email.toLowerCase().trim();
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({
            $or: [ { login: new RegExp(`^${email}$`, 'i') }, { email: new RegExp(`^${email}$`, 'i') } ]
        });

        if (!user || (user.status && user.status.toLowerCase() === 'inativo')) {
            return res.status(200).json({ success: true, message: "Se este e-mail estiver cadastrado, enviaremos um link." });
        }

        const tokenLimpo = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(tokenLimpo).digest('hex');
        const expiraEm = new Date(Date.now() + 30 * 60 * 1000); 

        await database.collection('password_resets').deleteMany({ userId: user.id });
        await database.collection('password_resets').insertOne({
            userId: user.id, escolaId: user.escolaId, email, tokenHash, expiraEm, usado: false, criadoEm: new Date()
        });

        const linkRedefinicao = `${FRONTEND_URL}/index.html?reset=${tokenLimpo}`;
        const { error } = await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email, subject: '🔐 Redefinição de Senha',
            html: `<div style="font-family: Arial, sans-serif; padding: 20px; color: #333;"><h2>Redefinição de Senha</h2><p>Clique abaixo para criar nova senha (expira em 30 min).</p><p><a href="${linkRedefinicao}" style="background:#3498db; color:#ffffff; padding:14px 22px; border-radius:8px; text-decoration:none; font-weight:bold;">Redefinir minha senha</a></p></div>`
        });

        if (error) return res.status(500).json({ success: false, error: "Erro ao enviar e-mail." });
        return res.status(200).json({ success: true, message: "Enviado com sucesso." });
    } catch (erro) {
        return res.status(500).json({ success: false, error: "Erro no servidor." });
    }
});

app.post('/auth/redefinir-senha', authLimiter, async (req, res) => {
    try {
        const { token, novaSenha } = req.body;
        if (!token || !novaSenha) return res.status(400).json({ success: false, error: "Dados obrigatórios." });
        if (String(novaSenha).length < 6) return res.status(400).json({ success: false, error: "A senha deve ter pelo menos 6 caracteres." });

        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const database = await connectDB();
        const reset = await database.collection('password_resets').findOne({ tokenHash, usado: false, expiraEm: { $gt: new Date() } });

        if (!reset) return res.status(401).json({ success: false, error: "Link inválido ou expirado." });
        const senhaHash = await bcrypt.hash(novaSenha, 10);

        await database.collection('usuarios').updateOne({ id: reset.userId, escolaId: reset.escolaId }, { $set: { senha: senhaHash } });
        await database.collection('password_resets').updateOne({ _id: reset._id }, { $set: { usado: true, usadoEm: new Date() } });
        await database.collection('password_resets').deleteMany({ userId: reset.userId, usado: false });

        return res.status(200).json({ success: true, message: "Senha redefinida." });
    } catch (erro) { return res.status(500).json({ success: false, error: "Erro interno." }); }
});

// =========================================================
// 👑 MASTER
// =========================================================

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
    const codigoSeguro = crypto.randomBytes(3).toString('hex').toUpperCase();
    const pin = 'PRO-' + codigoSeguro;
    
    const database = await connectDB();
    await database.collection('ativacoes').updateOne(
        { email: email.toLowerCase() }, 
        { $set: { email: email.toLowerCase(), pinAtivacao: pin, status: 'Pendente', plano } }, 
        { upsert: true }
    );
    res.json({ success: true, pin });
});

// 🚀 AQUI É A LISTA INTELIGENTE QUE FORÇA "VERIFICADO" SE A CONTA JÁ EXISTIR
app.get('/master/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();
        const usuarios = await database.collection('usuarios').find({ isDono: true }).toArray();

        const mapaContas = new Map();

        // 1. Pega quem tem licença
        ativacoes.forEach(a => {
            if(a.email) mapaContas.set(a.email.toLowerCase(), { ...a, _id: undefined });
        });

        // 2. Cruza os dados das escolas ativas e FORÇA o status Ativo
        escolas.forEach(e => {
            if (e.email) {
                const emailLower = e.email.toLowerCase();
                if (mapaContas.has(emailLower)) {
                    let conta = mapaContas.get(emailLower);
                    if(conta.status !== 'Bloqueado') { 
                        conta.status = 'Ativo'; 
                    }
                    conta.plano = e.plano || conta.plano;
                    mapaContas.set(emailLower, conta);
                } else {
                    mapaContas.set(emailLower, { email: e.email, plano: e.plano || 'Desconhecido', status: 'Ativo', pinAtivacao: 'FANTASMA 👻' });
                }
            }
        });

        // 3. Pega quem fez usuário de login
        usuarios.forEach(u => {
            if (u.login && !mapaContas.has(u.login.toLowerCase())) {
                mapaContas.set(u.login.toLowerCase(), { email: u.login, plano: 'Desconhecido', status: 'FANTASMA 👻', pinAtivacao: 'Sem Licença' });
            }
        });

        res.json(Array.from(mapaContas.values()));
    } catch (error) {
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

app.post('/master/bloquear', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });

        const database = await connectDB();
        await database.collection('ativacoes').updateOne( { email: email.toLowerCase() }, { $set: { status: 'Bloqueado' } } );
        await database.collection('escola').updateOne( { email: email.toLowerCase() }, { $set: { plano: 'Bloqueado' } } );

        res.json({ success: true, message: 'Conta bloqueada' });
    } catch (error) { res.status(500).json({ error: 'Erro interno no servidor' }); }
});
 
app.post('/master/excluir-conta', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });

        const targetEmail = email.toLowerCase().trim();
        const database = await connectDB();

        const escola = await database.collection('escola').findOne({ email: targetEmail });
        const usuario = await database.collection('usuarios').findOne({ login: targetEmail });
        const idParaApagar = (escola && escola.escolaId) ? escola.escolaId : ((usuario && usuario.escolaId) ? usuario.escolaId : null);

        if (idParaApagar) {
            const colecoesTenant = [ 'alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'usuarios', 'estoques' ];
            for (const col of colecoesTenant) {
                await database.collection(col).deleteMany({ escolaId: idParaApagar });
            }
        }

        await database.collection('escola').deleteMany({ email: targetEmail });
        await database.collection('usuarios').deleteMany({ login: targetEmail });
        await database.collection('usuarios').deleteMany({ email: targetEmail });
        await database.collection('ativacoes').deleteMany({ email: targetEmail });

        res.json({ success: true, message: 'Conta obliterada do banco.' });
    } catch (error) { res.status(500).json({ error: 'Erro interno no servidor' }); }
});

// =========================================================
// 🏫 ESCOLA & USUÁRIOS (LEITURA E ESCRITA)
// =========================================================

app.get('/escola', async (req, res) => {
    const database = await connectDB();

    const data = await database.collection('escola').findOne({
        $or: [
            { escolaId: req.escolaId },
            { donoId: req.userId }
        ]
    });

    if (data) delete data._id;
    res.json(data || {});
});

app.put('/escola', async (req, res) => {
    try {
        const database = await connectDB();
        const { _id, ...body } = req.body; 
        
        await database.collection('escola').updateOne(
    { escolaId: req.escolaId },
    { $set: { ...body, escolaId: req.escolaId } },
    { upsert: true }
);
        res.json({ success: true, ...body });
    } catch (error) { res.status(500).json({ error: 'Erro ao salvar.' }); }
});

// 🚀 AQUI ELE VALIDA O PIN DA RENOVAÇÃO E BLOQUEIA REUSO
app.post('/escola/validar-pin', async (req, res) => {
    try {
        const { pin } = req.body;
        if (!pin) return res.status(400).json({ error: 'PIN não informado.' });

        const database = await connectDB();
        
        // Verifica se o PIN existe e se ESTÁ PENDENTE (se já usou, vai dar erro 404!)
        const ativacao = await database.collection('ativacoes').findOne({ 
            pinAtivacao: pin.toUpperCase(),
            status: 'Pendente' 
        });

       if (ativacao) {
            await database.collection('ativacoes').updateOne(
                { _id: ativacao._id },
                { $set: { 
                    status: 'Ativo',
                    dataAtivacao: new Date().toISOString()
                } }
            );

            await database.collection('escola').updateOne(
                { escolaId: req.escolaId },
                { $set: { plano: ativacao.plano || 'Profissional' } }
            );

            return res.json({ success: true, plano: ativacao.plano || 'Profissional' });
        } else {
            return res.status(404).json({ error: 'PIN inválido ou já utilizado.' });
        }
    } catch (error) { res.status(500).json({ error: 'Erro interno ao validar PIN.' }); }
});

// =========================================================
// 👥 ROTAS EXCLUSIVAS DE USUÁRIOS E SEGURANÇA
// =========================================================

app.put('/usuarios/atualizar-conta', async (req, res) => {
    const { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ id: req.userId, escolaId: req.escolaId });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
    
    const senhaValida = await bcrypt.compare(senhaAtual, user.senha);
    if (!senhaValida) return res.status(401).json({ error: 'Senha atual incorreta.' });
    
    const updateData = { login: novoLogin };
    if (novoEmail) updateData.email = novoEmail;
    if (novaSenha) updateData.senha = await bcrypt.hash(novaSenha, 10);
    
    await database.collection('usuarios').updateOne({ id: req.userId }, { $set: updateData });
    res.json({ success: true });
});

app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('usuarios').find({ escolaId: req.escolaId }).toArray();
    res.json(data.map(({ _id, senha, ...rest }) => rest));
});

app.post('/usuarios', async (req, res) => {
    const database = await connectDB();
    const { senha, ...body } = req.body;
    const novoUsuario = { ...body, id: crypto.randomUUID(), escolaId: req.escolaId };
    if (senha) novoUsuario.senha = await bcrypt.hash(senha, 10);
    await database.collection('usuarios').insertOne(novoUsuario);
    delete novoUsuario.senha; 
    res.json(novoUsuario);
});

app.put('/usuarios/:id', async (req, res) => {
    const database = await connectDB();
    const { _id, senha, ...body } = req.body;
    const updateData = { ...body };
    if (senha) updateData.senha = await bcrypt.hash(senha, 10);
    await database.collection('usuarios').updateOne({ id: req.params.id, ...filtroTenant(req) }, { $set: updateData });
    res.json({ success: true });
});

app.delete('/usuarios/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection('usuarios').deleteOne({ id: req.params.id, ...filtroTenant(req) });
    res.json({ success: true });
});

const COLECOES_OK = [
    'alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'estoques', 'contratos', 'notificacoes'
];

app.get('/sistema/notificacoes/nao-lidas', async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = await database.collection('notificacoes')
            .find({
    ...filtroTenant(req),
    lida: false
})
            .sort({ dataCriacao: -1 }) 
            .toArray();
            
        res.json(notificacoes.map(({_id, ...rest}) => rest));
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar notificações.' }); }
});

app.put('/sistema/notificacoes/lida/:id', async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('notificacoes').updateOne(
            { id: req.params.id, ...filtroTenant(req) },
            { $set: { lida: true } }
        );
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao marcar como lida.' }); }
});

app.get('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).find(filtroTenant(req)).toArray();
    res.json(data.map(({_id, ...rest}) => rest));
});

app.get('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({
    id: req.params.id,
    ...filtroTenant(req)
});
    if (data) delete data._id;
    res.json(data || {});
});

app.post('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const body = { 
        ...req.body, 
        id: req.body.id || crypto.randomUUID(), 
        escolaId: req.escolaId 
    }; 
    await database.collection(req.params.collection).insertOne(body);
    res.json(body);
});

app.put('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });
    const database = await connectDB();
    const { _id, escolaId, ...body } = req.body;
    const resultado = await database.collection(req.params.collection).updateOne(
        { id: req.params.id, ...filtroTenant(req) },
        { $set: body }
    );
    if (resultado.matchedCount === 0) return res.status(404).json({ error: 'Registro não encontrado para atualização.' });
    res.json({ success: true, matchedCount: resultado.matchedCount, modifiedCount: resultado.modifiedCount, ...body });
});

app.delete('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });
    const database = await connectDB();
    const resultado = await database.collection(req.params.collection).deleteOne({
    id: req.params.id,
    ...filtroTenant(req)
});
    if (resultado.deletedCount === 0) return res.status(404).json({ error: 'Registro não encontrado para exclusão.' });
    res.json({ success: true });
});

cron.schedule('*/10 * * * *', async () => {
    try {
        const url = 'https://sistema-escolar-api-k3o8.onrender.com/'; 
        const response = await fetch(url);
        const data = await response.json();
        console.log(`⏰ [CRON] Ping automático: A API está ${data.status} às ${new Date().toLocaleTimeString('pt-BR')}`);
    } catch (error) { console.error("❌ [CRON] Erro no Ping automático:", error.message); }
});

connectDB().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 API Sistema Escolar na porta ${PORT}`));
});