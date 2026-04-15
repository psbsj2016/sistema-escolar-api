const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');

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

if (!JWT_SECRET || !uri) {
    console.error("❌ ERRO FATAL DE SEGURANÇA: JWT_SECRET ou MONGODB_URI ausentes!");
    process.exit(1); 
}

// 1. HELMET: Desbloqueia recursos para o Front-end Externo
app.use(helmet({ crossOriginResourcePolicy: false }));

// =========================================================
// 2. 🛡️ CORS BLINDADO (Bloqueia sites não oficiais)
// =========================================================
const dominiosPermitidos = [
    'https://www.sistemaptt.com.br',
    'https://sistemaptt.com.br',
    'http://localhost:3000',     // Para os teus testes locais
    'http://127.0.0.1:5500'      // Para o teu Live Server local
];

app.use(cors({
    origin: function (origin, callback) {
        // O '!origin' permite ferramentas como o Postman ou chamadas do próprio servidor
        if (!origin || dominiosPermitidos.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`🛑 Tentativa de acesso bloqueada pelo CORS. Origem: ${origin}`);
            callback(new Error('Acesso bloqueado por políticas de segurança (CORS).'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true 
}));

// 🛡️ REFORÇO MANUAL (Garante a entrega dos headers mesmo em caso de erro no pacote cors)
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (origin && dominiosPermitidos.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
    } else {
        // 🚀 AJUSTE: Se não houver origin (caso do cron-job), permite para evitar 403
        res.header("Access-Control-Allow-Origin", "*");
    }
    
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(express.json({ limit: '10mb' })); 
app.use(mongoSanitize());

// =========================================================
// 🛡️ RATE LIMIT NA MEMÓRIA (Ultra rápido e não quebra o Mongo)
// =========================================================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 800, 
    message: { error: 'Tráfego excessivo. O seu IP foi temporariamente bloqueado.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 15, 
    message: { error: 'Muitas tentativas falhadas. Sistema bloqueado por 15 minutos.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Aplica as regras de bloqueio (Sem dar erro de doubleCount)
app.use((req, res, next) => {
    if (req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/escola/')) {
        return next();
    }
    return globalLimiter(req, res, next);
});

app.use('/auth/login', authLimiter);
app.use('/auth/enviar-codigo', authLimiter);
app.use('/master/login', authLimiter);
app.use('/escola/validar-pin', authLimiter);

// =========================================================
// 🧹 SANITIZAÇÃO DE DADOS (XSS)
// =========================================================
const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/</g, '&lt;').replace(/>/g, '&gt;'); 
};

const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        if (key === 'senha' || key === 'senhaAtual' || key === 'novaSenha' || key === 'pin') {
            sanitized[key] = value;
        } else {
            sanitized[key] = sanitizeObject(value);
        }
    }
    return sanitized;
};

app.use((req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    next();
});

// =========================================================
// 📦 CONEXÃO MONGODB (POOL)
// =========================================================
let dbInstance = null;

async function connectDB() {
    if (dbInstance) return dbInstance;
    try {
        const client = new MongoClient(uri);
        await client.connect();
        dbInstance = client.db('sistema-escolar');
        console.log("📦 Conectado ao MongoDB com sucesso! (Pool de Conexões Ativo)");
        return dbInstance;
    } catch (error) {
        console.error("❌ Erro fatal ao conectar ao MongoDB:", error);
        throw error;
    }
}

// =========================================================
// 🔑 MIDDLEWARE JWT (AUTENTICAÇÃO PRINCIPAL)
// =========================================================
app.use((req, res, next) => {
    // 🚀 ADICIONADO: req.path === '/' para permitir o ping do cron-job
    if (req.path === '/' || req.path.startsWith('/auth/') || req.path.startsWith('/master/')) return next();

    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acesso negado. Token não fornecido.' });

    const token = authHeader.split(' ')[1]; 

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada ou token inválido.' });
        req.userId = decoded.id; 
        req.escolaId = decoded.escolaId; 
        req.userTipo = decoded.tipo;
        next();
    });
});

// 🚀 NOVA ROTA: Resposta para o Cron-job e verificação de status
app.get('/', (req, res) => {
    res.status(200).json({ 
        status: "online", 
        message: "API Sistema Escolar PTT ativa e operacional 🚀",
        timestamp: new Date().toISOString()
    });
});

// =========================================================
// 📩 SISTEMA DE CADASTRO E ATIVAÇÃO (COM 30 DIAS)
// =========================================================
const codigosAtivos = new Map();
 
app.post('/auth/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail não fornecido' });
    email = email.toLowerCase().trim(); // BLINDAGEM CASE INSENSITIVE

    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        const { data, error } = await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Seu Código - Sistema Escolar',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; color: #333;">
                    <h2 style="color: #27ae60;">Bem-vindo ao Sistema Escolar!</h2>
                    <p>Você iniciou o cadastro para uma nova instituição.</p>
                    <p>Seu código de verificação do e-mail é:</p>
                    <h1 style="letter-spacing: 5px; color: #2c3e50; background: #f4f6f7; padding: 15px; border-radius: 8px; display: inline-block;">${codigoGerado}</h1>
                    <p style="font-size: 12px; color: #7f8c8d; margin-top: 20px;">Use este código junto com o <b>PIN Exclusivo de Liberação</b> fornecido pelo administrador para ativar a sua conta.</p>
                </div>
            `
        });

        if (error) return res.status(500).json({ error: 'Erro ao disparar Resend' });

        codigosAtivos.set(email, codigoGerado);
        setTimeout(() => codigosAtivos.delete(email), 10 * 60 * 1000);

        const database = await connectDB();
        const ativacao = await database.collection('ativacoes').findOne({ email: new RegExp(`^${email}$`, 'i') });
        
        if (!ativacao) {
            await database.collection('ativacoes').insertOne({
                id: Date.now().toString(),
                email: email,
                status: 'Pendente',
                pinAtivacao: null, 
                dataRequisicao: new Date().toLocaleDateString('pt-BR')
            });
        }

        res.json({ success: true, mensagem: 'Código enviado com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Falha no servidor' });
    }
});

app.post('/auth/validar-cadastro', async (req, res) => {
    let { email, codigo, pin } = req.body;

    if (!email || !codigo || !pin) return res.status(400).json({ error: 'Dados incompletos.' });
    email = email.toLowerCase().trim();

    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: new RegExp(`^${email}$`, 'i') });

    if (!ativacao) return res.status(400).json({ error: 'E-mail não encontrado nas solicitações.' });
    if (ativacao.status === 'Verificado') return res.status(400).json({ error: 'Esta conta já está ativada e em uso!' });
    if (ativacao.status === 'Bloqueado') return res.status(403).json({ error: 'Cadastro bloqueado pelo administrador.' });

    // Permite uso de PIN insensível a maiúsculas
    if (!ativacao.pinAtivacao || ativacao.pinAtivacao.toUpperCase() !== pin.toUpperCase()) {
        return res.status(401).json({ error: 'O PIN Único está incorreto ou ainda não foi liberado pelo Dono.' });
    }

    const codigoReal = codigosAtivos.get(email);
    if (!codigoReal || codigoReal !== codigo) {
        return res.status(401).json({ error: 'Código de e-mail inválido ou expirado.' });
    }

    codigosAtivos.delete(email); 

    try {
        await database.collection('ativacoes').updateOne(
            { _id: ativacao._id }, 
            { $set: { status: 'Verificado', pinAtivacao: 'USADO E QUEIMADO' } }
        );
        
        // Mantém a escolaId se a escola já existir (caso o cliente esteja a tentar recriar a conta)
        const escolaExistente = await database.collection('escola').findOne({ email: new RegExp(`^${email}$`, 'i') });
        const escolaId = (escolaExistente && escolaExistente.escolaId) ? escolaExistente.escolaId : 'ESC-' + Date.now().toString(36).toUpperCase();

        // 🚀 GERA 30 DIAS DE ACESSO INICIAIS
        const dataVencimento = new Date();
        dataVencimento.setDate(dataVencimento.getDate() + 30);

        await database.collection('escola').updateOne(
            { email: new RegExp(`^${email}$`, 'i') }, 
            { $set: { 
                escolaId: escolaId, 
                email: email, 
                plano: ativacao.plano || 'Profissional', 
                pinUsado: pin.toUpperCase(), 
                dataCriacao: (escolaExistente && escolaExistente.dataCriacao) ? escolaExistente.dataCriacao : new Date().toISOString(),
                dataExpiracao: dataVencimento.toISOString() // Ciclo de 30 dias inserido!
            } },
            { upsert: true }
        );

        const userExistente = await database.collection('usuarios').findOne({ login: new RegExp(`^${email}$`, 'i') });
        if (!userExistente) {
            const senhaCriptografada = await bcrypt.hash("123", 10);
            const novoGestor = { 
                id: Date.now().toString(), 
                escolaId: escolaId, 
                nome: "Gestor Principal", 
                login: email, 
                senha: senhaCriptografada, 
                tipo: "Gestor", 
                email: email,
                isDono: true // 👑 A MARCA DO DONO INTOCÁVEL
            };
            await database.collection('usuarios').insertOne(novoGestor);
        } else {
            await database.collection('usuarios').updateOne({ _id: userExistente._id }, { $set: { escolaId: escolaId, isDono: true } });
        }

        res.json({ success: true, mensagem: 'Sistema ativado e 30 dias gerados com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao configurar a conta.' });
    }
});

// =========================================================
// 👑 ROTAS MASTER (DESBLOQUEIO IMEDIATO)
// =========================================================
const SENHA_DONO = process.env.SENHA_DONO;

app.post('/master/login', (req, res) => {
    const { senha } = req.body;
    if (!SENHA_DONO) return res.status(500).json({ error: 'Erro crítico: Senha Mestra não configurada no cofre do servidor!' });

    if (senha === SENHA_DONO) {
        const tokenMaster = jwt.sign({ master: true }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token: tokenMaster });
    } else {
        res.status(401).json({ error: 'Senha Mestra Incorreta!' });
    }
});

const masterAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acesso negado.' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded.master) return res.status(401).json({ error: 'Sessão do dono inválida.' });
        next();
    });
};

app.get('/master/ativacoes', masterAuth, async (req, res) => {
    const database = await connectDB();
    const lista = await database.collection('ativacoes').find({}).sort({ _id: -1 }).toArray();
    res.json(lista);
});

// 🚀 O CORAÇÃO DA MUDANÇA: ATUALIZAÇÃO E DESBLOQUEIO IMEDIATO!
app.post('/master/gerar-pin', masterAuth, async (req, res) => {
    let { email, plano } = req.body;
    email = email.toLowerCase().trim(); // Garante compatibilidade universal

    const database = await connectDB();
    
    let prefix = 'PRO';
    if (plano === 'Premium') prefix = 'PRE';
    if (plano === 'Essencial') prefix = 'ESS';
    if (plano === 'Teste') prefix = 'TST';
    
    const novoPin = prefix + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
    
    // Calcula o ciclo exato de 30 dias
    const dataVencimento = new Date();
    dataVencimento.setDate(dataVencimento.getDate() + 30);
    
    await database.collection('ativacoes').updateOne(
        { email: new RegExp(`^${email}$`, 'i') },
        { $set: { email: email, pinAtivacao: novoPin, status: 'Pendente', plano: plano || 'Profissional' } },
        { upsert: true }
    );

    // INJEÇÃO DIRETA NA ESCOLA: O desbloqueio acontece no segundo em que clica!
    await database.collection('escola').updateOne(
        { email: new RegExp(`^${email}$`, 'i') }, 
        { $set: { 
            email: email, 
            plano: plano || 'Profissional',
            dataExpiracao: dataVencimento.toISOString() // Aplica a mensalidade de 30 dias
        } }, 
        { upsert: true }
    );

    res.json({ success: true, pin: novoPin });
});

app.post('/master/bloquear', masterAuth, async (req, res) => {
    let { email } = req.body;
    email = email.toLowerCase().trim();
    const database = await connectDB();
    
    await database.collection('ativacoes').updateOne(
        { email: new RegExp(`^${email}$`, 'i') },
        { $set: { status: 'Bloqueado', pinAtivacao: 'BLOQUEADO' } }
    );
    
    // Mata a data de expiração instantaneamente
    await database.collection('escola').updateOne(
        { email: new RegExp(`^${email}$`, 'i') }, 
        { $set: { plano: 'Bloqueado', dataExpiracao: new Date().toISOString() } }, 
        { upsert: true }
    );
    res.json({ success: true });
});

// Validação manual de PIN pela própria escola no ecrã "Meu Plano"
app.post('/escola/validar-pin', async (req, res) => {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN não fornecido.' });

    try {
        const database = await connectDB();
        const ativacao = await database.collection('ativacoes').findOne({ pinAtivacao: new RegExp(`^${pin}$`, 'i') });

        if (!ativacao) return res.status(404).json({ error: 'PIN inválido, expirado ou não encontrado no servidor.' });
        if (ativacao.status === 'Bloqueado') return res.status(403).json({ error: 'Cadastro bloqueado pelo administrador.' });

        const planoConfirmado = ativacao.plano || 'Profissional';

        // O cliente validou o PIN manualmente: Renova 30 dias
        const dataVencimento = new Date();
        dataVencimento.setDate(dataVencimento.getDate() + 30);

        await database.collection('escola').updateOne(
            { escolaId: req.escolaId }, 
            { $set: { plano: planoConfirmado, pinUsado: pin.toUpperCase(), dataExpiracao: dataVencimento.toISOString() } }, 
            { upsert: true }
        );

        await database.collection('ativacoes').updateOne(
            { _id: ativacao._id },
            { $set: { status: 'Verificado' } }
        );

        res.json({ success: true, plano: planoConfirmado });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao validar o PIN no servidor.' });
    }
});

// =========================================================
// 🚀 ROTA SEGURA DE LOGIN E CONTROLE DE APARELHOS
// =========================================================
app.post('/auth/login', async (req, res) => {
    let { login, senha, deviceId } = req.body;
    
    if (!login || !senha) return res.status(400).json({ error: 'Login e senha são obrigatórios.' });

    let forcarSaida = false;
    if (login.endsWith('*FORCAR')) {
        forcarSaida = true;
        login = login.replace('*FORCAR', ''); 
    }

    try {
        const database = await connectDB();
        // 🛡️ Busca Case-Insensitive para evitar erros de digitação
        const usuario = await database.collection('usuarios').findOne({ login: new RegExp(`^${login}$`, 'i') });

        if (!usuario) return res.status(401).json({ error: 'Utilizador ou senha incorretos.' });

        let senhaCorreta = false;

        if (usuario.senha && (usuario.senha.startsWith('$2b$') || usuario.senha.startsWith('$2a$'))) {
            senhaCorreta = await bcrypt.compare(senha, usuario.senha);
        } else {
            senhaCorreta = (senha === usuario.senha);
            if (senhaCorreta) {
                const novaSenhaHash = await bcrypt.hash(senha, 10);
                await database.collection('usuarios').updateOne({ id: usuario.id }, { $set: { senha: novaSenhaHash } });
            }
        }

        if (senhaCorreta) {
            // 🛡️ ANTI-PIRATARIA (EXCETO PREMIUM E LIBERADO)
            const escola = await database.collection('escola').findOne({ escolaId: usuario.escolaId });
            const plano = escola ? (escola.plano || 'Teste') : 'Teste';

            if (plano !== 'Premium' && plano !== 'Liberado') {
                if (usuario.deviceId && usuario.deviceId !== deviceId && !forcarSaida) {
                    return res.status(403).json({ 
                        error: '🚫 Sessão ativa noutro aparelho! Para derrubar a outra conexão, adicione *FORCAR no final do seu login e tente novamente.' 
                    });
                }
            }

            await database.collection('usuarios').updateOne(
                { id: usuario.id }, 
                { $set: { deviceId: deviceId || 'desconhecido' } }
            );

            delete usuario.senha;
            delete usuario._id;
            
            const token = jwt.sign({ id: usuario.id, tipo: usuario.tipo, escolaId: usuario.escolaId }, JWT_SECRET, { expiresIn: '12h' });
            res.json({ success: true, usuario: usuario, token: token });
        } else {
            res.status(401).json({ error: 'Utilizador ou senha incorretos.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// =========================================================
// ✉️ ROTA DE RECUPERAÇÃO DE SENHA (ENVIO SEGURO VIA RESEND)
// =========================================================
app.post('/auth/recuperar-senha', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'O E-mail é obrigatório.' });

    try {
        const database = await connectDB();
        
        // 1. Procura o utilizador pelo e-mail ignorando maiúsculas/minúsculas
        const user = await database.collection('usuarios').findOne({ email: new RegExp(`^${email}$`, 'i') });

        if (!user) {
            return res.status(404).json({ error: 'E-mail não encontrado na nossa base de dados.' });
        }

        // 2. Gera uma senha temporária forte (8 caracteres)
        const novaSenha = Math.random().toString(36).slice(-8) + Math.floor(Math.random() * 10);
        
        // 3. Criptografa a nova senha antes de guardar
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(novaSenha, salt);

        // 4. Atualiza a senha no banco de dados
        await database.collection('usuarios').updateOne({ _id: user._id }, { $set: { senha: hash } });

        // 5. Envia o e-mail utilizando o Resend
        await resend.emails.send({
            from: 'Suporte Sistema PTT <nao-responda@sistemaptt.com.br>', // Altere se tiver outro domínio validado no Resend
            to: email,
            subject: '🔑 Recuperação de Senha - Acesso ao Sistema',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 30px; color: #333; max-width: 500px; margin: 0 auto; border: 1px solid #eee; border-radius: 10px;">
                    <h2 style="color: #2c3e50;">Olá, ${user.nome}!</h2>
                    <p>Foi solicitada a recuperação de senha para a sua conta no nosso sistema.</p>
                    <div style="background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; margin: 25px 0;">
                        <span style="font-size: 14px; color: #666;">A sua nova senha temporária é:</span><br>
                        <strong style="font-size: 26px; color: #3498db; letter-spacing: 2px;">${novaSenha}</strong>
                    </div>
                    <p style="font-size: 13px; color: #666;"><strong>Atenção:</strong> Recomendamos que aceda ao sistema o mais rapidamente possível e altere esta senha no menu <b>"Gestão de Utilizadores"</b> por motivos de segurança.</p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
                    <p style="font-size: 11px; color: #aaa; text-align: center;">Se não foi você que fez este pedido, por favor ignore este e-mail.</p>
                </div>
            `
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao recuperar senha:', error);
        res.status(500).json({ error: 'Erro interno ao tentar recuperar a senha.' });
    }
});

// =========================================================
// 👥 GESTÃO DE UTILIZADORES
// =========================================================
app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    let query = {};
    if (req.escolaId) query.escolaId = req.escolaId; 
    let data = await database.collection('usuarios').find(query).toArray();
    const formatted = data.map(item => { const { _id, senha, ...rest } = item; return rest; });
    res.json(formatted);
});

app.post('/usuarios', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
    if (req.escolaId) body.escolaId = req.escolaId; 
    
    if (body.senha) {
        body.senha = await bcrypt.hash(body.senha, 10);
    }
    
    // Converte e-mail/login para minúsculas ao criar
    if(body.login) body.login = body.login.toLowerCase().trim();
    if(body.email) body.email = body.email.toLowerCase().trim();

    await database.collection('usuarios').insertOne(body);
    delete body._id;
    res.json(body);
});

app.put('/usuarios/atualizar-conta', async (req, res) => {
    let { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
    const userId = req.userId;

    if (!senhaAtual) return res.status(400).json({ error: 'A senha atual é obrigatória.' });

    try {
        const database = await connectDB();
        const usuario = await database.collection('usuarios').findOne({ id: userId });

        if (!usuario) return res.status(401).json({ error: 'Usuário não encontrado.' });

        let senhaCorreta = false;
        if (usuario.senha && (usuario.senha.startsWith('$2b$') || usuario.senha.startsWith('$2a$'))) {
            senhaCorreta = await bcrypt.compare(senhaAtual, usuario.senha);
        } else {
            senhaCorreta = (senhaAtual === usuario.senha);
        }

        if (!senhaCorreta) return res.status(401).json({ error: 'Senha atual incorreta.' });

        const atualizacoes = {};
        if (novaSenha) atualizacoes.senha = await bcrypt.hash(novaSenha, 10); 
        if (novoEmail) atualizacoes.email = novoEmail.toLowerCase().trim(); 
        
        if (novoLogin) {
            novoLogin = novoLogin.toLowerCase().trim();
            if (novoLogin !== usuario.login) {
                const loginExistente = await database.collection('usuarios').findOne({ login: novoLogin, id: { $ne: userId } });
                if (loginExistente) return res.status(400).json({ error: 'Este login já está em uso.' });
                atualizacoes.login = novoLogin;
            }
        }

        if (Object.keys(atualizacoes).length === 0) return res.status(400).json({ error: 'Nenhuma alteração solicitada.' });

        await database.collection('usuarios').updateOne({ id: userId }, { $set: atualizacoes });
        res.json({ success: true, mensagem: 'Conta atualizada com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.put('/usuarios/:id', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    
    if (body.senha) {
        body.senha = await bcrypt.hash(body.senha, 10);
    }
    
    if(body.login) body.login = body.login.toLowerCase().trim();
    if(body.email) body.email = body.email.toLowerCase().trim();

    let query = { id: req.params.id };
    if (req.escolaId) query.escolaId = req.escolaId; 

    await database.collection('usuarios').updateOne(query, { $set: body }, { upsert: true });
    res.json(body);
});

// =========================================================
// 🏫 GESTÃO DA ESCOLA
// =========================================================
app.get('/escola', async (req, res) => {
    const database = await connectDB();
    let query = {};
    if (req.escolaId) query.escolaId = req.escolaId; 
    else if (req.userId) query.donoId = req.userId; 
    
    const data = await database.collection('escola').findOne(query) || {};
    delete data._id;
    res.json(data);
});

app.put('/escola', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;

    let query = {};
    if (req.escolaId) query.escolaId = req.escolaId; 
    else if (req.userId) query.donoId = req.userId;

    await database.collection('escola').updateOne(query, { $set: body }, { upsert: true });
    res.json(body);
});

// =========================================================
// 🔄 MOTOR CRUD DINÂMICO E VALIDADO (NoSQL SAFE)
// =========================================================
const SCHEMAS_PERMITIDOS = {
    alunos: ['id', 'status', 'escolaId', 'donoId', 'nome', 'nascimento', 'rg', 'cpf', 'cep', 'rua', 'numero', 'bairro', 'cidade', 'estado', 'nomePai', 'nomeMae', 'telEmergencia', 'whatsapp', 'curso', 'turma', 'modulo', 'dataMatricula', 'diaVencimento', 'valorMensalidade', 'obs', 'sexo', 'profissao', 'pais', 'resp_nome', 'resp_parentesco', 'resp_cpf', 'resp_zap'],
    turmas: ['id', 'escolaId', 'donoId', 'nome', 'curso', 'dia', 'horario', 'professor', 'maxAlunos'],
    cursos: ['id', 'escolaId', 'donoId', 'nome', 'carga', 'modulos'],
    financeiro: ['id', 'escolaId', 'donoId', 'idCarne', 'idAluno', 'alunoNome', 'valor', 'vencimento', 'status', 'descricao', 'tipo', 'dataGeracao', 'dataPagamento', 'formaPagamento', 'formaPagamento2', 'valorPago1', 'valorPago2', 'cobradoZap'],
    eventos: ['id', 'escolaId', 'donoId', 'data', 'tipo', 'descricao', 'inicio', 'fim'],
    chamadas: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'data', 'status', 'duracao'],
    avaliacoes: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'disciplina', 'data', 'tipo', 'valorMax', 'nota', 'bimestre', 'dataLancamento'],
    planejamentos: ['id', 'escolaId', 'donoId', 'idAluno', 'nomeAluno', 'curso', 'aulas', 'status'],
    estoques: ['id', 'escolaId', 'donoId', 'nome', 'codigo', 'quantidade', 'quantidadeMinima', 'valor', 'obs']
};

const purificarDados = (colecao, dadosBrutos) => {
    const schema = SCHEMAS_PERMITIDOS[colecao];
    if (!schema) return dadosBrutos; 
    
    const dadosLimpos = {};
    for (const campo of schema) {
        if (dadosBrutos[campo] !== undefined) {
            dadosLimpos[campo] = dadosBrutos[campo];
        }
    }
    return dadosLimpos;
};

const COLECOES_PERMITIDAS = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'estoques'];

const validarColecao = (req, res, next) => {
    if (!COLECOES_PERMITIDAS.includes(req.params.collection)) {
        return res.status(403).json({ error: 'Acesso bloqueado: Coleção não autorizada.' });
    }
    next();
};

// =========================================================
// 🛡️ MIDDLEWARE DE AUTORIZAÇÃO (CONTROLE DE ACESSO POR CARGO)
// =========================================================
const validarPermissoes = (req, res, next) => {
    const colecao = req.params.collection;
    const tipoUsuario = req.userTipo || 'Gestor'; // Assume Gestor se houver alguma anomalia

    // 1. Regras para Professores
    if (tipoUsuario === 'Professor') {
        const colecoesProibidas = ['financeiro', 'usuarios', 'escola', 'estoques'];
        if (colecoesProibidas.includes(colecao)) {
            return res.status(403).json({ error: 'Acesso negado: Perfil de Professor não tem permissão para aceder a esta área.' });
        }
    }

    // 2. Regras para a Secretaria
    if (tipoUsuario === 'Secretaria') {
        const colecoesProibidas = ['usuarios', 'escola'];
        
        // Bloqueia acesso total a áreas administrativas
        if (colecoesProibidas.includes(colecao)) {
            return res.status(403).json({ error: 'Acesso negado: Nível de acesso insuficiente para área administrativa.' });
        }
        
        // Exemplo extra de segurança: A secretaria pode ver e criar mensalidades, mas não pode apagá-las!
        if (colecao === 'financeiro' && req.method === 'DELETE') {
            return res.status(403).json({ error: 'Acesso negado: A Secretaria não tem permissão para apagar registos financeiros.' });
        }
    }

    // Se chegou até aqui, tem autorização para prosseguir!
    next(); 
};

// 🚀 APLICAÇÃO DOS MIDDLEWARES NAS ROTAS CRUD COM CINTOS DE SEGURANÇA (TRY/CATCH)

app.get('/:collection', validarColecao, validarPermissoes, async (req, res) => {
    try {
        const database = await connectDB();
        let query = {};
        if (req.escolaId) query.escolaId = req.escolaId; 
        else if (req.userId) query.donoId = req.userId; 
        
        const data = await database.collection(req.params.collection).find(query).toArray();
        const formatted = data.map(item => { const { _id, ...rest } = item; return rest; });
        res.json(formatted);
    } catch (error) {
        console.error(`❌ Erro ao buscar lista de ${req.params.collection}:`, error);
        res.status(500).json({ error: 'Erro interno ao consultar base de dados. Tente novamente.' });
    }
});

app.get('/:collection/:id', validarColecao, validarPermissoes, async (req, res) => {
    try {
        const database = await connectDB();
        let query = { id: req.params.id };
        if (req.escolaId) query.escolaId = req.escolaId; 
        
        const data = await database.collection(req.params.collection).findOne(query);
        if(data) delete data._id;
        res.json(data || {});
    } catch (error) {
        console.error(`❌ Erro ao buscar item em ${req.params.collection}:`, error);
        res.status(500).json({ error: 'Erro interno ao consultar base de dados.' });
    }
});

app.post('/:collection', validarColecao, validarPermissoes, async (req, res) => {
    try {
        const database = await connectDB();
        let body = { ...req.body };
        
        if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
        if (req.escolaId) body.escolaId = req.escolaId; 
        else if (req.userId) body.donoId = req.userId;
        
        body = purificarDados(req.params.collection, body);

        await database.collection(req.params.collection).insertOne(body);
        delete body._id;
        res.json(body);
    } catch (error) {
        console.error(`❌ Erro ao criar em ${req.params.collection}:`, error);
        res.status(500).json({ error: 'Erro interno ao salvar na base de dados.' });
    }
});

app.put('/:collection/:id', validarColecao, validarPermissoes, async (req, res) => {
    try {
        const database = await connectDB();
        let body = { ...req.body };
        delete body._id;
        
        let query = { id: req.params.id };
        if (req.escolaId) query.escolaId = req.escolaId; 
        
        if (body.escolaId && body.escolaId !== req.escolaId) delete body.escolaId;

        body = purificarDados(req.params.collection, body);

        await database.collection(req.params.collection).updateOne(query, { $set: body }, { upsert: true });
        res.json(body);
    } catch (error) {
        console.error(`❌ Erro ao atualizar em ${req.params.collection}:`, error);
        res.status(500).json({ error: 'Erro interno ao atualizar base de dados.' });
    }
});

app.delete('/:collection/:id', validarColecao, validarPermissoes, async (req, res) => {
    try {
        const database = await connectDB();
        let query = { id: req.params.id };
        if (req.escolaId) query.escolaId = req.escolaId; 

        // 🛡️ O DONO NUNCA PODE SER EXCLUÍDO
        if (req.params.collection === 'usuarios') {
            const userToDelete = await database.collection('usuarios').findOne(query);
            if (userToDelete && userToDelete.isDono) {
                return res.status(403).json({ error: 'O Dono da conta principal não pode ser excluído.' });
            }
        }

        await database.collection(req.params.collection).deleteOne(query);
        res.json({ success: true });
    } catch (error) {
        console.error(`❌ Erro ao excluir em ${req.params.collection}:`, error);
        res.status(500).json({ error: 'Erro interno ao excluir na base de dados.' });
    }
});

// =========================================================
// 🚀 ARRANQUE DO SERVIDOR
// =========================================================
connectDB().catch(console.error);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { 
    console.log(`🚀 API Blindada SaaS (Rate Limit + Helmet + NoSQL Safe + Schema Validator) a rodar perfeitamente na porta ${PORT}!`); 
});

const cron = require('node-cron');

// Exemplo: Corre todos os dias à meia-noite (00:00)
cron.schedule('0 0 * * *', async () => {
    console.log("cron 🕒 Iniciando processamento diário automático...");
    try {
        const database = await connectDB();
        // Aqui colocas a lógica, ex: marcar mensalidades como atrasadas
        console.log("✅ Tarefas concluídas com sucesso.");
    } catch (err) {
        console.error("❌ Erro no Cron:", err);
    }
});