const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');
const cron = require('node-cron'); // Importação essencial
const crypto = require('crypto'); 

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');

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
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://www.sistemaptt.com.br';

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
app.use('/master/login', authLimiter); // 🛡️ ADICIONE ESTA LINHA! Agora robôs serão bloqueados no Master.

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
    // Adicionamos a liberação para rotas que começam com '/public/'
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
        req.escolaId = decoded.escolaId; 
        req.userTipo = decoded.tipo;
        next();
    });
});

// =========================================================
// 📄 ÁREA PÚBLICA (Matrículas Externas Automáticas)
// =========================================================

// 🚀 NOVA ROTA: Fornece o layout dinâmico para o matricula.html
app.get('/public/escola/:id', async (req, res) => {
    try {
        const escolaId = req.params.id;
        const database = await connectDB();
        
        // Busca a escola no banco
        const escola = await database.collection('escola').findOne({ escolaId: escolaId });
        
        if (!escola) {
            return res.status(404).json({ error: 'Escola não encontrada.' });
        }

        // 🛡️ SEGURANÇA: Retorna APENAS o objeto configMatricula
        // Nunca envie o objeto 'escola' inteiro aqui, pois isso vazaria e-mails e planos!
        res.status(200).json({
            escolaId: escola.escolaId,
            configMatricula: escola.configMatricula || null
        });

    } catch (error) {
        console.error("❌ Erro ao buscar dados públicos da escola:", error);
        res.status(500).json({ error: 'Erro interno ao carregar a página de matrícula.' });
    }
});

app.post('/public/receber-matricula', async (req, res) => {
    try {
        const { escolaId, ...dadosBrutos } = req.body;

        if (!escolaId) {
            return res.status(400).json({ error: 'ID da escola não fornecido no formulário.' });
        }

        const database = await connectDB();

       // 🛡️ BLINDAGEM CONTRA INJEÇÃO DE DADOS (Mass Assignment)
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
            
            // 🪄 NOVA LINHA: O Radar de Campanhas (Guarda a origem do aluno)
            refLink: dadosBrutos.refLink || 'Direto',
            
            // Dados do responsável legal (se aplicável)
            resp_nome: dadosBrutos.resp_nome || null,
            resp_parentesco: dadosBrutos.resp_parentesco || null,
            resp_cpf: dadosBrutos.resp_cpf || null,
            resp_zap: dadosBrutos.resp_zap || null,
            conteudoHTML: sanitizeString(dadosBrutos.conteudoHTML || '<p>Contrato não gerado.</p>')
        };

        const idAlunoGerado = crypto.randomUUID(); // Muito mais seguro que Date.now()

        const novoAluno = {
            ...dadosPermitidos,
            id: idAlunoGerado,
            escolaId: escolaId,
            status: 'Ativo', // 🟢 Já entra "Ativo"
            dataMatricula: new Date().toISOString()
        };

        // Salva o aluno na base
        await database.collection('alunos').insertOne(novoAluno);
        
        // =======================================================
        // 🔒 INÍCIO DO COFRE DE CONTRATOS (VERSÃO ENRIQUECIDA)
        // =======================================================
        const carimboDeTempo = new Date().toISOString();
        // --- SUBSTITUA TODO O BLOCO const novoContrato = { ... }; POR ESTE ---
        const enderecoFormatado = `${dadosPermitidos.rua || ''}, ${dadosPermitidos.numero || ''} - ${dadosPermitidos.bairro || ''}, ${dadosPermitidos.cidade || ''} - ${dadosPermitidos.estado || ''}, ${dadosPermitidos.pais || 'Brasil'}`;

    const novoContrato = {
    id: "DOC_" + crypto.randomUUID(),
    escolaId: escolaId,
    idAluno: idAlunoGerado,
    nomeAluno: dadosPermitidos.nome || 'Nome não informado',
    
    // DADOS PESSOAIS
    cpf: dadosPermitidos.cpf || 'Não informado',
    rg: dadosPermitidos.rg || 'Não informado',
    nascimento: dadosPermitidos.nascimento || 'Não informado',
    sexo: dadosPermitidos.sexo || 'Não informado',
    profissao: dadosPermitidos.profissao || 'Não informada',
    
    // CONTATOS E ENDEREÇO
    whatsapp: dadosPermitidos.whatsapp || 'Não informado',
    email: dadosPermitidos.email || 'Não informado',
    enderecoCompleto: enderecoFormatado,
    
    // DADOS ACADÉMICOS E FINANCEIROS
    curso: dadosPermitidos.curso || 'Não informado',
    turma: dadosPermitidos.turma || 'Não informada',
    planoCurso: dadosPermitidos.planoCurso || 'Não informado',
    diaVencimento: dadosPermitidos.diaVencimento || 'Não informado',
    
    // DADOS DO RESPONSÁVEL
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
// 🔔 NOTIFICAÇÃO OFICIAL PARA O SININHO
// =======================================================
await database.collection('notificacoes').insertOne({
    id: "NOTI_" + crypto.randomUUID(),
    escolaId: escolaId,
    tipo: "matricula_contrato",
    titulo: "Nova matrícula recebida",
    mensagem: `${dadosPermitidos.nome || 'Novo aluno'} enviou uma matrícula online e o contrato digital foi gerado.`,
    nomeAluno: dadosPermitidos.nome || '',
    idAluno: idAlunoGerado,
    idContrato: novoContrato.id,
    refLink: dadosPermitidos.refLink || 'Direto',
    lida: false,
    dataCriacao: new Date().toISOString()
});

console.log(`✅ Novo aluno matriculado: ${dadosPermitidos.nome} (Escola: ${escolaId})`);

        // =======================================================
        // 🔔 GERAR NOTIFICAÇÃO PARA O SININHO
        // =======================================================
        const novaNotificacao = {
            id: "NOTIF_" + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: '🎉 Nova Matrícula!',
            mensagem: `${dadosPermitidos.nome} acabou de garantir uma vaga.`,
            tipo: 'matricula',
            lida: false,
            dataCriacao: new Date().toISOString(),
            idAlunoReferencia: idAlunoGerado
        };
        await database.collection('notificacoes').insertOne(novaNotificacao);
        // =======================================================

res.status(200).json({ success: true, message: 'Matrícula ativada com sucesso!' });
    } catch (error) {
        console.error("❌ Erro ao salvar matrícula:", error);
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

    res.json({
        success: true
    });
});

// =========================================================
// 📩 AUTH & CADASTRO
// =========================================================
// Removemos o 'const codigosAtivos = new Map();'

app.post('/auth/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
    
    email = email.toLowerCase().trim();
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Define a validade do código para 10 minutos a partir de agora
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

        // O Resend não joga um Catch automático se o erro for da API (ex: email rejeitado).
        // Precisamos verificar a propriedade 'error' que ele retorna.
        if (error) {
            console.error("❌ Resend API Error:", error);
            return res.status(400).json({ error: 'Falha ao enviar e-mail. Verifique o endereço.' });
        }

        const database = await connectDB();
        await database.collection('ativacoes').updateOne(
            { email }, 
            { 
                $set: { 
                    email, 
                    codigoValidacao: codigoGerado, // Salva no banco
                    expiracaoCodigo: validade,     // Salva a expiração
                    status: 'Pendente', 
                    dataRequisicao: new Date().toISOString() 
                } 
            }, 
            { upsert: true }
        );
        
        res.json({ success: true });
    } catch (error) { 
        console.error("❌ Erro grave ao processar envio de código:", error);
        res.status(500).json({ error: 'Erro interno ao tentar enviar o código.' }); 
    }
});

app.post('/auth/validar-cadastro', async (req, res) => {
    let { email, codigo, pin } = req.body;
    email = email.toLowerCase().trim();
    
    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: new RegExp(`^${email}$`, 'i') });
    
    if (!ativacao) return res.status(404).json({ error: 'Nenhuma solicitação encontrada para este e-mail.' });
    
    // 1. Verifica o PIN
    if (ativacao.pinAtivacao?.toUpperCase() !== pin.toUpperCase()) {
        return res.status(401).json({ error: 'PIN incorreto.' });
    }
    
    // 2. Verifica se o código bate com o do banco
    if (ativacao.codigoValidacao !== codigo) {
        return res.status(401).json({ error: 'Código inválido.' });
    }
    
    // 3. Verifica se o código expirou
    if (new Date() > new Date(ativacao.expiracaoCodigo)) {
         return res.status(401).json({ error: 'O código de verificação expirou. Solicite um novo.' });
    }

    // Pega o primeiro bloco de letras/números do UUID
    const escolaId = 'ESC-' + crypto.randomUUID().split('-')[0].toUpperCase();
    const dataVencimento = new Date(); 
    dataVencimento.setDate(dataVencimento.getDate() + 30);

    await database.collection('escola').updateOne(
        { email }, 
        { $set: { escolaId, email, plano: ativacao.plano || 'Profissional', dataExpiracao: dataVencimento.toISOString() } }, 
        { upsert: true }
    );
    
    const senhaHash = await bcrypt.hash("123", 10);
    
    // 4. Limpa o código do banco para que não possa ser reusado
    await database.collection('ativacoes').updateOne(
        { email }, 
        { $unset: { codigoValidacao: "", expiracaoCodigo: "" } }
    );

    await database.collection('usuarios').insertOne({ id: crypto.randomUUID(), escolaId, login: email, senha: senhaHash, tipo: "Gestor", isDono: true });
    
    res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
    let { login, senha, deviceId } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: new RegExp(`^${login.replace('*FORCAR','')}$`, 'i') });
    if (!user || !(await bcrypt.compare(senha, user.senha))) return res.status(401).json({ error: 'Credenciais inválidas.' });
    
    const token = jwt.sign(
    {
        id: user.id,
        tipo: user.tipo,
        escolaId: user.escolaId
    },
    JWT_SECRET,
    { expiresIn: '12h' }
);

// 🍪 COOKIE HTTPONLY SUPER SEGURO
res.cookie('token_acesso', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    domain: '.sistemaptt.com.br',
    maxAge: 12 * 60 * 60 * 1000, // 12 horas
    path: '/'
});

res.json({
    success: true,
    usuario: user
});
});

// =========================================================
// ROTA: Recuperação de Senha por Link Temporário
// =========================================================
app.post('/auth/recuperar-senha', authLimiter, async (req, res) => {
    try {
        let { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: "Por favor, informe um e-mail válido."
            });
        }

        email = email.toLowerCase().trim();
        const database = await connectDB();

        const user = await database.collection('usuarios').findOne({
            $or: [
                { login: new RegExp(`^${email}$`, 'i') },
                { email: new RegExp(`^${email}$`, 'i') }
            ]
        });

        /*
          Importante:
          Mesmo se o e-mail não existir, respondemos sucesso.
          Isso evita que alguém use a tela para descobrir quais e-mails existem no sistema.
        */
        if (!user || (user.status && user.status.toLowerCase() === 'inativo')) {
            return res.status(200).json({
                success: true,
                message: "Se este e-mail estiver cadastrado, enviaremos um link de redefinição."
            });
        }

        const tokenLimpo = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto
            .createHash('sha256')
            .update(tokenLimpo)
            .digest('hex');

        const expiraEm = new Date(Date.now() + 30 * 60 * 1000); // 30 minutos

        await database.collection('password_resets').deleteMany({
            userId: user.id
        });

        await database.collection('password_resets').insertOne({
            userId: user.id,
            escolaId: user.escolaId,
            email,
            tokenHash,
            expiraEm,
            usado: false,
            criadoEm: new Date()
        });

        const linkRedefinicao = `${FRONTEND_URL}/index.html?reset=${tokenLimpo}`;

        const { error } = await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email,
            subject: '🔐 Redefinição de Senha',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
                    <h2>Redefinição de Senha</h2>
                    <p>Recebemos uma solicitação para redefinir a sua senha.</p>
                    <p>Clique no botão abaixo para criar uma nova senha. Este link expira em 30 minutos.</p>

                    <p style="margin: 30px 0;">
                        <a href="${linkRedefinicao}" style="background:#3498db; color:#ffffff; padding:14px 22px; border-radius:8px; text-decoration:none; font-weight:bold; display:inline-block;">
                            Redefinir minha senha
                        </a>
                    </p>

                    <p style="font-size:13px; color:#777;">
                        Se você não solicitou esta alteração, ignore este e-mail.
                    </p>
                </div>
            `
        });

        if (error) {
            console.error("Erro Resend recuperação:", error);
            return res.status(500).json({
                success: false,
                error: "Erro ao enviar o e-mail de recuperação."
            });
        }

        return res.status(200).json({
            success: true,
            message: "Se este e-mail estiver cadastrado, enviaremos um link de redefinição."
        });

    } catch (erro) {
        console.error("Erro ao solicitar recuperação:", erro);
        return res.status(500).json({
            success: false,
            error: "Erro interno no servidor. Tente novamente mais tarde."
        });
    }
});

app.post('/auth/redefinir-senha', authLimiter, async (req, res) => {
    try {
        const { token, novaSenha } = req.body;

        if (!token || !novaSenha) {
            return res.status(400).json({
                success: false,
                error: "Token e nova senha são obrigatórios."
            });
        }

        if (String(novaSenha).length < 6) {
            return res.status(400).json({
                success: false,
                error: "A nova senha deve ter pelo menos 6 caracteres."
            });
        }

        const tokenHash = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const database = await connectDB();

        const reset = await database.collection('password_resets').findOne({
            tokenHash,
            usado: false,
            expiraEm: { $gt: new Date() }
        });

        if (!reset) {
            return res.status(401).json({
                success: false,
                error: "Link inválido ou expirado. Solicite uma nova recuperação."
            });
        }

        const senhaHash = await bcrypt.hash(novaSenha, 10);

        await database.collection('usuarios').updateOne(
            { id: reset.userId, escolaId: reset.escolaId },
            { $set: { senha: senhaHash } }
        );

        await database.collection('password_resets').updateOne(
            { _id: reset._id },
            {
                $set: {
                    usado: true,
                    usadoEm: new Date()
                }
            }
        );

        await database.collection('password_resets').deleteMany({
            userId: reset.userId,
            usado: false
        });

        return res.status(200).json({
            success: true,
            message: "Senha redefinida com sucesso."
        });

    } catch (erro) {
        console.error("Erro ao redefinir senha:", erro);
        return res.status(500).json({
            success: false,
            error: "Erro interno ao redefinir senha."
        });
    }
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
    
    // Gera 3 bytes aleatórios seguros e os transforma em Hexadecimal (ex: A4F9C2)
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

// =========================================================
// ROTA: Listar TODAS as escolas (Ativas, Pendentes e Fantasmas)
// =========================================================
app.get('/master/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();
        const usuarios = await database.collection('usuarios').find({ isDono: true }).toArray();

        // Usamos um Mapa para juntar todo mundo e não repetir e-mails na sua tela
        const mapaContas = new Map();

        // 1. Pega quem tem licença
        ativacoes.forEach(a => {
            if(a.email) mapaContas.set(a.email.toLowerCase(), { ...a, _id: undefined });
        });

        // 2. Pega quem tem escola cadastrada (mas sumiu da licença)
        escolas.forEach(e => {
            if (e.email && !mapaContas.has(e.email.toLowerCase())) {
                mapaContas.set(e.email.toLowerCase(), { email: e.email, plano: e.plano || 'Desconhecido', status: 'Desconectado', pinAtivacao: 'FANTASMA 👻' });
            }
        });

        // 3. Pega quem fez usuário de login (mas sumiu do resto)
        usuarios.forEach(u => {
            if (u.login && !mapaContas.has(u.login.toLowerCase())) {
                mapaContas.set(u.login.toLowerCase(), { email: u.login, plano: 'Desconhecido', status: 'Desconectado', pinAtivacao: 'FANTASMA 👻' });
            }
        });

        res.json(Array.from(mapaContas.values()));
    } catch (error) {
        console.error("Erro ao buscar escolas:", error);
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
// ROTA: Excluir DEFINITIVAMENTE uma conta e todos os seus dados
// =========================================================
app.post('/master/excluir-conta', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });

        const targetEmail = email.toLowerCase().trim();
        const database = await connectDB();

        // 1. Descobrir o ID real da escola (ex: ESC-1234)
        const escola = await database.collection('escola').findOne({ email: targetEmail });
        const usuario = await database.collection('usuarios').findOne({ login: targetEmail });
        
        const idParaApagar = (escola && escola.escolaId) ? escola.escolaId : ((usuario && usuario.escolaId) ? usuario.escolaId : null);

        // 2. Apagar TODOS os dados de todas as abas do sistema
        if (idParaApagar) {
            const colecoesTenant = [ 'alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'usuarios', 'estoques' ];
            for (const col of colecoesTenant) {
                await database.collection(col).deleteMany({ escolaId: idParaApagar });
            }
        }

        // 3. Apagar tudo o que sobrou usando o e-mail
        await database.collection('escola').deleteMany({ email: targetEmail });
        await database.collection('usuarios').deleteMany({ login: targetEmail });
        await database.collection('usuarios').deleteMany({ email: targetEmail });
        await database.collection('ativacoes').deleteMany({ email: targetEmail });

        res.json({ success: true, message: 'Conta obliterada do banco.' });
    } catch (error) {
        console.error("Erro ao excluir conta:", error);
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

// Rota para validar o PIN de renovação de plano
app.post('/escola/validar-pin', async (req, res) => {
    try {
        const { pin } = req.body;
        if (!pin) return res.status(400).json({ error: 'PIN não informado.' });

        const database = await connectDB();
        
        // Vai no banco de dados (coleção ativacoes) e procura se o PIN existe
        const ativacao = await database.collection('ativacoes').findOne({ pinAtivacao: pin.toUpperCase() });

        if (ativacao) {
            // Sucesso! O PIN foi encontrado no banco de dados.
            return res.json({ success: true, plano: ativacao.plano || 'Profissional' });
        } else {
            return res.status(404).json({ error: 'PIN não encontrado na base de dados.' });
        }
    } catch (error) {
        console.error("Erro ao validar PIN:", error);
        res.status(500).json({ error: 'Erro interno ao validar PIN.' });
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
    
    const novoUsuario = { ...body, id: crypto.randomUUID(), escolaId: req.escolaId };
    
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
const COLECOES_OK = [
    'alunos',
    'turmas',
    'cursos',
    'financeiro',
    'eventos',
    'chamadas',
    'avaliacoes',
    'planejamentos',
    'estoques',
    'contratos',
    'notificacoes'
];

// =========================================================
// 🔔 ROTAS DO SININHO (NOTIFICAÇÕES EM TEMPO REAL)
// =========================================================

// 1. Buscar apenas as não lidas (Otimizado para o Polling)
app.get('/sistema/notificacoes/nao-lidas', async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = await database.collection('notificacoes')
            .find({ escolaId: req.escolaId, lida: false })
            .sort({ dataCriacao: -1 }) // As mais recentes primeiro
            .toArray();
            
        res.json(notificacoes.map(({_id, ...rest}) => rest));
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar notificações.' });
    }
});

// 2. Marcar uma notificação como lida ao clicar
app.put('/sistema/notificacoes/lida/:id', async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('notificacoes').updateOne(
            { id: req.params.id, escolaId: req.escolaId },
            { $set: { lida: true } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao marcar como lida.' });
    }
});

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
    
    // A MÁGICA ACONTECE AQUI: req.body.id || crypto.randomUUID()
    const body = { 
        ...req.body, 
        id: req.body.id || crypto.randomUUID(), 
        escolaId: req.escolaId 
    }; 
    
    await database.collection(req.params.collection).insertOne(body);
    res.json(body);
});

app.put('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) {
        return res.status(403).json({ error: 'Coleção não permitida.' });
    }

    const database = await connectDB();
    const { _id, escolaId, ...body } = req.body;

    const resultado = await database.collection(req.params.collection).updateOne(
        { id: req.params.id, escolaId: req.escolaId },
        { $set: body }
    );

    if (resultado.matchedCount === 0) {
        return res.status(404).json({ error: 'Registro não encontrado para atualização.' });
    }

    res.json({
        success: true,
        matchedCount: resultado.matchedCount,
        modifiedCount: resultado.modifiedCount,
        ...body
    });
});

app.delete('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) {
        return res.status(403).json({ error: 'Coleção não permitida.' });
    }

    const database = await connectDB();

    const resultado = await database.collection(req.params.collection).deleteOne({
        id: req.params.id,
        escolaId: req.escolaId
    });

    if (resultado.deletedCount === 0) {
        return res.status(404).json({ error: 'Registro não encontrado para exclusão.' });
    }

    res.json({ success: true });
});

// =========================================================
// ⏰ CRON JOB: PREVENIR HIBERNAÇÃO (RENDER FREE TIER)
// =========================================================
// O Render "adormece" a API após 15 minutos. 
// Este script faz uma chamada na rota raiz a cada 10 minutos para mantê-la acordada.

cron.schedule('*/10 * * * *', async () => {
    try {
        // A URL raiz '/' que criamos lá em cima retorna { status: "online" }
        const url = 'https://sistema-escolar-api-k3o8.onrender.com/'; 
        
        // Fazemos a requisição (usando o fetch nativo do Node 18+)
        const response = await fetch(url);
        const data = await response.json();
        
        console.log(`⏰ [CRON] Ping automático: A API está ${data.status} às ${new Date().toLocaleTimeString('pt-BR')}`);
    } catch (error) {
        console.error("❌ [CRON] Erro no Ping automático:", error.message);
    }
});

// =========================================================
// 🚀 INICIALIZAÇÃO & CRON
// =========================================================
connectDB().then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 API Sistema Escolar na porta ${PORT}`));
});