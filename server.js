const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt'); // Motor de Criptografia de Senhas

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

const JWT_SECRET = process.env.JWT_SECRET || 'chave_super_secreta_gestao_escolar_777';

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));

app.use(express.json({ limit: '10mb' })); 

// =========================================================
// 🛡️ FILTRO PURIFICADOR ANTI-XSS (BARREIRA DE ENTRADA)
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
// CONEXÃO COM O BANCO DE DADOS
// =========================================================
const uri = process.env.MONGODB_URI;
let client;
let clientPromise;

async function connectDB() {
    if (!clientPromise) {
        client = new MongoClient(uri);
        clientPromise = client.connect();
        console.log("Iniciando conexão com o Banco de Dados Permanente...");
    }
    await clientPromise;
    return client.db('sistema-escolar');
}

// =========================================================
// MIDDLEWARE DE SEGURANÇA MÁXIMA (JWT)
// =========================================================
app.use((req, res, next) => {
    if (req.path.startsWith('/auth/') || req.path.startsWith('/master/') || (req.path === '/escola' && req.method === 'GET')) return next();

    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acesso negado. Token não fornecido.' });

    const token = authHeader.split(' ')[1]; 

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada ou token inválido.' });
        req.userId = decoded.id; 
        next();
    });
});

// =========================================================
// MOTOR DE E-MAILS (SAAS) E VALIDAÇÃO DE REGISTO
// =========================================================
const codigosAtivos = new Map();
const SENHA_DONO = process.env.SENHA_DONO || "master777"; 

app.post('/auth/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail não fornecido' });

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
        const ativacao = await database.collection('ativacoes').findOne({ email: email });
        
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
    const { email, codigo, pin } = req.body;

    if (!email || !codigo || !pin) return res.status(400).json({ error: 'Dados incompletos.' });

    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: email });

    if (!ativacao) return res.status(400).json({ error: 'E-mail não encontrado nas solicitações.' });
    if (ativacao.status === 'Verificado') return res.status(400).json({ error: 'Esta conta já está ativada e em uso!' });
    if (ativacao.status === 'Bloqueado') return res.status(403).json({ error: 'Cadastro bloqueado pelo administrador.' });

    if (!ativacao.pinAtivacao || ativacao.pinAtivacao !== pin) {
        return res.status(401).json({ error: 'O PIN Único está incorreto ou ainda não foi liberado pelo Dono.' });
    }

    const codigoReal = codigosAtivos.get(email);
    if (!codigoReal || codigoReal !== codigo) {
        return res.status(401).json({ error: 'Código de e-mail inválido ou expirado.' });
    }

    codigosAtivos.delete(email); 

    try {
        await database.collection('ativacoes').updateOne(
            { email: email }, 
            { $set: { status: 'Verificado', pinAtivacao: 'USADO E QUEIMADO' } }
        );
        
        const userExistente = await database.collection('usuarios').findOne({ login: "admin" });
        if (!userExistente) {
            const senhaCriptografada = await bcrypt.hash("123", 10);
            const defaultAdmin = { id: Date.now().toString(), nome: "Gestor Principal", login: "admin", senha: senhaCriptografada, tipo: "Gestor", email: email };
            await database.collection('usuarios').insertOne(defaultAdmin);
        } else {
            await database.collection('usuarios').updateOne({ login: "admin" }, { $set: { email: email } });
        }

        res.json({ success: true, mensagem: 'Sistema ativado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao configurar a conta.' });
    }
});

// =========================================================
// 👑 ÁREA SECRETA DO DONO DO SISTEMA (MASTER)
// =========================================================
app.post('/master/login', (req, res) => {
    const { senha } = req.body;
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

app.post('/master/gerar-pin', masterAuth, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    const novoPin = Math.random().toString(36).substring(2, 5).toUpperCase() + '-' + Math.random().toString(36).substring(2, 5).toUpperCase();
    
    await database.collection('ativacoes').updateOne(
        { email: email },
        { $set: { pinAtivacao: novoPin, status: 'Pendente' } }
    );
    res.json({ success: true, pin: novoPin });
});

app.post('/master/bloquear', masterAuth, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    await database.collection('ativacoes').updateOne(
        { email: email },
        { $set: { status: 'Bloqueado', pinAtivacao: 'BLOQUEADO' } }
    );
    res.json({ success: true });
});

// =========================================================
// ROTA SEGURA DE LOGIN E USUÁRIOS
// =========================================================
app.post('/auth/login', async (req, res) => {
    const { login, senha } = req.body;
    
    if (!login || !senha) return res.status(400).json({ error: 'Login e senha são obrigatórios.' });

    try {
        const database = await connectDB();
        const usuario = await database.collection('usuarios').findOne({ login: login });

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
            delete usuario.senha;
            delete usuario._id;
            
            const token = jwt.sign({ id: usuario.id, tipo: usuario.tipo }, JWT_SECRET, { expiresIn: '12h' });
            res.json({ success: true, usuario: usuario, token: token });
        } else {
            res.status(401).json({ error: 'Utilizador ou senha incorretos.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    let data = await database.collection('usuarios').find({}).toArray();
    if (data.length === 0) {
        const hash = await bcrypt.hash("123", 10);
        const defaultAdmin = { id: "1", nome: "Gestor Principal", login: "admin", senha: hash, tipo: "Gestor" };
        await database.collection('usuarios').insertOne(defaultAdmin);
        data = [defaultAdmin];
    }
    const formatted = data.map(item => { const { _id, senha, ...rest } = item; return rest; });
    res.json(formatted);
});

app.post('/usuarios', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
    
    if (body.senha) {
        body.senha = await bcrypt.hash(body.senha, 10);
    }
    
    await database.collection('usuarios').insertOne(body);
    delete body._id;
    res.json(body);
});

app.put('/usuarios/:id', async (req, res) => {
    if(req.params.id === 'atualizar-conta' || req.params.id === 'mudar-senha') return; 
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    
    if (body.senha) {
        body.senha = await bcrypt.hash(body.senha, 10);
    }
    
    await database.collection('usuarios').updateOne({ id: req.params.id }, { $set: body }, { upsert: true });
    res.json(body);
});

app.put('/usuarios/atualizar-conta', async (req, res) => {
    const { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
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
        if (novoEmail) atualizacoes.email = novoEmail; 
        
        if (novoLogin && novoLogin !== usuario.login) {
            const loginExistente = await database.collection('usuarios').findOne({ login: novoLogin, id: { $ne: userId } });
            if (loginExistente) return res.status(400).json({ error: 'Este login já está em uso.' });
            atualizacoes.login = novoLogin;
        }

        if (Object.keys(atualizacoes).length === 0) return res.status(400).json({ error: 'Nenhuma alteração solicitada.' });

        await database.collection('usuarios').updateOne({ id: userId }, { $set: atualizacoes });
        res.json({ success: true, mensagem: 'Conta atualizada com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/escola', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('escola').findOne({}) || {};
    delete data._id;
    res.json(data);
});

app.put('/escola', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    await database.collection('escola').updateOne({}, { $set: body }, { upsert: true });
    res.json(body);
});

// =========================================================
// 🚧 GUARDAS DE FRONTEIRA: ROTAS GENÉRICAS
// =========================================================

// Apenas estas coleções podem ser lidas ou gravadas pelas rotas genéricas
const COLECOES_PERMITIDAS = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos'];

// Segurança VIP
const validarColecao = (req, res, next) => {
    if (!COLECOES_PERMITIDAS.includes(req.params.collection)) {
        return res.status(403).json({ error: 'Acesso bloqueado: Coleção não autorizada.' });
    }
    next();
};

app.get('/:collection', validarColecao, async (req, res) => {
    const database = await connectDB();
    let query = {};
    if (req.userId) query.donoId = req.userId;
    const data = await database.collection(req.params.collection).find(query).toArray();
    const formatted = data.map(item => { const { _id, ...rest } = item; return rest; });
    res.json(formatted);
});

app.get('/:collection/:id', validarColecao, async (req, res) => {
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({ id: req.params.id });
    if(data) delete data._id;
    res.json(data || {});
});

app.post('/:collection', validarColecao, async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
    if (req.userId) body.donoId = req.userId;
    await database.collection(req.params.collection).insertOne(body);
    delete body._id;
    res.json(body);
});

app.put('/:collection/:id', validarColecao, async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    await database.collection(req.params.collection).updateOne({ id: req.params.id }, { $set: body }, { upsert: true });
    res.json(body);
});

app.delete('/:collection/:id', validarColecao, async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id });
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`API Blindada (JWT, Bcrypt, XSS e Filtro de Tabelas) rodando na porta ${PORT}!`); });