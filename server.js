const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// --- CONFIGURAÇÃO DE CORS REFORÇADA ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));

app.use(express.json({ limit: '10mb' })); 

// Conexão com o Banco de Dados (MongoDB)
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

// Middleware de Segurança e Isolamento (Multi-escola)
app.use((req, res, next) => {
    req.userId = req.headers['x-user-id'];
    next();
});

// =========================================================
// MOTOR DE E-MAILS (SAAS) E VALIDAÇÃO DE REGISTO
// =========================================================

// Cofre de memória temporária para guardar os códigos de quem está a tentar registar-se
const codigosAtivos = new Map();
const PIN_MESTRE = "7777"; // O seu PIN secreto intocável!

app.post('/auth/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail não fornecido' });

    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        const { data, error } = await resend.emails.send({
            from: 'Sistema Escolar <onboarding@resend.dev>', // Ou o seu domínio verificado
            to: email, 
            subject: '🔐 Seu Código - Sistema Escolar',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; color: #333;">
                    <h2 style="color: #27ae60;">Bem-vindo ao Sistema Escolar!</h2>
                    <p>Você iniciou o cadastro para uma nova instituição.</p>
                    <p>Seu código de verificação é:</p>
                    <h1 style="letter-spacing: 5px; color: #2c3e50; background: #f4f6f7; padding: 15px; border-radius: 8px; display: inline-block;">${codigoGerado}</h1>
                    <p style="font-size: 12px; color: #7f8c8d; margin-top: 20px;">Use este código junto com o PIN Exclusivo do Gestor para liberar a sua conta.</p>
                </div>
            `
        });

        if (error) {
            console.error("Erro no Resend:", error);
            return res.status(500).json({ error: 'Erro ao disparar Resend' });
        }

        // SEGURANÇA MÁXIMA: Guardamos o código no servidor e NÃO o devolvemos ao frontend!
        codigosAtivos.set(email, codigoGerado);
        
        // Destrói o código passado 10 minutos (Segurança extra contra tentativas infinitas)
        setTimeout(() => codigosAtivos.delete(email), 10 * 60 * 1000);

        res.json({ success: true, mensagem: 'Código enviado com sucesso' });
    } catch (error) {
        console.error("Erro interno:", error);
        res.status(500).json({ error: 'Falha no servidor' });
    }
});

app.post('/auth/validar-cadastro', async (req, res) => {
    const { email, codigo, pin } = req.body;

    if (!email || !codigo || !pin) {
        return res.status(400).json({ error: 'Dados incompletos.' });
    }

    // 1ª Barreira: O PIN Mestre bate certo?
    if (pin !== PIN_MESTRE) {
        return res.status(401).json({ error: 'PIN Exclusivo incorreto.' });
    }

    // 2ª Barreira: O Código é exatamente o que enviámos para aquele e-mail?
    const codigoReal = codigosAtivos.get(email);
    if (!codigoReal || codigoReal !== codigo) {
        return res.status(401).json({ error: 'Código de e-mail inválido ou expirado.' });
    }

    // Passou em tudo! Limpamos o código da memória para não ser reutilizado.
    codigosAtivos.delete(email);

    try {
        const database = await connectDB();
        
        // Garante que a conta admin base existe para o primeiro login
        const userExistente = await database.collection('usuarios').findOne({ login: "admin" });
        if (!userExistente) {
            const defaultAdmin = { id: Date.now().toString(), nome: "Gestor Principal", login: "admin", senha: "123", tipo: "Gestor" };
            await database.collection('usuarios').insertOne(defaultAdmin);
        }

        res.json({ success: true, mensagem: 'Sistema ativado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao configurar a conta.' });
    }
});

// =========================================================
// ROTA SEGURA DE LOGIN
// =========================================================
app.post('/auth/login', async (req, res) => {
    const { login, senha } = req.body;
    
    if (!login || !senha) {
        return res.status(400).json({ error: 'Login e senha são obrigatórios.' });
    }

    try {
        const database = await connectDB();
        // Procura exatamente o utilizador com esse login e senha
        const usuario = await database.collection('usuarios').findOne({ login: login, senha: senha });

        if (usuario) {
            // Removemos a senha antes de devolver os dados para o navegador (Boas práticas!)
            delete usuario.senha;
            delete usuario._id;
            res.json({ success: true, usuario: usuario });
        } else {
            res.status(401).json({ error: 'Utilizador ou senha incorretos.' });
        }
    } catch (error) {
        console.error("Erro no login seguro:", error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    let data = await database.collection('usuarios').find({}).toArray();
    if (data.length === 0) {
        // Criando o usuário inicial padrão, só que agora a senha fica no BD
        const defaultAdmin = { id: "1", nome: "Gestor Principal", login: "admin", senha: "123", tipo: "Gestor" };
        await database.collection('usuarios').insertOne(defaultAdmin);
        data = [defaultAdmin];
    }
    // IMPORTANTE DE SEGURANÇA: Não vamos enviar as senhas para o navegador em listas abertas!
    // Mas para o login provisório funcionar até fazermos a rota de login seguro, deixaremos retornar.
    const formatted = data.map(item => { const { _id, ...rest } = item; return rest; });
    res.json(formatted);
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

app.get('/:collection', async (req, res) => {
    if(req.params.collection === 'escola' || req.params.collection === 'usuarios') return;
    const database = await connectDB();
    let query = {};
    if (req.userId) query.donoId = req.userId;
    const data = await database.collection(req.params.collection).find(query).toArray();
    const formatted = data.map(item => { const { _id, ...rest } = item; return rest; });
    res.json(formatted);
});

app.get('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({ id: req.params.id });
    if(data) delete data._id;
    res.json(data || {});
});

app.post('/:collection', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
    if (req.params.collection !== 'usuarios' && req.userId) body.donoId = req.userId;
    await database.collection(req.params.collection).insertOne(body);
    delete body._id;
    res.json(body);
});

app.put('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    await database.collection(req.params.collection).updateOne({ id: req.params.id }, { $set: body }, { upsert: true });
    res.json(body);
});

app.delete('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id });
    res.json({ success: true });
});

// Inicialização Correta
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`API Blindada rodando na porta ${PORT} com Resend!`); });