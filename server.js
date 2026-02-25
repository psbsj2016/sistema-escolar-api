const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend'); // <-- NOVO MOTOR RESEND

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// --- CONFIGURAÇÃO DE CORS REFORÇADA ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));

app.use(express.json({ limit: '10mb' })); 

// Conexão com o Banco de Dados
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

app.use((req, res, next) => {
    req.userId = req.headers['x-user-id'];
    next();
});

// =========================================================
// MOTOR DE E-MAILS (SAAS) - RESEND
// =========================================================

app.post('/auth/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail não fornecido' });

    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        const { data, error } = await resend.emails.send({
            from: 'Sistema Escolar <onboarding@resend.dev>', // Remetente padrão de teste do Resend
            to: email, 
            subject: '🔐 Seu Código - Sistema Escolar',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; color: #333;">
                    <h2 style="color: #27ae60;">Bem-vindo ao Sistema Escolar!</h2>
                    <p>Você iniciou o cadastro para uma nova instituição.</p>
                    <p>Seu código de verificação é:</p>
                    <h1 style="letter-spacing: 5px; color: #2c3e50; background: #f4f6f7; padding: 15px; border-radius: 8px; display: inline-block;">${codigoGerado}</h1>
                    <p style="font-size: 12px; color: #7f8c8d; margin-top: 20px;">Use este código junto com o PIN Exclusivo do Gestor para liberar sua conta.</p>
                </div>
            `
        });

        if (error) {
            console.error("Erro no Resend:", error);
            return res.status(500).json({ error: 'Erro ao disparar Resend' });
        }

        res.json({ success: true, codigo: codigoGerado });
    } catch (error) {
        console.error("Erro interno:", error);
        res.status(500).json({ error: 'Falha no servidor' });
    }
});

// =========================================================
// ROTAS PADRÕES DO SISTEMA
// =========================================================

app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    let data = await database.collection('usuarios').find({}).toArray();
    if (data.length === 0) {
        const defaultAdmin = { id: "1", nome: "Gestor Principal", login: "admin", senha: "123", tipo: "Gestor" };
        await database.collection('usuarios').insertOne(defaultAdmin);
        data = [defaultAdmin];
    }
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`API Blindada rodando na porta ${PORT} com Resend!`); });
