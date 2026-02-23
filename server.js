const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = express();

// --- CONFIGURAÇÃO DE CORS REFORÇADA ---
app.use(cors({
    origin: '*', // Permite que a Vercel acesse a API
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));

app.use(express.json({ limit: '10mb' })); 

// Conexão com o Banco de Dados (CORRIGIDA PARA MÚLTIPLOS ACESSOS)
const uri = process.env.MONGODB_URI;
let client;
let clientPromise;

async function connectDB() {
    // Se ainda não começou a conectar, inicia a conexão
    if (!clientPromise) {
        client = new MongoClient(uri);
        clientPromise = client.connect();
        console.log("Iniciando conexão com o Banco de Dados Permanente...");
    }
    // Aguarda a conexão terminar, mesmo se 10 pedidos chegarem ao mesmo tempo
    await clientPromise;
    return client.db('sistema-escolar');
}

// Middleware de Segurança e Isolamento (Multi-escola)
app.use((req, res, next) => {
    req.userId = req.headers['x-user-id'];
    next();
});

// Geração automática do 1º Acesso (Gestor)
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

// Gerenciamento Exclusivo do Perfil da Escola
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

// Busca Inteligente de Listas (Alunos, Financeiro, Notas, etc)
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

// Salvamento e Edição Genéricos
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

// Remoção Genérica
app.delete('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id });
    res.json({ success: true });
});

// Inicialização
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`API Blindada rodando na porta ${PORT}`); });
