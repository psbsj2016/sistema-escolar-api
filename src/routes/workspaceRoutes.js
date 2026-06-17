const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        return {
            folder: 'workspace_escola',
            resource_type: 'auto',
            public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
        };
    },
});
const upload = multer({ storage: storage });

const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    
    // Simplificação: num cenário real, o ID do utilizador é extraído do token aqui.
    // req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
};

// 1. UPLOAD
router.post('/upload', verificarToken, upload.array('anexos', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Nenhum ficheiro.' });
        const urls = req.files.map(file => ({ url: file.path, nome: file.originalname, tipo: file.mimetype }));
        res.status(200).json({ success: true, anexos: urls });
    } catch (error) {
        res.status(500).json({ error: 'Erro no envio para a Nuvem.' });
    }
});

// 2. CRIAR POST
router.post('/posts', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, autorTipo, escolaId, anexos } = req.body;
        if (!texto && (!anexos || anexos.length === 0)) return res.status(400).json({ error: 'Publicação vazia.' });

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(),
            escolaId: escolaId || 'DEFAULT',
            autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor',
            texto: texto,
            anexos: anexos || [],
            dataCriacao: new Date().toISOString(),
            comentarios: [],
            likes: 0
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        res.status(201).json({ success: true, post: novoPost });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao publicar.' });
    }
});

// 3. BUSCAR POSTS
router.get('/posts', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const posts = await database.collection('workspace_posts').find({}).sort({ dataCriacao: -1 }).limit(50).toArray();
        res.status(200).json(posts);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar o feed.' });
    }
});

// 4. COMENTAR E GERAR NOTIFICAÇÃO 🔔
router.post('/posts/:id/comentarios', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto, autorNome } = req.body;

        const database = await connectDB();
        const novoComentario = { id: crypto.randomUUID(), autorNome: autorNome, texto: texto, data: new Date().toISOString() };

        // Procura o post para saber quem é o dono dele
        const postOriginal = await database.collection('workspace_posts').findOne({ id: postId });

        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $push: { comentarios: novoComentario } }
        );

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });

        // 🔔 Cria a notificação se o autor do comentário for diferente do dono do post
        if (postOriginal && postOriginal.autorNome !== autorNome) {
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(),
                escolaId: postOriginal.escolaId,
                destinatarioNome: postOriginal.autorNome, // A quem se destina a notificação
                remetenteNome: autorNome,
                mensagem: `comentou na sua publicação: "${texto.substring(0, 20)}..."`,
                lida: false,
                data: new Date().toISOString()
            });
        }

        res.status(201).json({ success: true, comentario: novoComentario });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao comentar.' });
    }
});

// 5. BUSCAR NOTIFICAÇÕES NÃO LIDAS 🔔
router.get('/notificacoes/:nomeDono', verificarToken, async (req, res) => {
    try {
        const nomeDono = req.params.nomeDono;
        const database = await connectDB();
        const notificacoes = await database.collection('workspace_notificacoes')
            .find({ destinatarioNome: nomeDono, lida: false })
            .sort({ data: -1 })
            .toArray();
            
        res.status(200).json(notificacoes);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar notificações.' });
    }
});

// 6. MARCAR NOTIFICAÇÕES COMO LIDAS 🔔
router.put('/notificacoes/ler/:nomeDono', verificarToken, async (req, res) => {
    try {
        const nomeDono = req.params.nomeDono;
        const database = await connectDB();
        await database.collection('workspace_notificacoes').updateMany(
            { destinatarioNome: nomeDono, lida: false },
            { $set: { lida: true } }
        );
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar.' });
    }
});

module.exports = router;