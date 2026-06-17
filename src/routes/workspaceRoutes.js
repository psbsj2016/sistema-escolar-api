const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ☁️ 1. Configuração do Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// 📦 2. Configuração do Motor de Upload
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        return {
            folder: 'workspace_escola', // Pasta que será criada no seu Cloudinary
            resource_type: 'auto', // Aceita vídeo, imagem e ficheiros raw (PDF/Docs)
            public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
        };
    },
});
const upload = multer({ storage: storage });

const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    next();
};

// 🚀 3. ROTA NOVA: UPLOAD DIRETO PARA A NUVEM
// Aceita até 10 ficheiros de uma vez no campo 'anexos'
router.post('/upload', verificarToken, upload.array('anexos', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Nenhum ficheiro enviado.' });

        // Monta os links gerados pelo Cloudinary
        const urls = req.files.map(file => ({
            url: file.path,
            nome: file.originalname,
            tipo: file.mimetype
        }));

        res.status(200).json({ success: true, anexos: urls });
    } catch (error) {
        console.error("Erro no upload da Nuvem:", error);
        res.status(500).json({ error: 'Erro ao enviar ficheiros para a Nuvem.' });
    }
});

// 📝 4. ROTA PARA CRIAR A PUBLICAÇÃO NO MONGODB
router.post('/posts', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, autorTipo, escolaId, anexos } = req.body;
        
        if (!texto && (!anexos || anexos.length === 0)) {
            return res.status(400).json({ error: 'A publicação não pode estar vazia.' });
        }

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(),
            escolaId: escolaId || 'DEFAULT',
            autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor',
            texto: texto,
            anexos: anexos || [], // Aqui gravamos apenas os LINKS do Cloudinary!
            dataCriacao: new Date().toISOString(),
            comentarios: [],
            likes: 0
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        res.status(201).json({ success: true, post: novoPost });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno ao publicar.' });
    }
});

// 🔍 5. ROTA PARA BUSCAR TODAS AS PUBLICAÇÕES
router.get('/posts', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const posts = await database.collection('workspace_posts')
            .find({})
            .sort({ dataCriacao: -1 })
            .limit(50)
            .toArray();

        res.status(200).json(posts);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar o feed.' });
    }
});

module.exports = router;