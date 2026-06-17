const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db'); // Ajuste o caminho se a sua pasta config estiver noutro local

// Middleware simples para validar a sessão (caso não tenha um global)
const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    // Assume-se que o token é verificado aqui (pode usar o jwt.verify se desejar)
    next();
};

// 1. ROTA PARA CRIAR UMA NOVA PUBLICAÇÃO
router.post('/posts', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, autorTipo, escolaId, anexos } = req.body;
        
        if (!texto && (!anexos || anexos.length === 0)) {
            return res.status(400).json({ error: 'A publicação não pode estar vazia.' });
        }

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(),
            escolaId: escolaId || 'DEFAULT', // O ideal é extrair do token JWT
            autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor',
            texto: texto,
            anexos: anexos || [], // Array de URLs (Fase 4: Nuvem)
            dataCriacao: new Date().toISOString(),
            comentarios: [],
            likes: 0
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        
        // Retorna o post recém-criado para o frontend desenhar imediatamente
        res.status(201).json({ success: true, post: novoPost });

    } catch (error) {
        console.error("Erro ao criar post no Workspace:", error);
        res.status(500).json({ error: 'Erro interno ao publicar.' });
    }
});

// 2. ROTA PARA BUSCAR TODAS AS PUBLICAÇÕES
router.get('/posts', verificarToken, async (req, res) => {
    try {
        // Num cenário real, filtramos pelo escolaId da requisição
        const database = await connectDB();
        const posts = await database.collection('workspace_posts')
            .find({})
            .sort({ dataCriacao: -1 }) // Mais recentes primeiro
            .limit(50) // Paginação básica
            .toArray();

        res.status(200).json(posts);
    } catch (error) {
        console.error("Erro ao buscar posts:", error);
        res.status(500).json({ error: 'Erro ao carregar o feed.' });
    }
});

// 3. ROTA PARA ADICIONAR COMENTÁRIOS / RESPOSTAS A UMA ATIVIDADE
router.post('/posts/:id/comentarios', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto, autorNome } = req.body;

        const database = await connectDB();
        const novoComentario = {
            id: crypto.randomUUID(),
            autorNome: autorNome,
            texto: texto,
            data: new Date().toISOString()
        };

        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $push: { comentarios: novoComentario } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Post não encontrado.' });
        }

        res.status(201).json({ success: true, comentario: novoComentario });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao comentar.' });
    }
});

module.exports = router;