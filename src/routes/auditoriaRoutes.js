const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');

// 🔍 1. LISTAR OS LOGS (Apenas para o Diretor ver o que se passa)
router.get('/', async (req, res) => {
    try {
        const database = await connectDB();
        
        // Puxa os últimos 100 eventos da escola, do mais recente para o mais antigo
        const logs = await database.collection('auditoria')
            .find({ escolaId: req.usuario.escolaId })
            .sort({ data: -1 })
            .limit(100)
            .toArray();

        res.status(200).json(logs);
    } catch (error) {
        console.error("Erro na Auditoria:", error);
        res.status(500).json({ error: 'Erro ao buscar histórico de auditoria.' });
    }
});

// 📝 2. GRAVAR UM LOG (O sistema chama esta rota sempre que alguém faz algo importante)
router.post('/', async (req, res) => {
    try {
        const { acao, detalhes } = req.body;
        const database = await connectDB();
        
        const novoLog = {
            escolaId: req.usuario.escolaId,
            usuarioId: req.usuario.id,
            // Guardamos quem fez a ação!
            usuarioNome: req.usuario.nome || req.usuario.login || 'Desconhecido',
            usuarioTipo: req.usuario.tipo || 'Desconhecido',
            acao: acao,
            detalhes: detalhes || '',
            data: new Date().toISOString()
        };

        await database.collection('auditoria').insertOne(novoLog);
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registar log de auditoria.' });
    }
});

module.exports = router;