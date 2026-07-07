const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');

// 🔍 1. LISTAR OS LOGS (Apenas para o Diretor ver o que se passa)
router.get('/', async (req, res) => {
    try {
        const database = await connectDB();
        
        // 🛡️ TRUQUE DE MESTRE: Suporta tanto req.user como req.usuario
        const utilizadorLogado = req.usuario || req.user;
        
        if (!utilizadorLogado || !utilizadorLogado.escolaId) {
            return res.status(401).json({ error: 'Acesso negado: Escola não identificada.' });
        }

        const logs = await database.collection('auditoria')
            .find({ escolaId: utilizadorLogado.escolaId })
            .sort({ data: -1 })
            .limit(100)
            .toArray();

        res.status(200).json(logs);
    } catch (error) {
        // 🔥 Agora, se der erro, o servidor vai imprimir o motivo EXATO no Render!
        console.error("Erro GET Auditoria:", error);
        res.status(500).json({ error: 'Erro ao buscar histórico de auditoria.' });
    }
});

// 📝 2. GRAVAR UM LOG (O sistema chama esta rota sempre que alguém faz algo importante)
router.post('/', async (req, res) => {
    try {
        const { acao, detalhes } = req.body;
        const database = await connectDB();
        
        const utilizadorLogado = req.usuario || req.user;

        if (!utilizadorLogado) {
            return res.status(401).json({ error: 'Acesso negado.' });
        }

        const novoLog = {
            escolaId: utilizadorLogado.escolaId,
            usuarioId: utilizadorLogado.id,
            // Guardamos quem fez a ação!
            usuarioNome: utilizadorLogado.nome || utilizadorLogado.login || 'Desconhecido',
            usuarioTipo: utilizadorLogado.tipo || 'Desconhecido',
            acao: acao,
            detalhes: detalhes || '',
            data: new Date().toISOString()
        };

        await database.collection('auditoria').insertOne(novoLog);
        res.status(201).json({ success: true });
    } catch (error) {
        console.error("Erro POST Auditoria:", error);
        res.status(500).json({ error: 'Erro ao registar log de auditoria.' });
    }
});

module.exports = router;