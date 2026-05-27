const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const { sanitizeString } = require('../middlewares/security');

// Buscar dados básicos da escola para a página de matrícula
router.get('/escola/:id', async (req, res) => {
    try {
        const database = await connectDB();
        const escola = await database.collection('escola').findOne({ escolaId: req.params.id });
        if (!escola) return res.status(404).json({ error: 'Escola não encontrada.' });

        res.json({ escolaId: escola.escolaId, configMatricula: escola.configMatricula || null });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar matrícula.' });
    }
});

// Receber formulário de matrícula externa
router.post('/receber-matricula', async (req, res) => {
    try {
        const database = await connectDB();
        const { escolaId, nome, email, whatsapp, conteudoHTML } = req.body;

        const idAlunoGerado = crypto.randomUUID();
        const novoAluno = {
            id: idAlunoGerado,
            escolaId,
            nome,
            email,
            whatsapp,
            status: 'Ativo',
            dataMatricula: new Date().toISOString()
        };

        await database.collection('alunos').insertOne(novoAluno);

        // Criar notificação para o gestor
        await database.collection('notificacoes').insertOne({
            id: "NOTI_" + crypto.randomUUID(),
            escolaId,
            tipo: "matricula",
            titulo: "🎉 Nova Matrícula Online!",
            mensagem: `${nome} acabou de se matricular pelo link externo.`,
            lida: false,
            dataCriacao: new Date().toISOString()
        });

        res.json({ success: true, message: 'Matrícula realizada!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar matrícula.' });
    }
});

module.exports = router;