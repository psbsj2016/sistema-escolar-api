const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const jwt = require('jsonwebtoken');

// 🧠 FUNÇÃO MÁGICA: Extrai os dados do utilizador de qualquer lugar possível (Até do Cookie direto!)
const obterDadosUtilizador = (req) => {
    // 1. Tenta ler formatos comuns de objetos anexados pelo verifyJWT global
    const alvo = req.usuario || req.user || req.tokenData;
    if (alvo && alvo.escolaId) {
        return {
            id: alvo.id || alvo.userId,
            escolaId: alvo.escolaId,
            nome: alvo.nome || alvo.login || 'Membro da Equipa',
            tipo: alvo.tipo || 'Equipe'
        };
    }

    // 2. Tenta ler propriedades diretas anexadas no objeto 'req'
    if (req.escolaId) {
        return {
            id: req.userId || req.id,
            escolaId: req.escolaId,
            nome: req.usuarioNome || req.login || 'Membro da Equipa',
            tipo: req.usuarioTipo || req.tipo || 'Equipe'
        };
    }

    // 🛡️ 3. PLANO DE CONTINGÊNCIA ABSOLUTO: Se o verifyJWT falhou a passar os dados, nós lemos o cookie diretamente!
    try {
        const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return {
                id: decoded.id,
                escolaId: decoded.escolaId,
                nome: decoded.nome || decoded.login || 'Membro da Equipa',
                tipo: decoded.tipo || 'Equipe'
            };
        }
    } catch (e) {
        console.error("Falha na contingência de segurança da auditoria:", e);
    }

    return null; // Se mesmo assim não houver token, o acesso é realmente negado
};

// 🔍 1. LISTAR OS LOGS
router.get('/', async (req, res) => {
    try {
        const database = await connectDB();
        const user = obterDadosUtilizador(req);
        
        if (!user || !user.escolaId) {
            return res.status(401).json({ error: 'Acesso negado: Login inválido.' });
        }

        const logs = await database.collection('auditoria')
            .find({ escolaId: user.escolaId })
            .sort({ data: -1 })
            .limit(100)
            .toArray();

        res.status(200).json(logs);
    } catch (error) {
        console.error("Erro GET Auditoria:", error);
        res.status(500).json({ error: 'Erro ao buscar histórico de auditoria.' });
    }
});

// 📝 2. GRAVAR UM LOG
router.post('/', async (req, res) => {
    try {
        const { acao, detalhes } = req.body;
        const database = await connectDB();
        const user = obterDadosUtilizador(req);

        if (!user || !user.escolaId) {
            return res.status(401).json({ error: 'Acesso negado.' });
        }

        const novoLog = {
            escolaId: user.escolaId,
            usuarioId: user.id,
            usuarioNome: user.nome,
            usuarioTipo: user.tipo,
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