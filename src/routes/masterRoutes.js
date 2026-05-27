const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const connectDB = require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET;
const SENHA_DONO = process.env.SENHA_DONO;

const verifyMaster = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Não autorizado.' });
    jwt.verify(authHeader.split(' ')[1], JWT_SECRET, (err, decoded) => {
        if (err || !decoded.master) return res.status(401).json({ error: 'Acesso negado.' });
        next();
    });
};

router.post('/login', (req, res) => {
    if (req.body.senha === SENHA_DONO) {
        const token = jwt.sign({ master: true }, JWT_SECRET, { expiresIn: '2h' });
        return res.json({ success: true, token });
    }
    res.status(401).json({ error: 'Senha incorreta.' });
});

router.post('/bloquear', verifyMaster, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    await database.collection('ativacoes').updateOne({ email: email.toLowerCase() }, { $set: { status: 'Bloqueado' } });
    await database.collection('escola').updateOne({ email: email.toLowerCase() }, { $set: { plano: 'Bloqueado' } });
    res.json({ success: true });
});

router.post('/excluir-conta', verifyMaster, async (req, res) => {
    const { email } = req.body;
    const target = email.toLowerCase().trim();
    const database = await connectDB();
    const escola = await database.collection('escola').findOne({ email: target });
    const id = escola?.escolaId;

    if (id) {
        const colecoes = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'usuarios', 'estoques', 'contratos', 'notificacoes'];
        for (const col of colecoes) await database.collection(col).deleteMany({ escolaId: id });
    }
    await database.collection('escola').deleteOne({ email: target });
    await database.collection('usuarios').deleteMany({ login: target });
    await database.collection('ativacoes').deleteOne({ email: target });
    res.json({ success: true, message: 'Conta obliterada.' });
});

module.exports = router;