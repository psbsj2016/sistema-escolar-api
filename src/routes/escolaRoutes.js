const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const { filtroTenant } = require('../middlewares/auth');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// 🚀 1. CRIAMOS O MEGA-FONE GLOBAL SE NÃO EXISTIR[cite: 7]
if (!global.escolaEmitter) {
    const EventEmitter = require('events');
    global.escolaEmitter = new EventEmitter();
}

router.get('/', async (req, res) => {
    const db = await connectDB();
    const data = await db.collection('escola').findOne({ $or: [{ escolaId: req.escolaId }, { donoId: req.userId }] });
    if (data) delete data._id;
    res.json(data || {});
});

router.put('/', async (req, res) => {
    const db = await connectDB();
    const { _id, ...body } = req.body;
    await db.collection('escola').updateOne({ escolaId: req.escolaId }, { $set: { ...body, escolaId: req.escolaId } }, { upsert: true });
    
    // 🚀 2. GATILHO DE TEMPO REAL: O Servidor "grita" que esta escola foi atualizada![cite: 7]
    if (global.escolaEmitter) {
        global.escolaEmitter.emit('atualizacao-escola', req.escolaId);
    }

    res.json({ success: true });
});

router.post('/validar-pin', async (req, res) => {
    const { pin } = req.body;
    const db = await connectDB();
    const ativacao = await db.collection('ativacoes').findOne({ pinAtivacao: pin.toUpperCase(), status: 'Pendente' });
    if (ativacao) {
        await db.collection('ativacoes').updateOne({ _id: ativacao._id }, { $set: { status: 'Ativo', dataAtivacao: new Date().toISOString() } });
        await db.collection('escola').updateOne({ escolaId: req.escolaId }, { $set: { plano: ativacao.plano } });
        return res.json({ success: true, plano: ativacao.plano });
    }
    res.status(404).json({ error: 'PIN inválido.' });
});

// Gestão de Usuários da Escola
router.get('/usuarios', async (req, res) => {
    const db = await connectDB();
    const data = await db.collection('usuarios').find({ escolaId: req.escolaId }).toArray();
    res.json(data.map(({ _id, senha, ...rest }) => rest));
});

module.exports = router;