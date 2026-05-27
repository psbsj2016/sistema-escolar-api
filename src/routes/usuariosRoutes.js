const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { filtroTenant } = require('../middlewares/auth');

router.put('/atualizar-conta', async (req, res) => {
    const { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ id: req.userId, escolaId: req.escolaId });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
    
    const senhaValida = await bcrypt.compare(senhaAtual, user.senha);
    if (!senhaValida) return res.status(401).json({ error: 'Senha atual incorreta.' });
    
    const updateData = { login: novoLogin };
    if (novoEmail) updateData.email = novoEmail;
    if (novaSenha) updateData.senha = await bcrypt.hash(novaSenha, 10);
    
    await database.collection('usuarios').updateOne({ id: req.userId }, { $set: updateData });
    res.json({ success: true });
});

router.get('/', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('usuarios').find({ escolaId: req.escolaId }).toArray();
    res.json(data.map(({ _id, senha, ...rest }) => rest));
});

router.post('/', async (req, res) => {
    const database = await connectDB();
    const { senha, ...body } = req.body;
    const novoUsuario = { ...body, id: crypto.randomUUID(), escolaId: req.escolaId };
    if (senha) novoUsuario.senha = await bcrypt.hash(senha, 10);
    await database.collection('usuarios').insertOne(novoUsuario);
    delete novoUsuario.senha; 
    res.json(novoUsuario);
});

router.put('/:id', async (req, res) => {
    const database = await connectDB();
    const { _id, senha, ...body } = req.body;
    const updateData = { ...body };
    if (senha) updateData.senha = await bcrypt.hash(senha, 10);
    await database.collection('usuarios').updateOne({ id: req.params.id, ...filtroTenant(req) }, { $set: updateData });
    res.json({ success: true });
});

router.delete('/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection('usuarios').deleteOne({ id: req.params.id, ...filtroTenant(req) });
    res.json({ success: true });
});

module.exports = router;