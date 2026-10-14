const express = require('express');
const router = express.Router();
const webpush = require('web-push');
const connectDB = require('../config/db');
const jwt = require('jsonwebtoken');

// ⚙️ 1. Ligar o Motor com as Chaves do Render
webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

// 🛡️ Middleware para identificar QUEM está a pedir a notificação
const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado.' });
    try {
        req.usuario = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Token inválido.' });
    }
};

// 📡 ROTA 1: Entregar a Chave Pública ao Telemóvel (Frontend)
router.get('/public-key', (req, res) => {
    res.status(200).json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// 💾 ROTA 2: Guardar o "Contacto" e o Cargo do aparelho na Base de Dados
router.post('/subscribe', verificarToken, async (req, res) => {
    try {
        const subscription = req.body;
        const database = await connectDB();
        
        await database.collection('push_subscriptions').updateOne(
            { endpoint: subscription.endpoint }, 
            { 
                $set: { 
                    userId: req.usuario.id,
                    escolaId: req.usuario.escolaId,
                    tipo: req.usuario.tipo || 'Gestor', // Guarda o cargo para filtrar avisos financeiros
                    subscription: subscription,
                    dataRegistro: new Date().toISOString()
                } 
            },
            { upsert: true }
        );

        res.status(201).json({ success: true, message: 'Aparelho registado para notificações!' });
    } catch (error) {
        console.error('Erro ao subscrever push:', error);
        res.status(500).json({ error: 'Erro ao guardar subscrição no servidor.' });
    }
});

// 🚀 ROTA 3: Botão para Testar Push no próprio aparelho
router.post('/teste', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const inscricoes = await database.collection('push_subscriptions').find({ userId: req.usuario.id }).toArray();

        if (inscricoes.length === 0) {
            return res.status(404).json({ error: 'Nenhum aparelho registado. Clique em "Ativar Notificações" no menu.' });
        }

        const payload = JSON.stringify({
            title: '🎉 Notificações Ativas!',
            body: 'O seu aparelho está conectado ao radar de alertas do Sistema PTT.',
            url: '/'
        });

        for (let inscricao of inscricoes) {
            await webpush.sendNotification(inscricao.subscription, payload).catch(err => {
                if (err.statusCode === 410 || err.statusCode === 404) {
                    database.collection('push_subscriptions').deleteOne({ _id: inscricao._id });
                }
            });
        }

        res.status(200).json({ success: true, message: 'Notificação enviada!' });
    } catch (error) {
        console.error('Erro no teste push:', error);
        res.status(500).json({ error: 'Falha ao enviar notificação.' });
    }
});

module.exports = router;