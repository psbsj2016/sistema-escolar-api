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

// 🛡️ Middleware para saber QUEM está a pedir a notificação
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

// 💾 ROTA 2: Guardar o "Contacto" do telemóvel na Base de Dados
router.post('/subscribe', verificarToken, async (req, res) => {
    try {
        const subscription = req.body;
        const database = await connectDB();
        
        // O "endpoint" é o ID único que a Apple/Google dão a cada aparelho
        await database.collection('push_subscriptions').updateOne(
            { endpoint: subscription.endpoint }, 
            { 
                $set: { 
                    userId: req.usuario.id,
                    escolaId: req.usuario.escolaId,
                    subscription: subscription,
                    dataRegistro: new Date().toISOString()
                } 
            },
            { upsert: true } // Atualiza se já existir, cria se for novo
        );

        res.status(201).json({ success: true, message: 'Aparelho registado para notificações!' });
    } catch (error) {
        console.error('Erro ao subscrever push:', error);
        res.status(500).json({ error: 'Erro ao guardar subscrição no servidor.' });
    }
});

// 🚀 ROTA 3: Um botão mágico para Testar (Dispara para o próprio utilizador)
router.post('/teste', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        // Puxa todos os aparelhos (PC, Telemóvel, Tablet) da pessoa que clicou
        const inscricoes = await database.collection('push_subscriptions').find({ userId: req.usuario.id }).toArray();

        if (inscricoes.length === 0) {
            return res.status(404).json({ error: 'Nenhum aparelho registado para receber Push.' });
        }

        // A mensagem que vai aparecer no ecrã bloqueado
        const payload = JSON.stringify({
            title: '🎉 Magia PTT a funcionar!',
            body: 'Se está a ler isto, as notificações Push estão ativas no seu telemóvel.',
            url: '/' // Para onde a app vai quando clicamos na notificação
        });

        // Dispara para a Apple/Google entregar nos telemóveis
        for (let inscricao of inscricoes) {
            await webpush.sendNotification(inscricao.subscription, payload).catch(err => {
                // Se der erro 410, significa que a pessoa removeu a permissão no telemóvel
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