const express = require('express');
const router = express.Router();
const webpush = require('web-push');
const crypto = require('crypto');
const connectDB = require('../config/db');
const jwt = require('jsonwebtoken');

// ⚙️ 1. Ligar o Motor com as Chaves do Render
webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

// 🛡️ Middleware para identificar QUEM está a fazer o pedido
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
                    tipo: req.usuario.tipo || 'Gestor',
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
            return res.status(404).json({ error: 'Nenhum aparelho registado. Ative as notificações primeiro.' });
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

// 🎓 ROTA 4: Enviar Aviso Direto para o Sininho/Tela do Workspace do Aluno + Web Push
router.post('/enviar-aviso-aluno', verificarToken, async (req, res) => {
    try {
        const { alvoUserId, alunoRefId, nomeDestino, titulo, mensagem } = req.body;
        if (!titulo || !mensagem) {
            return res.status(400).json({ error: 'Preencha o título e a mensagem do aviso.' });
        }

        const database = await connectDB();
        const escolaId = req.usuario.escolaId || 'DEFAULT';
        const remetenteNome = req.usuario.nome || req.usuario.login || 'Coordenação';
        const tituloLimpo = titulo.trim();
        const mensagemLimpa = mensagem.trim();

        // 1. Descobrir exatamente os nomes de utilizador no Workspace (coleção 'usuarios')
        const nomesDestinatarios = new Set();

        if (alvoUserId && alvoUserId !== 'TODOS') {
            // Busca a conta específica do aluno no Workspace
            const contaUser = await database.collection('usuarios').findOne({
                $or: [
                    { id: String(alvoUserId) },
                    ...(alunoRefId ? [{ alunoRefId: String(alunoRefId) }] : [])
                ]
            });

            if (contaUser) {
                const nomeExatoNoWS = (contaUser.nome || contaUser.login || '').trim();
                if (nomeExatoNoWS) nomesDestinatarios.add(nomeExatoNoWS);
            }
            // Fallback de segurança caso o nome passado já seja o nome de login
            if (nomesDestinatarios.size === 0 && nomeDestino) {
                nomesDestinatarios.add(nomeDestino.trim());
            }
        } else {
            // Se for "TODOS", busca todas as contas de alunos da escola no Workspace
            const filtroEscola = escolaId !== 'DEFAULT' ? { escolaId: escolaId } : {};
            const usuarios = await database.collection('usuarios').find(filtroEscola).toArray();
            
            usuarios.forEach(u => {
                if (u.tipo === 'Aluno' || u.alunoRefId) {
                    const nomeWS = (u.nome || u.login || '').trim();
                    if (nomeWS) nomesDestinatarios.add(nomeWS);
                }
            });
        }

        const listaNomes = Array.from(nomesDestinatarios);
        if (listaNomes.length === 0) {
            return res.status(404).json({ error: 'Nenhum aluno com conta ativa no Workspace foi encontrado.' });
        }

        // 2. Grava na coleção oficial 'workspace_notificacoes' que o alertas.js do aluno lê!
        const agoraIso = new Date().toISOString();
        const notificacoesWorkspace = listaNomes.map(destNome => ({
            id: 'notif_coord_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8),
            escolaId: escolaId,
            destinatarioNome: destNome,
            remetenteNome: remetenteNome,
            tituloAviso: tituloLimpo,
            mensagem: `enviou um comunicado: <strong>"${tituloLimpo}"</strong> — ${mensagemLimpa}`,
            origem: 'aviso_coordenacao',
            origemId: 'feed',
            destinoNome: tituloLimpo,
            lida: false,
            data: agoraIso
        }));

        await database.collection('workspace_notificacoes').insertMany(notificacoesWorkspace);

        // 3. Dispara o evento em TEMPO REAL no túnel SSE do Workspace!
        // Como o alertas.js às vezes liga com 'DEFAULT' e às vezes com o ID da escola, emitimos para ambos se necessário
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'NOVA_NOTIFICACAO',
                destinatarios: listaNomes,
                escolaId: escolaId
            });
            if (escolaId !== 'DEFAULT') {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'NOVA_NOTIFICACAO',
                    destinatarios: listaNomes,
                    escolaId: 'DEFAULT'
                });
            }
        }

        // 4. Também dispara o Web Push caso o aluno tenha ativado notificações no telemóvel
        const filtroPush = (alvoUserId && alvoUserId !== 'TODOS')
            ? { userId: String(alvoUserId) }
            : { escolaId: escolaId, tipo: 'Aluno' };

        const aparelhosAlunos = await database.collection('push_subscriptions').find(filtroPush).toArray();
        let enviadosPush = 0;

        if (aparelhosAlunos.length > 0) {
            const payload = JSON.stringify({
                title: tituloLimpo,
                body: mensagemLimpa,
                url: '/workspace.html'
            });

            for (const ap of aparelhosAlunos) {
                try {
                    await webpush.sendNotification(ap.subscription, payload);
                    enviadosPush++;
                } catch (err) {
                    if (err.statusCode === 410 || err.statusCode === 404) {
                        await database.collection('push_subscriptions').deleteOne({ _id: ap._id });
                    }
                }
            }
        }

        res.status(200).json({
            success: true,
            enviadosWorkspace: listaNomes.length,
            enviadosPush: enviadosPush,
            message: `🚀 Aviso entregue ao vivo no Workspace para ${listaNomes.length} aluno(s)!`
        });
    } catch (error) {
        console.error('Erro ao enviar aviso para aluno:', error);
        res.status(500).json({ error: 'Erro ao enviar aviso para o aluno.' });
    }
});

module.exports = router;