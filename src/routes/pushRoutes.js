const express = require('express');
const router = express.Router();
const webpush = require('web-push');
const crypto = require('crypto');
const connectDB = require('../config/db');
const jwt = require('jsonwebtoken');

// ⚙️ 1. Ligar o Motor com as Chaves do Render
webpush.setVapidDetails(
    process.env.VAPID_SUBJECT ? process.env.VAPID_SUBJECT : 'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

// 🛡️ Middleware para identificar QUEM está a fazer o pedido
const verificarToken = (req, res, next) => {
    const authHeader = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
    const token = (req.cookies && req.cookies.token_acesso) ? req.cookies.token_acesso : authHeader;
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
                    tipo: req.usuario.tipo ? req.usuario.tipo : 'Gestor',
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

// ============================================================================
// 🗂️ ROTAS DE MENSAGENS SALVAS (PARA REUTILIZAR EM OUTROS MOMENTOS)
// ============================================================================

// Listar mensagens salvas da escola
router.get('/avisos-salvos', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const escolaId = req.usuario.escolaId ? req.usuario.escolaId : 'DEFAULT';
        const filtro = escolaId !== 'DEFAULT' ? { $or: [{ escolaId: escolaId }, { escolaId: 'DEFAULT' }] } : {};
        
        const salvos = await database.collection('workspace_avisos_salvos')
            .find(filtro)
            .sort({ dataCriacao: -1 })
            .limit(50)
            .toArray();

        res.status(200).json(salvos);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar mensagens salvas.' });
    }
});

// Guardar manualmente um modelo de mensagem sem precisar de enviar
router.post('/avisos-salvos', verificarToken, async (req, res) => {
    try {
        const { titulo, mensagem } = req.body;
        if (!titulo || !mensagem) {
            return res.status(400).json({ error: 'Preencha o título e a mensagem para salvar.' });
        }

        const database = await connectDB();
        const escolaId = req.usuario.escolaId ? req.usuario.escolaId : 'DEFAULT';
        const tituloLimpo = titulo.trim();
        const msgLimpa = mensagem.trim();

        const existente = await database.collection('workspace_avisos_salvos').findOne({
            escolaId: escolaId,
            titulo: tituloLimpo,
            mensagem: msgLimpa
        });

        if (existente) {
            await database.collection('workspace_avisos_salvos').updateOne(
                { id: existente.id },
                { $set: { dataCriacao: new Date().toISOString() } }
            );
            return res.status(200).json({ success: true, message: 'Mensagem atualizada na sua lista!' });
        }

        const novoModelo = {
            id: 'msg_salva_' + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: tituloLimpo,
            mensagem: msgLimpa,
            dataCriacao: new Date().toISOString()
        };

        await database.collection('workspace_avisos_salvos').insertOne(novoModelo);
        res.status(201).json({ success: true, item: novoModelo, message: '💾 Mensagem guardada para uso futuro!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao guardar mensagem.' });
    }
});

// Excluir uma mensagem salva
router.delete('/avisos-salvos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_avisos_salvos').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir mensagem salva.' });
    }
});

// ============================================================================
// 🎓 ROTA 4: ENVIAR AVISO EXCLUSIVAMENTE PARA O WORKSPACE DO ALUNO + PUSH
// ============================================================================
router.post('/enviar-aviso-aluno', verificarToken, async (req, res) => {
    try {
        const { alvoUserId, alunoRefId, nomeDestino, nomesListaFrontend, titulo, mensagem, salvarMensagem } = req.body;
        if (!titulo || !mensagem) {
            return res.status(400).json({ error: 'Preencha o título e a mensagem do aviso.' });
        }

        const database = await connectDB();
        const escolaId = req.usuario.escolaId ? req.usuario.escolaId : 'DEFAULT';
        const remetenteNome = req.usuario.nome ? req.usuario.nome : (req.usuario.login ? req.usuario.login : 'Coordenação');
        const tituloLimpo = titulo.trim();
        const mensagemLimpa = mensagem.trim();

        // 🧹 LIMPEZA AUTOMÁTICA: Remove qualquer aviso antigo de aluno que tenha caído no sininho do sistema principal
        try {
            await database.collection('notificacoes').deleteMany({ tipo: 'aviso_workspace_aluno' });
        } catch (e) {}

        // 💾 1. Se a opção "Guardar para uso futuro" estiver marcada, salva na galeria de mensagens
        if (salvarMensagem !== false) {
            try {
                const jaSalva = await database.collection('workspace_avisos_salvos').findOne({
                    escolaId: escolaId,
                    titulo: tituloLimpo,
                    mensagem: mensagemLimpa
                });
                if (jaSalva) {
                    await database.collection('workspace_avisos_salvos').updateOne(
                        { id: jaSalva.id },
                        { $set: { dataCriacao: new Date().toISOString() } }
                    );
                } else {
                    await database.collection('workspace_avisos_salvos').insertOne({
                        id: 'msg_salva_' + crypto.randomUUID(),
                        escolaId: escolaId,
                        titulo: tituloLimpo,
                        mensagem: mensagemLimpa,
                        dataCriacao: new Date().toISOString()
                    });
                }
            } catch (e) {}
        }

        // 🎯 2. Descobre TODOS os identificadores (nome e login) do(s) aluno(s) no Workspace
        const destinatariosParaGravar = new Set();

        // Adiciona nomes enviados diretamente pelo painel de gestão (garantia absoluta)
        if (Array.isArray(nomesListaFrontend)) {
            nomesListaFrontend.forEach(n => {
                if (n && String(n).trim()) destinatariosParaGravar.add(String(n).trim());
            });
        }

        if (alvoUserId && alvoUserId !== 'TODOS') {
            const criterios = [{ id: String(alvoUserId) }];
            if (alunoRefId) criterios.push({ alunoRefId: String(alunoRefId) });
            const contaUser = await database.collection('usuarios').findOne({ $or: criterios });

            if (contaUser) {
                const nomePrincipal = contaUser.nome ? contaUser.nome.trim() : (contaUser.login ? contaUser.login.trim() : '');
                if (nomePrincipal) destinatariosParaGravar.add(nomePrincipal);
                if (contaUser.login && contaUser.login.trim() !== nomePrincipal) {
                    destinatariosParaGravar.add(contaUser.login.trim());
                }
            }
            if (destinatariosParaGravar.size === 0 && nomeDestino) {
                destinatariosParaGravar.add(String(nomeDestino).trim());
            }
       } else {
            // Modo TODOS: Busca todas as contas de alunos ATIVOS no Workspace
            const todosAlunos = await database.collection('alunos').find({}).toArray();
            const idsInativos = new Set(
                todosAlunos
                    .filter(a => {
                        const st = String(a.status || 'Ativo').trim().toLowerCase();
                        return st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist');
                    })
                    .map(a => String(a.id))
            );

            const todosUsuarios = await database.collection('usuarios').find({}).toArray();
            todosUsuarios.forEach(u => {
                if (u.alunoRefId && idsInativos.has(String(u.alunoRefId))) return;
                const pertenceEscola = (escolaId === 'DEFAULT' || !u.escolaId || String(u.escolaId) === String(escolaId));
                const ehAluno = (u.tipo === 'Aluno' || Boolean(u.alunoRefId));
                if (pertenceEscola && ehAluno) {
                    const nomePrincipal = u.nome ? u.nome.trim() : (u.login ? u.login.trim() : '');
                    if (nomePrincipal) destinatariosParaGravar.add(nomePrincipal);
                }
            });
        }

        const listaNomes = Array.from(destinatariosParaGravar);
        if (listaNomes.length === 0) {
            return res.status(404).json({ error: 'Nenhum aluno com acesso ativo no Workspace foi encontrado.' });
        }

        // 📥 3. Grava EXCLUSIVAMENTE em 'workspace_notificacoes' (onde o aluno tem acesso no Workspace)
        const agoraIso = new Date().toISOString();
        const notificacoesWorkspace = listaNomes.map(destNome => ({
            id: 'notif_coord_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8),
            escolaId: escolaId,
            destinatarioNome: destNome,
            remetenteNome: remetenteNome,
            tituloAviso: tituloLimpo,
            textoAvisoPuro: mensagemLimpa,
            mensagem: ` enviou um comunicado: <strong>"${tituloLimpo}"</strong> — ${mensagemLimpa}`,
            origem: 'aviso_coordenacao',
            origemId: 'feed',
            destinoNome: tituloLimpo,
            lida: false,
            data: agoraIso
        }));

        await database.collection('workspace_notificacoes').insertMany(notificacoesWorkspace);

        // 📡 4. Dispara o sinal ao vivo no túnel SSE do Workspace para tocar o sininho do aluno na hora
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'NOVA_NOTIFICACAO',
                destinatarios: listaNomes,
                escolaId: 'DEFAULT'
            });
            if (escolaId !== 'DEFAULT') {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'NOVA_NOTIFICACAO',
                    destinatarios: listaNomes,
                    escolaId: escolaId
                });
            }
        }

        // 📲 5. Dispara o Web Push apenas para telemóveis de Alunos
        const filtroPush = (alvoUserId && alvoUserId !== 'TODOS')
            ? { userId: String(alvoUserId) }
            : { tipo: 'Aluno' };

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
            message: `🚀 Aviso entregue no Workspace para ${listaNomes.length} aluno(s)!`
        });
    } catch (error) {
        console.error('Erro ao enviar aviso para aluno:', error);
        res.status(500).json({ error: 'Erro ao enviar aviso para o aluno.' });
    }
});

module.exports = router;