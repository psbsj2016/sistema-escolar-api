const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const multerCloudinary = require('multer-storage-cloudinary');
const CloudinaryStorage = multerCloudinary.CloudinaryStorage || multerCloudinary;

const { enviarParaR2 } = require('../config/cloudflareR2');
const { filtroTenant } = require('../middlewares/auth');

// 🚀 PROTEÇÃO ANTI-502: Interceta a demora aos 15 MINUTOS (para suportar uploads gigantes de 700MB!)
router.use((req, res, next) => {
    req.setTimeout(900000, () => {
        console.log('⚠️ Timeout na requisição atingido (15m). Destruindo conexão.');
        if (!res.headersSent) {
            res.status(408).json({ error: 'Tempo esgotado. A sua internet pode estar lenta para o tamanho do ficheiro.' });
        }
        req.destroy();
    });
    next();
});

// ⚡ MOTOR DE TEMPO REAL (Túnel SSE)
const EventEmitter = require('events');
const workspaceStream = new EventEmitter();
workspaceStream.setMaxListeners(0); 
global.workspaceStream = workspaceStream;

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, os.tmpdir()); // Salva o ficheiro gigante no disco rígido temporário do servidor
    },
    filename: function (req, file, cb) {
        const nomeSeguro = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
        cb(null, `upload_${Date.now()}_${nomeSeguro}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 800 * 1024 * 1024, // 🚀 Limite expandido para 800 MB físicos!
        files: 3 // Evita sobrecarga simultânea
    }
});

const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    
    // 🚀 O MOTOR "FANTASMA" FOI REMOVIDO!
    // A presença online passa a ser controlada EXCLUSIVAMENTE pelo Heartbeat (/ping) e só quando a aba está aberta.
    next();
};


// ============================================================================
// 🚀 TÚNEL DE CONEXÃO EM TEMPO REAL (SERVER-SENT EVENTS)
// ============================================================================
router.get('/stream', verificarToken, (req, res) => { // <-- Cadeado adicionado aqui!
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); 

    const escolaId = req.query.escolaId;

    const enviarEvento = (data) => {
        if (data.escolaId === escolaId || data.escolaId === 'DEFAULT') {
            res.write(`data: ${JSON.stringify(data)}\n\n`);
        }
    };

    workspaceStream.on('evento_realtime', enviarEvento);
    req.on('close', () => workspaceStream.off('evento_realtime', enviarEvento));
});

// ============================================================================
// 🚀 PLANO B (VIA VERDE): ROTA PARA SOLICITAR BILHETE VIP DE UPLOAD DIRETO
// ============================================================================
router.post('/upload/solicitar-link', verificarToken, async (req, res) => {
    try {
        const { nomeFicheiro, tipoFicheiro } = req.body;
        
        if (!nomeFicheiro || !tipoFicheiro) {
            return res.status(400).json({ error: 'Faltam dados do ficheiro para gerar a autorização.' });
        }

        // 🚀 BLINDAGEM DE NUVEM: Remove espaços e acentos que quebram o link na Cloudflare R2!
        const nomeSeguro = String(nomeFicheiro).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const nomeFinal = `doc_${Date.now()}_${nomeSeguro}`;

        // Importamos a nossa nova máquina de bilhetes
        const { gerarLinkUploadDireto } = require('../config/cloudflareR2');
        
        // Fabricamos o link VIP e o link final de leitura com o nome perfeitamente limpo!
        const dadosAutorizacao = await gerarLinkUploadDireto(nomeFinal, tipoFicheiro);

        // Devolvemos ao navegador do aluno/professor!
        res.status(200).json({ success: true, ...dadosAutorizacao });
    } catch (erro) {
        console.error('🚨 Erro na Via Verde:', erro);
        res.status(500).json({ error: 'Erro ao comunicar com a nuvem de armazenamento.' });
    }
});

// 🛡️ CONFIGURAÇÃO DE UPLOAD DE ALTA CAPACIDADE (SSD) - BLINDADO CONTRA EXPLOSÃO DE RAM
const fs = require('fs');
const os = require('os');


// ============================================================================
// 🚀 TÚNEL DE CONEXÃO EM TEMPO REAL E VIA VERDE (PODE MANTER OS SEUS COMO ESTÃO)
// ============================================================================
router.get('/stream', verificarToken, (req, res) => { 
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); 

    const escolaId = req.query.escolaId;

    const enviarEvento = (data) => {
        if (data.escolaId === escolaId || data.escolaId === 'DEFAULT') {
            res.write(`data: ${JSON.stringify(data)}\n\n`);
        }
    };

    workspaceStream.on('evento_realtime', enviarEvento);
    req.on('close', () => workspaceStream.off('evento_realtime', enviarEvento));
});

router.post('/upload/solicitar-link', verificarToken, async (req, res) => {
    try {
        const { nomeFicheiro, tipoFicheiro } = req.body;
        if (!nomeFicheiro || !tipoFicheiro) return res.status(400).json({ error: 'Faltam dados do ficheiro.' });

        const nomeSeguro = String(nomeFicheiro).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const nomeFinal = `doc_${Date.now()}_${nomeSeguro}`;
        const { gerarLinkUploadDireto } = require('../config/cloudflareR2');
        const dadosAutorizacao = await gerarLinkUploadDireto(nomeFinal, tipoFicheiro);

        res.status(200).json({ success: true, ...dadosAutorizacao });
    } catch (erro) {
        res.status(500).json({ error: 'Erro ao comunicar com a nuvem de armazenamento.' });
    }
});

// ============================================================================
// 1. UPLOAD BLINDADO COM SINALEIRO INTELIGENTE (CLOUDINARY ↔ CLOUDFLARE R2)
// ============================================================================
router.post('/upload', verificarToken, (req, res) => {
    try {
        const uploadProcess = upload.array('anexos', 10);
        
        uploadProcess(req, res, async (err) => {
            if (res.headersSent) return; 

            if (err) {
                if (err.message === 'Request aborted' || err.code === 'ECONNRESET') {
                    return res.status(400).json({ error: 'A ligação do aluno foi interrompida.' }); 
                }
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'O ficheiro excede o limite gigante de 800MB.' });
                }
                return res.status(500).json({ error: 'Falha ao processar o ficheiro no servidor.' });
            }

            if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Nenhum ficheiro recebido.' });

            try {
                // 🚀 O SINALEIRO INTELIGENTE COM STREAM DO DISCO
                const promessasUpload = req.files.map(file => {
                    return new Promise(async (resolve, reject) => { 
                        try {
                            let nomeOriginal = file.originalname || `ficheiro_${Date.now()}.jpg`;
                            let nomeSeguro = String(nomeOriginal).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
                            
                            // 🚀 O DICIONÁRIO ATUALIZADO: Agora ele reconhece .pps e .ppsx e manda-os para o lugar certo!
                            const ehDocumento = nomeSeguro.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|pps|ppsx|txt|zip|rar|csv)$/i);
                            
                            if (ehDocumento) {
                                // 🟢 ROTA 1: CLOUDFLARE R2 (Bomba o ficheiro do disco para a nuvem via Stream)
                                try {
                                    console.log(`🚀 Enviando DOCUMENTO para Cloudflare R2: ${nomeSeguro}`);
                                    const fileStream = fs.createReadStream(file.path);
                                    const urlR2 = await enviarParaR2(fileStream, nomeOriginal, file.mimetype);
                                    resolve({ url: urlR2, nome: file.originalname, tipo: file.mimetype });
                                } finally {
                                    // 🧹 Limpa o disco rígido após o envio (Sucesso ou Falha)
                                    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                                }
                           } else {
                                // 🔵 ROTA 2: CLOUDINARY
                                console.log(`📸 Enviando MULTIMÉDIA para Cloudinary: ${nomeSeguro}`);
                                
                                // 🚀 FIX: Força o Cloudinary a processar vídeos corretamente para que não rodem apenas como áudio
                                let recursoTipo = 'auto'; 
                                if (file.mimetype.startsWith('video/') || file.mimetype.startsWith('audio/')) {
                                    recursoTipo = 'video';
                                } else if (file.mimetype.startsWith('image/')) {
                                    recursoTipo = 'image';
                                }
                                
                                let publicId = `${Date.now()}_${nomeSeguro.split('.')[0]}`;

                                // O Cloudinary consegue ler o ficheiro diretamente do disco!
                                cloudinary.uploader.upload(file.path, { folder: 'workspace_escola', resource_type: recursoTipo, public_id: publicId }, (error, result) => {
                                    if (fs.existsSync(file.path)) fs.unlinkSync(file.path); // 🧹 Faxina do disco
                                    
                                    if (error) reject(error);
                                    else resolve({ url: result.secure_url, nome: file.originalname, tipo: file.mimetype });
                                });
                            }
                        } catch (errUpload) {
                            if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                            reject(errUpload);
                        }
                    });
                });

                const urls = await Promise.all(promessasUpload);
                if (!res.headersSent) res.status(200).json({ success: true, anexos: urls });
                
            } catch (processError) {
                console.error('🚨 Erro no envio para as nuvens:', processError);
                if (!res.headersSent) res.status(500).json({ error: 'Erro ao transferir ficheiro para a nuvem.' });
            }
        });
        
    } catch (erroGlobal) {
        console.error('🚨 Erro inesperado na rota de upload:', erroGlobal);
        if (!res.headersSent) res.status(500).json({ error: 'Ocorreu um erro interno.' });
    }
});

// ============================================================================
// 🖼️ IDENTIDADE VISUAL DO GRUPO (FOTO E NOME DA TURMA)
// ============================================================================
router.get('/chat/info/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const turma = await database.collection('turmas').findOne({ id: req.params.turmaId });
        if (!turma) return res.status(404).json({ error: 'Grupo não encontrado.' });
        res.status(200).json({ nome: turma.nome, foto: turma.foto });
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar informações do grupo.' }); }
});

router.put('/chat/info/:turmaId', verificarToken, async (req, res) => {
    try {
        const { nome, foto } = req.body;
        const database = await connectDB();
        
        await database.collection('turmas').updateOne(
            { id: req.params.turmaId },
            { $set: { nome: nome, foto: foto } }
        );

        workspaceStream.emit('evento_realtime', {
            type: 'SALA_UPDATE',
            turmaId: req.params.turmaId,
            escolaId: 'DEFAULT'
        });

        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar grupo.' }); }
});

// ============================================================================
// 🩺 ROTA DE DIAGNÓSTICO: TESTAR CONEXÃO COM CLOUDINARY
// ============================================================================
router.get('/testar-cloudinary', async (req, res) => {
    try {
        // Tenta fazer um "ping" simples ao servidor do Cloudinary
        const resultado = await cloudinary.api.ping();
        
        // Se a resposta for positiva, as credenciais estão perfeitas!
        res.status(200).json({
            success: true,
            mensagem: "✅ Conexão com o Cloudinary estabelecida com sucesso!",
            detalhes: resultado
        });
    } catch (error) {
        // Se der erro, as chaves no Render estão incorretas ou com espaços invisíveis.
        console.error("🚨 Erro no Ping do Cloudinary:", error);
        res.status(500).json({
            success: false,
            mensagem: "❌ Falha de comunicação com o Cloudinary. Verifique as chaves no Render.",
            erro: error.message || error
        });
    }
});

// ============================================================================
// 💬 CHAT DO FÓRUM (COM TEMPO REAL E INDICADOR DE DIGITAÇÃO)
// ============================================================================

// 1. ROTA GET (Foi a que apagou sem querer - Serve para ler o histórico)
router.get('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mensagens = await database.collection('workspace_chats').find({ turmaId: req.params.turmaId }).sort({ data: 1 }).toArray();
        res.status(200).json(mensagens);
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar o chat.' }); }
});

// 2. ROTA POST (Atualizada para guardar PDFs, Nomes e Imagens do Cloudinary)
router.post('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        // 🚀 O Servidor lê todos os dados, incluindo os anexos e nomes
        const { texto, autorNome, anexoUrl, anexoTipo, anexoNome } = req.body;
        const database = await connectDB();
        
        const novaMensagem = { 
            id: crypto.randomUUID(), 
            turmaId: req.params.turmaId, 
            autorNome: autorNome || 'Desconhecido', 
            texto: texto || '', 
            anexoUrl: anexoUrl || null,
            anexoTipo: anexoTipo || null,
            anexoNome: anexoNome || null,
            data: new Date().toISOString() 
        };
        
        await database.collection('workspace_chats').insertOne(novaMensagem);
        
        workspaceStream.emit('evento_realtime', { 
            type: 'NOVA_MENSAGEM', 
            turmaId: req.params.turmaId,
            mensagem: novaMensagem,
            escolaId: 'DEFAULT'
        });

        res.status(201).json({ success: true, mensagem: novaMensagem });
    } catch (error) { 
        console.error("Erro ao processar mensagem do chat:", error);
        res.status(500).json({ error: 'Erro ao enviar mensagem.' }); 
    }
});

// 3. ROTA DE DIGITAÇÃO
router.post('/chat/:turmaId/digitando', verificarToken, (req, res) => {
    const { autorNome, isTyping } = req.body;
    workspaceStream.emit('evento_realtime', {
        type: 'DIGITANDO', turmaId: req.params.turmaId, autorNome: autorNome, isTyping: isTyping, escolaId: 'DEFAULT'
    });
    res.status(200).json({ success: true });
});

// ============================================================================
// 📝 FEED, REAÇÕES E COMENTÁRIOS
// ============================================================================
router.post('/posts', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, autorTipo, escolaId, anexos, destino, destinoNome } = req.body;
        if (!texto && (!anexos || anexos.length === 0)) return res.status(400).json({ error: 'Vazio.' });

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(), escolaId: escolaId || 'DEFAULT', autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor', destino: destino || 'global', destinoNome: destinoNome || 'Público Geral',
            texto: texto, anexos: anexos || [], dataCriacao: new Date().toISOString(), comentarios: [], likes: [], dislikes: []
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        workspaceStream.emit('evento_realtime', { type: 'NOVO_POST', escolaId: novoPost.escolaId });

        res.status(201).json({ success: true, post: novoPost });
    } catch (error) { res.status(500).json({ error: 'Erro ao publicar.' }); }
});

router.get('/posts', verificarToken, async (req, res) => {
    try {
        const alunoRefId = req.query.alunoRefId;
        const database = await connectDB();
        let filtro = {}; 

        if (alunoRefId && alunoRefId !== 'undefined') {
            const aluno = await database.collection('alunos').findOne({ id: alunoRefId });
            if (aluno) {
                let minhasTurmas = Array.isArray(aluno.turmas) ? aluno.turmas : [aluno.turmas || aluno.turma];
                filtro = { $or: [{ destino: 'global' }, { destino: { $in: minhasTurmas } }, { destinoNome: { $in: minhasTurmas } }] };
            }
        }
        const posts = await database.collection('workspace_posts').find(filtro).sort({ dataCriacao: -1 }).limit(50).toArray();
        res.status(200).json(posts);
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar.' }); }
});

router.get('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const post = await database.collection('workspace_posts').findOne({ id: req.params.id });
        if (!post) return res.status(404).json({ error: 'Não encontrado.' });
        res.status(200).json(post);
    } catch (error) { res.status(500).json({ error: 'Erro ao sincronizar.' }); }
});

router.post('/posts/:id/comentarios', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto, autorNome } = req.body;
        const database = await connectDB();
        const novoComentario = { id: crypto.randomUUID(), autorNome: autorNome, texto: texto, dataCriacao: new Date().toISOString() };

        const postOriginal = await database.collection('workspace_posts').findOne({ id: postId });
        const result = await database.collection('workspace_posts').updateOne({ id: postId }, { $push: { comentarios: novoComentario } });

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Não encontrado.' });

        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: postId, escolaId: postOriginal.escolaId });

        if (postOriginal) {
            const usuariosNotificar = new Set();
            if (postOriginal.autorNome !== autorNome) usuariosNotificar.add(postOriginal.autorNome);
            if (postOriginal.comentarios) postOriginal.comentarios.forEach(c => { if (c.autorNome !== autorNome) usuariosNotificar.add(c.autorNome); });
            
            const notificacoesArray = Array.from(usuariosNotificar).map(destinatario => ({
                id: crypto.randomUUID(), escolaId: postOriginal.escolaId, destinatarioNome: destinatario, remetenteNome: autorNome,
                mensagem: `comentou: "${texto.substring(0, 30)}..."`, 
                origem: 'comentario_novo', 
                origemId: `${postId}|${novoComentario.id}`, // 🚀 O SALTO MÁGICO: Guardamos o ID do Post e do Comentário!
                lida: false, data: new Date().toISOString()
            }));

            if (notificacoesArray.length > 0) {
                await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
                workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: Array.from(usuariosNotificar), escolaId: postOriginal.escolaId });
            }
        }
        res.status(201).json({ success: true, comentario: novoComentario });
    } catch (error) { res.status(500).json({ error: 'Erro ao comentar.' }); }
});

router.put('/posts/:id/reagir', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { userId, tipo, autorNome } = req.body; 
        if (!userId) return res.status(400).json({ error: 'Obrigatório.' });

        const database = await connectDB();
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        if (!post) return res.status(404).json({ error: 'Não encontrada.' });

        let likes = Array.isArray(post.likes) ? post.likes : [];
        let dislikes = Array.isArray(post.dislikes) ? post.dislikes : [];

        likes = likes.filter(id => id !== userId);
        dislikes = dislikes.filter(id => id !== userId);

        if (tipo === 'like') likes.push(userId);
        if (tipo === 'dislike') dislikes.push(userId);

        await database.collection('workspace_posts').updateOne({ id: postId }, { $set: { likes: likes, dislikes: dislikes } });
        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: postId, escolaId: post.escolaId });

        // 🚀 NÃO NOTIFICA SE FOR "REMOVE" (Desfazer a curtida)
        if (autorNome && post.autorNome !== autorNome && tipo !== 'remove') { 
            const acaoRealizada = tipo === 'like' ? 'curtiu' : 'não curtiu';
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(), escolaId: post.escolaId, destinatarioNome: post.autorNome, remetenteNome: autorNome,
                mensagem: `${acaoRealizada} a sua publicação.`, 
                origem: 'post', 
                origemId: postId, 
                lida: false, data: new Date().toISOString()
            });
            workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: [post.autorNome], escolaId: post.escolaId });
        }
        res.status(200).json({ success: true, likes, dislikes });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// 🚀 NOVA ROTA: REAÇÃO EM COMENTÁRIOS
router.put('/posts/:postId/comentarios/:comentarioId/reagir', verificarToken, async (req, res) => {
    try {
        const { postId, comentarioId } = req.params;
        const { userId, tipo, autorNome } = req.body; 
        if (!userId) return res.status(400).json({ error: 'Obrigatório.' });

        const database = await connectDB();
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        if (!post || !post.comentarios) return res.status(404).json({ error: 'Post não encontrado.' });

        const commentIndex = post.comentarios.findIndex(c => c.id === comentarioId);
        if (commentIndex === -1) return res.status(404).json({ error: 'Comentário não encontrado.' });

        const comentario = post.comentarios[commentIndex];
        let likes = Array.isArray(comentario.likes) ? comentario.likes : [];
        let dislikes = Array.isArray(comentario.dislikes) ? comentario.dislikes : [];

        likes = likes.filter(id => id !== userId);
        dislikes = dislikes.filter(id => id !== userId);

        if (tipo === 'like') likes.push(userId);
        if (tipo === 'dislike') dislikes.push(userId);

        // Atualiza apenas o comentário específico dentro do Array
        await database.collection('workspace_posts').updateOne(
            { id: postId, "comentarios.id": comentarioId },
            { $set: { "comentarios.$.likes": likes, "comentarios.$.dislikes": dislikes } }
        );
        
        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: postId, escolaId: post.escolaId });

        // Notifica o dono do comentário!
        if (autorNome && comentario.autorNome !== autorNome && tipo !== 'remove') { 
            const acaoRealizada = tipo === 'like' ? 'curtiu' : 'não curtiu';
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(), escolaId: post.escolaId, destinatarioNome: comentario.autorNome, remetenteNome: autorNome,
                mensagem: `${acaoRealizada} o seu comentário.`, 
                origem: 'comentario_reacao', 
                origemId: `${postId}|${comentarioId}`, // Salto duplo!
                lida: false, data: new Date().toISOString()
            });
            workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: [comentario.autorNome], escolaId: post.escolaId });
        }
        res.status(200).json({ success: true, likes, dislikes });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.delete('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        // 1. Apaga fisicamente da Base de Dados
        await database.collection('workspace_posts').deleteOne({ id: req.params.id });
        
        // 2. 🚀 O GRITO GLOBAL (SSE): Avisa todos os aparelhos online instantaneamente!
        workspaceStream.emit('evento_realtime', { 
            type: 'POST_APAGADO', 
            postId: req.params.id, 
            escolaId: 'DEFAULT' 
        });

        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_posts').updateOne({ id: req.params.id }, { $set: { texto: req.body.texto } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.delete('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_posts').updateOne({ id: req.params.postId }, { $pull: { comentarios: { id: req.params.comentarioId } } });
        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: req.params.postId, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_posts').updateOne({ id: req.params.postId, "comentarios.id": req.params.comentarioId }, { $set: { "comentarios.$.texto": req.body.texto } });
        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: req.params.postId, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// ============================================================================
// ⚙️ OUTRAS ROTAS GERAIS
// ============================================================================
router.get('/notificacoes/:nomeDono', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = await database.collection('workspace_notificacoes').find({ destinatarioNome: req.params.nomeDono, lida: false }).sort({ data: -1 }).toArray();
        res.status(200).json(notificacoes);
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/notificacoes/:id/ler', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_notificacoes').updateOne({ id: req.params.id }, { $set: { lida: true } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// ============================================================================
// 🧹 LIMPAR TODAS AS NOTIFICAÇÕES DE UMA VEZ
// ============================================================================
router.put('/notificacoes/usuario/:nomeDono/ler-todas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        // Procura todas as notificações do utilizador que ainda não foram lidas
        // e atualiza todas de uma vez para lida: true
        await database.collection('workspace_notificacoes').updateMany(
            { destinatarioNome: req.params.nomeDono, lida: false },
            { $set: { lida: true } }
        );
        
        res.status(200).json({ success: true });
    } catch (error) { 
        console.error("🚨 Erro ao limpar todas as notificações:", error);
        res.status(500).json({ error: 'Erro ao limpar notificações.' }); 
    }
});

// ============================================================================
// ⚙️ ROTA DE ALTERAÇÃO DE SENHA (PERFIL) - COM CRIPTOGRAFIA
// ============================================================================
router.put('/perfil', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, senhaAtual, novaSenha } = req.body;
        const database = await connectDB();
        
        const senhaLimpa = String(senhaAtual).trim();
        const novaSenhaLimpa = String(novaSenha).trim();

        // 1. Encontra a ficha do aluno na gaveta de acessos
        const user = await database.collection('usuarios').findOne({ id: id });

        if (!user) {
            return res.status(404).json({ error: 'Conta de acesso não encontrada.' });
        }

        // 2. 🚀 O DESCODIFICADOR: Importamos a biblioteca de segurança (tentando as duas versões mais comuns no Node.js)
        let bcrypt;
        try { bcrypt = require('bcrypt'); } catch(e) { try { bcrypt = require('bcryptjs'); } catch(e) { bcrypt = null; } }

        let senhaCorreta = false;
        let novaSenhaParaGuardar = novaSenhaLimpa; // Por defeito é texto normal

        // 3. A VERIFICAÇÃO INTELIGENTE (Criptografada vs Texto Normal)
        // Se o sistema usa bcrypt, a senha na Base de Dados começa sempre por "$2"
        if (bcrypt && user.senha && String(user.senha).startsWith('$2')) {
            // A senha está criptografada! Usamos o motor para comparar
            senhaCorreta = await bcrypt.compare(senhaLimpa, user.senha);
            
            // Se estiver correta, CRIPTOGRAFAMOS a senha nova antes de guardar para não quebrar o login
            if (senhaCorreta) {
                novaSenhaParaGuardar = await bcrypt.hash(novaSenhaLimpa, 10);
            }
        } else {
            // Plano B: Se a senha estiver em texto normal (sistemas mais antigos)
            const senhasValidas = [
                String(user.senha).trim(),
                String(user.senha_provisoria).trim(),
                String(user.senhaProvisoria).trim()
            ];
            senhaCorreta = senhasValidas.includes(senhaLimpa) || senhasValidas.includes(String(Number(senhaLimpa)));
        }

        if (!senhaCorreta) {
            return res.status(400).json({ error: 'A senha atual está incorreta. Verifique e tente novamente.' });
        }

        // 4. ATUALIZAÇÃO DA SENHA SEGURA E LIMPEZA
        const updateDoc = {
            $set: { senha: novaSenhaParaGuardar },
            $unset: { senha_provisoria: "", senhaProvisoria: "" } 
        };

        // Guarda a senha secreta (Hash) na coleção principal
        await database.collection('usuarios').updateOne({ id: id }, updateDoc);

        // Espelha para a coleção de alunos (para coerência de dados)
        if (alunoRefId) {
            await database.collection('alunos').updateOne({ id: alunoRefId }, updateDoc);
        }

        res.status(200).json({ success: true });
        
    } catch (error) { 
        console.error("🚨 Erro ao atualizar senha:", error);
        res.status(500).json({ error: 'Erro interno ao tentar atualizar a senha.' }); 
    }
});

// ============================================================================
// 📸 ROTA DE ALTERAÇÃO DE FOTO (PERFIL) - INDEPENDENTE DA SECRETARIA
// ============================================================================
router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        // 🚀 Removemos o alunoRefId. O WorkSpace já não mexe nos dados oficiais!
        const { id, avatarUrl } = req.body; 
        const database = await connectDB();
        
        // Atualiza APENAS a identidade de acesso do WorkSpace (coleção usuarios)
        await database.collection('usuarios').updateOne(
            { id: id }, 
            { $set: { avatar: avatarUrl } }
        );
        
        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao guardar a foto de perfil.' }); 
    }
});

// ============================================================================
// ⚙️ ROTA DE ALTERAÇÃO DE NOME (PERFIL) - EFEITO CASCATA ABSOLUTO
// ============================================================================
router.put('/perfil/nome', verificarToken, async (req, res) => {
    try {
        const { id, novoNome } = req.body;
        
        if (!novoNome || novoNome.trim() === '') {
            return res.status(400).json({ error: 'O nome não pode estar vazio.' });
        }

        const nomeLimpo = String(novoNome).trim();
        const database = await connectDB();

        // 1. Descobre quem é o utilizador
        const user = await database.collection('usuarios').findOne({ id: id });
        if (!user) return res.status(404).json({ error: 'Conta de acesso não encontrada.' });
        
        // 2. Coleta TODOS os nomes possíveis (Oficial da Secretaria + Antigos do WorkSpace)
        let nomesParaAtualizar = [user.nome, user.login].filter(Boolean);
        
        if (user.alunoRefId) {
            const alunoOficial = await database.collection('alunos').findOne({ id: user.alunoRefId });
            if (alunoOficial && alunoOficial.nome) {
                nomesParaAtualizar.push(alunoOficial.nome);
            }
        }
        
        if (user.tipo === 'Gestor' || user.login === 'gestor' || nomesParaAtualizar.includes('Gestor Principal')) {
            nomesParaAtualizar.push('Gestor Principal');
        }

        // Remove nomes duplicados
        nomesParaAtualizar = [...new Set(nomesParaAtualizar)];

        // 3. Atualiza a Identidade INDEPENDENTE do WorkSpace
        await database.collection('usuarios').updateOne({ id: id }, { $set: { nome: nomeLimpo } });

        // ====================================================================
        // 4. 🚀 O EFEITO CASCATA ABSOLUTO (Varre todas as veias do WorkSpace)
        // ====================================================================
        const filtroBusca = { autorNome: { $in: nomesParaAtualizar } };

        // A) Publicações e Chats
        await database.collection('workspace_posts').updateMany(filtroBusca, { $set: { autorNome: nomeLimpo } });
        await database.collection('workspace_chats').updateMany(filtroBusca, { $set: { autorNome: nomeLimpo } });

        // B) Comentários dos posts
        const postsComComentarios = await database.collection('workspace_posts').find({ "comentarios.autorNome": { $in: nomesParaAtualizar } }).toArray();
        for (let post of postsComComentarios) {
            const novosComentarios = post.comentarios.map(c => {
                if (nomesParaAtualizar.includes(c.autorNome)) c.autorNome = nomeLimpo;
                return c;
            });
            await database.collection('workspace_posts').updateOne({ id: post.id }, { $set: { comentarios: novosComentarios } });
        }

        // C) 🚀 CORREÇÃO CRÍTICA: Atualiza os Exercícios e Provas baseando-se no ID do Aluno!
        const idsDoAluno = [String(id)];
        if (user.alunoRefId) idsDoAluno.push(String(user.alunoRefId));

        await database.collection('workspace_entregas').updateMany(
            { alunoId: { $in: idsDoAluno } },
            { $set: { alunoNome: nomeLimpo } }
        );
        await database.collection('workspace_entregas_provas').updateMany(
            { alunoId: { $in: idsDoAluno } },
            { $set: { alunoNome: nomeLimpo } }
        );

        // D) Histórico de Notificações
        await database.collection('workspace_notificacoes').updateMany(
            { remetenteNome: { $in: nomesParaAtualizar } },
            { $set: { remetenteNome: nomeLimpo } }
        );
        await database.collection('workspace_notificacoes').updateMany(
            { destinatarioNome: { $in: nomesParaAtualizar } },
            { $set: { destinatarioNome: nomeLimpo } }
        );

        // E) Feedbacks do Professor (Se um professor mudar de nome, atualiza os balões de feedback dele)
        if (user.tipo !== 'Aluno') {
            const entregasComFeedbacks = await database.collection('workspace_entregas').find({ "feedbacks.autorNome": { $in: nomesParaAtualizar } }).toArray();
            for (let ent of entregasComFeedbacks) {
                const novosFeedbacks = ent.feedbacks.map(f => {
                    if (nomesParaAtualizar.includes(f.autorNome)) f.autorNome = nomeLimpo;
                    return f;
                });
                await database.collection('workspace_entregas').updateOne({ id: ent.id }, { $set: { feedbacks: novosFeedbacks } });
            }
        }

        res.status(200).json({ success: true, nome: nomeLimpo, nomeAntigo: nomesParaAtualizar[0] });
    } catch (error) {
        console.error("🚨 Erro ao atualizar o nome do perfil e cascata:", error);
        res.status(500).json({ error: 'Erro interno ao tentar atualizar o nome.' });
    }
});

// ============================================================================
// 💬 GESTÃO DE FEEDBACKS DO PROFESSOR (EDITAR E APAGAR)
// ============================================================================

router.put('/entregas/:entregaId/feedback/:feedbackId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const { texto } = req.body;
        
        await database.collection('workspace_entregas').updateOne(
            { id: req.params.entregaId, "feedbacks.id": req.params.feedbackId },
            { $set: { "feedbacks.$.texto": texto } }
        );

        // Dispara um recarregamento silencioso nas telas (SSE)
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'NOVO_FEEDBACK', entregaId: req.params.entregaId, escolaId: 'DEFAULT' });
        }
        res.status(200).json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro ao editar feedback.' }); }
});

router.delete('/entregas/:entregaId/feedback/:feedbackId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        await database.collection('workspace_entregas').updateOne(
            { id: req.params.entregaId },
            { $pull: { feedbacks: { id: req.params.feedbackId } } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'NOVO_FEEDBACK', entregaId: req.params.entregaId, escolaId: 'DEFAULT' });
        }
        res.status(200).json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro ao apagar feedback.' }); }
});

// 🚀 Guardar a Entrega de Exercício/Avaliação e AVISAR O PROFESSOR
router.post('/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novaEntrega = { ...req.body, id: crypto.randomUUID(), dataEntrega: new Date().toISOString() };
        
        // Passo A: A gaveta recebe o trabalho do aluno
        await database.collection('workspace_entregas').insertOne(novaEntrega);

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES (ALUNO -> PROFESSOR/GESTOR)
        // ====================================================================
        try {
            const escolaId = novaEntrega.escolaId || 'DEFAULT';
            const nomeAluno = novaEntrega.alunoNome || 'Um aluno';
            const tituloTarefa = novaEntrega.eventoTitulo || 'uma tarefa';
            const turmaNome = novaEntrega.turmaNome || 'a sua turma';

            // 1. Localiza a Equipa Pedagógica (Professores e Gestores da Escola)
            const professoresEGestores = await database.collection('usuarios').find({ 
                escolaId: escolaId,
                tipo: { $in: ['Professor', 'Gestor'] }
            }).toArray();

            // 2. Fabrica os bilhetes de alerta para eles
            if (professoresEGestores.length > 0) {
                const nomesDestinatarios = [];
                const notificacoesArray = professoresEGestores.map(prof => {
                    const nomeProf = prof.nome || prof.login;
                    if (nomeProf) nomesDestinatarios.push(nomeProf);
                    
                    return {
                        id: crypto.randomUUID(),
                        escolaId: escolaId,
                        destinatarioNome: nomeProf,
                        remetenteNome: nomeAluno,
                        mensagem: `da turma de <strong>${turmaNome}</strong>, enviou o exercício intitulado <strong>"${tituloTarefa}"</strong> e já está disponível na área de exercícios. Confira 👀`,
                        origem: 'tarefa', // O clique no sino abrirá o modal de verificação!
                        origemId: novaEntrega.eventoId,
                        destinoNome: turmaNome,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                // 3. Guarda e emite o aviso em Tempo Real
                if (notificacoesArray.length > 0) {
                    await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    
                    workspaceStream.emit('evento_realtime', { 
                        type: 'NOVA_NOTIFICACAO', 
                        destinatarios: nomesDestinatarios, 
                        escolaId: escolaId 
                    });
                }
            }
        } catch (erroNoti) {
            console.error("Aviso: Falha ao notificar professores sobre a entrega.", erroNoti);
        }
        // ====================================================================

        res.status(201).json({ success: true, entrega: novaEntrega });
    } catch (error) { 
        console.error("Erro no envio da entrega:", error);
        res.status(500).json({ error: 'Erro interno.' }); 
    }
});

router.get('/entregas/verificar/:eventoId/:alunoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entrega = await database.collection('workspace_entregas').findOne({ eventoId: req.params.eventoId, alunoId: req.params.alunoId });
        res.status(200).json(entrega ? { entregue: true, detalhes: entrega } : { entregue: false });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.get('/entregas/tarefa/:eventoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entregas = await database.collection('workspace_entregas').find({ eventoId: req.params.eventoId }).sort({ dataEntrega: -1 }).toArray();
        res.status(200).json(entregas);
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// 🚀 OBTER DETALHES DE UMA ENTREGA (INCLUINDO FEEDBACKS)
router.get('/entregas/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const entrega = await db.collection('workspace_entregas').findOne({ id: req.params.id });
        if (!entrega) return res.status(404).json({ error: 'Entrega não encontrada' });
        res.status(200).json({ success: true, entrega });
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar entrega.' }); }
});

// 🚀 PROFESSOR ENVIA FEEDBACK AO ALUNO (E TOCA O SINO DELE)
router.post('/entregas/:id/feedback', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { texto, professorNome } = req.body;
        const entregaId = req.params.id;

        const entrega = await db.collection('workspace_entregas').findOne({ id: entregaId });
        if (!entrega) return res.status(404).json({ error: 'Entrega não encontrada.' });

        const novoFeedback = {
            id: crypto.randomUUID(),
            autorNome: professorNome || 'Professor',
            texto: texto,
            data: new Date().toISOString()
        };

        // Guarda o comentário na gaveta do trabalho
        await db.collection('workspace_entregas').updateOne(
            { id: entregaId },
            { $push: { feedbacks: novoFeedback } }
        );

        // ====================================================================
        // 🚀 O GATILHO: Avisar o Aluno!
        // ====================================================================
        const escolaId = entrega.escolaId || 'DEFAULT';
        const eventoId = entrega.eventoId;
        const nomeAluno = entrega.alunoNome;

        const notificacao = {
            id: 'notif_fb_' + Date.now(),
            escolaId: escolaId,
            destinatarioNome: nomeAluno,
            remetenteNome: professorNome,
            mensagem: `avaliou e enviou um feedback no seu exercício: "${entrega.eventoTitulo}"`,
            origem: 'feedback_tarefa', // 🚀 A Palavra Mágica para o Teletransporte!
            origemId: `${eventoId}|${entrega.id}`, // Guardamos os 2 IDs juntos
            destinoNome: 'Área de Exercícios',
            lida: false,
            data: new Date().toISOString()
        };

        await db.collection('workspace_notificacoes').insertOne(notificacao);

        if (global.workspaceStream) {
            // Toca o sininho do aluno
            global.workspaceStream.emit('evento_realtime', {
                type: 'NOVA_NOTIFICACAO',
                destinatarios: [nomeAluno],
                escolaId: escolaId
            });
            // 🚀 Atualiza a janela de Feedback ao vivo (se ele já estiver lá dentro)
            global.workspaceStream.emit('evento_realtime', {
                type: 'NOVO_FEEDBACK',
                entregaId: entregaId,
                feedback: novoFeedback,
                escolaId: escolaId
            });
        }

        res.status(201).json({ success: true, feedback: novoFeedback });
    } catch (error) {
        console.error("Erro ao enviar feedback:", error);
        res.status(500).json({ error: 'Erro interno.' });
    }
});

router.get('/avatars', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mapaAvatars = {};
        const alunos = await database.collection('alunos').find({ avatar: { $exists: true, $ne: null } }).toArray();
        const usuarios = await database.collection('usuarios').find({ avatar: { $exists: true, $ne: null } }).toArray();
        alunos.forEach(a => { if(a.nome) mapaAvatars[a.nome] = a.avatar; });
        usuarios.forEach(u => { const nome = u.nome || u.login; if(nome) mapaAvatars[nome] = u.avatar; });
        res.status(200).json(mapaAvatars);
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// ============================================================================
// 📝 CRIAR NOVA TAREFA / EXERCÍCIO (E DISPARAR CARTÃO ANIMADO PARA ALUNOS)
// ============================================================================
router.post('/eventos', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        
        // Monta a estrutura da tarefa recebida do sidebar.js
        const novoEvento = {
            ...req.body,
            id: crypto.randomUUID(), // Gera o ID único
            dataCriacao: new Date().toISOString()
        };

        // 1. Guarda a Tarefa fisicamente na Base de Dados
        await db.collection('eventos').insertOne(novoEvento);

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES (PROFESSOR -> ALUNOS) PARA EXERCÍCIOS
        // ====================================================================
        try {
            // Recolhe os dados do payload enviado pelo sidebar.js
            const escola = req.body.escolaId || 'DEFAULT'; 
            const tituloTarefa = req.body.titulo || 'Novo Exercício';
            const autorDaTarefa = req.body.autorNome || 'Professor';
            const destinoTarefa = req.body.turma || 'global';
            const destinoNomeTarefa = req.body.turmaNome || 'Geral';

            // Busca os alunos da base de dados
            const alunos = await db.collection('alunos').find({ escolaId: escola }).toArray();
            
            // Filtra quem tem o direito de receber o exercício
            let alunosAlvo = [];
            if (destinoTarefa === 'global') {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(destinoTarefa).toLowerCase() || String(t).toLowerCase() === String(destinoNomeTarefa).toLowerCase());
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    
                    return {
                        id: 'notif_' + Date.now() + Math.random().toString(36).substring(7),
                        escolaId: escola,
                        destinatarioNome: nomeAluno,
                        remetenteNome: autorDaTarefa,
                        mensagem: `agendou um novo exercício: "${tituloTarefa}"`,
                        origem: 'tarefa', // 🚀 Gatilho Mágico: Esta palavra ativa o cartão azul e a animação do sininho!
                        origemId: novoEvento.id, 
                        destinoNome: destinoNomeTarefa,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                // Guarda no cofre e dá o Grito de Tempo Real para o ecrã dos alunos!
                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    
                    if (global.workspaceStream) {
                        global.workspaceStream.emit('evento_realtime', { 
                            type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escola 
                        });
                    }
                }
            }
        } catch (erroNotificacao) {
            console.error("Aviso: Falha ao gerar notificações da tarefa.", erroNotificacao);
        }
        // ====================================================================

        res.status(201).json({ success: true, evento: novoEvento });
    } catch (error) {
        console.error("Erro ao criar evento/tarefa:", error);
        res.status(500).json({ error: 'Erro ao registar a atividade no servidor.' });
    }
});

router.put('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const eventoId = req.params.id;
        
        // 1. Vai buscar a tarefa antiga para saber quem foi o autor original e a escola
        const eventoOriginal = await database.collection('eventos').findOne({ id: eventoId });
        if (!eventoOriginal) return res.status(404).json({ error: 'Atividade não encontrada.' });

        // 2. Atualiza a atividade com os novos dados do professor
        const updateFields = {};
        if (req.body.titulo) updateFields.titulo = req.body.titulo;
        if (req.body.data) updateFields.data = req.body.data;
        if (req.body.turma) updateFields.turma = req.body.turma;
        if (req.body.turmaNome) updateFields.turmaNome = req.body.turmaNome;
        if (req.body.descricao !== undefined) updateFields.descricao = req.body.descricao;
        if (req.body.anexoUrl !== undefined) updateFields.anexoUrl = req.body.anexoUrl;

        await database.collection('eventos').updateOne({ id: eventoId }, { $set: updateFields });

        // ====================================================================
        // 🚀 O MOTOR DE ANULAÇÃO JUSTA E NOTIFICAÇÕES SEPARADAS
        // ====================================================================
        try {
            // A) Descobre quem já tinha entregado o trabalho
            const entregasAnteriores = await database.collection('workspace_entregas').find({ eventoId: eventoId }).toArray();
            const alunosQueEntregaramIds = entregasAnteriores.map(e => String(e.alunoId));
            const alunosQueEntregaramNomes = entregasAnteriores.map(e => e.alunoNome);

            // B) Apaga (anula) as entregas existentes na Base de Dados
            if (entregasAnteriores.length > 0) {
                await database.collection('workspace_entregas').deleteMany({ eventoId: eventoId });
            }

            // C) Vai buscar os alunos da turma para enviar os alertas adequados
            const escolaId = eventoOriginal.escolaId || 'DEFAULT';
            const autorDaTarefa = eventoOriginal.autorNome || 'Professor';
            const tituloNovo = req.body.titulo || eventoOriginal.titulo || 'Exercício Atualizado';
            const turmaAlvo = req.body.turma || eventoOriginal.turma || 'global';
            
            const todosAlunos = await database.collection('alunos').find({ escolaId: escolaId }).toArray();
            
            // Filtra só os alunos a quem o exercício se destina
            const alunosDaTurma = todosAlunos.filter(a => {
                if (turmaAlvo === 'global') return true;
                const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                return minhasTurmas.some(t => String(t).toLowerCase() === String(turmaAlvo).toLowerCase() || String(t).toLowerCase() === String(req.body.turmaNome || eventoOriginal.turmaNome).toLowerCase());
            });

            const notificacoesArray = [];
            const destinatariosGeral = [];

            // D) Escreve os bilhetes personalizados para cada aluno
            alunosDaTurma.forEach(aluno => {
                const nomeAluno = aluno.nome || aluno.login;
                if (!nomeAluno) return;
                
                destinatariosGeral.push(nomeAluno);

                // Verifica se o aluno está na lista de quem foi prejudicado pela edição
                const jaTinhaEntregue = alunosQueEntregaramIds.includes(String(aluno.id)) || alunosQueEntregaramNomes.includes(nomeAluno);

                let mensagemAviso = '';
                if (jaTinhaEntregue) {
                    mensagemAviso = `fez modificações estruturais no exercício <strong>"${tituloNovo}"</strong>. <span style="color:#e74c3c;">A sua entrega anterior foi anulada. Por favor, leia as novas instruções e refaça a atividade.</span>`;
                } else {
                    mensagemAviso = `atualizou as instruções e regras do exercício <strong>"${tituloNovo}"</strong>. Confirme as novidades antes de enviar!`;
                }

                notificacoesArray.push({
                    id: 'notif_upd_' + Date.now() + Math.random().toString(36).substring(7),
                    escolaId: escolaId,
                    destinatarioNome: nomeAluno,
                    remetenteNome: autorDaTarefa,
                    mensagem: mensagemAviso,
                    origem: 'tarefa', // Abre o modal do exercício!
                    origemId: eventoId,
                    destinoNome: req.body.turmaNome || eventoOriginal.turmaNome || 'Geral',
                    lida: false,
                    data: new Date().toISOString()
                });
            });

            // E) Guarda os alertas e dá o Grito Global
            if (notificacoesArray.length > 0) {
                await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
                if (global.workspaceStream) {
                    global.workspaceStream.emit('evento_realtime', {
                        type: 'NOVA_NOTIFICACAO', destinatarios: destinatariosGeral, escolaId: escolaId
                    });
                }
            }

        } catch (erroLogica) {
            console.error("Aviso: A tarefa foi atualizada, mas houve um erro ao processar anulações.", erroLogica);
        }

        res.status(200).json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao processar edição da atividade.' }); 
    }
});

router.delete('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        // 1. Apaga a instrução do exercício principal
        await database.collection('eventos').deleteOne({ id: req.params.id });
        
        // 2. 🚀 CORREÇÃO: Apaga as entregas da gaveta correta do WorkSpace!
        await database.collection('workspace_entregas').deleteMany({ eventoId: req.params.id });
        
        res.status(200).json({ success: true });
    } catch (error) { 
        console.error("Erro ao apagar exercício:", error);
        res.status(500).json({ error: 'Erro ao apagar o exercício.' }); 
    }
});

// ============================================================================
// 🧹 ROTAS DE DESTRUIÇÃO E REATIVAÇÃO (DELETE)
// ============================================================================

// 1. Apagar Mensagens em Massa do Chat com SSE Global
router.delete('/chat/:turmaId/mensagens/massa', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const { ids } = req.body; // Recebemos o "cesto" cheio de IDs

        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ error: 'Nenhuma mensagem selecionada.' });
        }

        // 1. Destrói fisicamente todas as mensagens listadas de uma vez
        await database.collection('workspace_chats').deleteMany({ 
            id: { $in: ids },
            turmaId: req.params.turmaId
        });
        
        // 2. 🚀 O GRITO GLOBAL (SSE): Avisa todos para apagarem esta lista do ecrã
        workspaceStream.emit('evento_realtime', { 
            type: 'MSG_APAGADA_MASSA', 
            turmaId: req.params.turmaId, 
            mensagensIds: ids, // Passamos a lista toda pelo túnel
            escolaId: 'DEFAULT' 
        });

        res.status(200).json({ success: true, message: "Mensagens apagadas com sucesso!" });
    } catch (error) { 
        console.error("Erro ao apagar mensagens em massa:", error);
        res.status(500).json({ error: 'Erro interno.' }); 
    }
});

// 2. Apagar uma Mensagem Individual do Chat com SSE Global
router.delete('/chat/:turmaId/mensagem/:mensagemId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        // 1. Apaga fisicamente a mensagem da Base de Dados
        await database.collection('workspace_chats').deleteOne({ 
            id: req.params.mensagemId,
            turmaId: req.params.turmaId
        });
        
        // 2. 🚀 O GRITO GLOBAL (SSE): Avisa os telemóveis conectados para apagarem a msg do ecrã
        workspaceStream.emit('evento_realtime', { 
            type: 'MSG_APAGADA', 
            turmaId: req.params.turmaId, 
            mensagemId: req.params.mensagemId,
            escolaId: 'DEFAULT' 
        });

        res.status(200).json({ success: true, message: "Mensagem apagada com sucesso!" });
    } catch (error) { 
        console.error("Erro ao apagar mensagem individual do chat:", error);
        res.status(500).json({ error: 'Erro ao apagar a mensagem do chat.' }); 
    }
});

// 3. Limpar todo o Chat de uma turma
router.delete('/chat/:turmaId/limpar', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        
        // Comanda a base de dados para apagar todas as mensagens daquela turma
        await database.collection('workspace_chats').deleteMany({ turmaId: req.params.turmaId });
        
        // Avisa os telemóveis/computadores conectados para atualizarem o ecrã em tempo real
        workspaceStream.emit('evento_realtime', { 
            type: 'SALA_UPDATE', 
            turmaId: req.params.turmaId, 
            escolaId: 'DEFAULT' 
        });

        res.status(200).json({ success: true, message: "Chat limpo com sucesso!" });
    } catch (error) { 
        console.error("Erro ao limpar chat:", error);
        res.status(500).json({ error: 'Erro ao limpar o chat.' }); 
    }
});

// 4. Reativar Acesso de 1 Aluno na Sala Online (Apaga uma presença específica)
router.delete('/entregas/:entregaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteOne({ id: req.params.entregaId });
        res.status(200).json({ success: true, message: "Acesso reativado!" });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao reativar aluno.' }); 
    }
});

// 5. Reativar Sala para Todos os Alunos (Apaga todas as presenças daquela sala)
router.delete('/avaliacoes/:id/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteMany({ avaliacaoId: req.params.id });
        res.status(200).json({ success: true, message: "Sala reativada para todos!" });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao limpar presenças.' }); 
    }
});

// ============================================================================
// 🧰 BAÚ DAS MEMÓRIAS (NOTAS E ALARMES)
// ============================================================================

// 1. Buscar Todas as Notas do Aluno (Lista)
router.get('/bau/notas', verificarToken, async (req, res) => {
    try {
        const usuarioId = req.query.usuarioId;
        const database = await connectDB();
        const notas = await database.collection('workspace_bau_notas')
            .find({ usuarioId: usuarioId })
            .sort({ dataAtualizacao: -1 })
            .toArray();
        res.status(200).json({ dados: notas });
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar notas.' }); }
});

// 2. Criar Nova Nota
router.post('/bau/notas', verificarToken, async (req, res) => {
    try {
        const { usuarioId, titulo, texto } = req.body;
        const database = await connectDB();
        const novaNota = {
            id: crypto.randomUUID(), usuarioId, titulo: titulo || 'Nota sem título', 
            texto, dataCriacao: new Date().toISOString(), dataAtualizacao: new Date().toISOString()
        };
        await database.collection('workspace_bau_notas').insertOne(novaNota);
        res.status(201).json({ success: true, nota: novaNota });
    } catch (error) { res.status(500).json({ error: 'Erro ao criar nota.' }); }
});

// 2.1. Atualizar Nota Existente
router.put('/bau/notas/:id', verificarToken, async (req, res) => {
    try {
        const { titulo, texto } = req.body;
        const database = await connectDB();
        await database.collection('workspace_bau_notas').updateOne(
            { id: req.params.id },
            { $set: { titulo: titulo, texto: texto, dataAtualizacao: new Date().toISOString() } }
        );
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar nota.' }); }
});

// 2.2. Apagar Nota
router.delete('/bau/notas/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_notas').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar nota.' }); }
});

// 3. Buscar Alarmes/Lembretes Pendentes
router.get('/bau/alarmes', verificarToken, async (req, res) => {
    try {
        const usuarioId = req.query.usuarioId;
        const database = await connectDB();
        
        const alarmes = await database.collection('workspace_bau_alarmes')
            .find({ usuarioId: usuarioId })
            .sort({ tempoDisparo: 1 })
            .toArray();
            
        res.status(200).json({ dados: alarmes });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao carregar alarmes.' }); 
    }
});

// 4. Criar Novo Alarme/Lembrete
router.post('/bau/alarmes', verificarToken, async (req, res) => {
    try {
        const { usuarioId, mensagem, tempoDisparo } = req.body;
        const database = await connectDB();
        
        const novoAlarme = {
            id: crypto.randomUUID(),
            usuarioId,
            mensagem,
            tempoDisparo,
            criadoEm: new Date().toISOString()
        };
        
        await database.collection('workspace_bau_alarmes').insertOne(novoAlarme);
        res.status(201).json({ success: true, id: novoAlarme.id });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao criar alarme.' }); 
    }
});

// 4.1. Marcar Alarme como Disparado (Mantém no Calendário)
router.put('/bau/alarmes/:id/disparado', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_alarmes').updateOne(
            { id: req.params.id },
            { $set: { disparado: true } }
        );
        res.status(200).json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao atualizar alarme.' }); 
    }
});

// 5. Apagar Alarme (Após ele disparar na tela)
router.delete('/bau/alarmes/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_alarmes').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao apagar alarme.' }); 
    }
});

// ============================================================================
// 📚 MATERIAIS DAS AULAS (A ESTANTE DIGITAL)
// ============================================================================

// 1. Guardar metadados do Material e DISPARAR NOTIFICAÇÕES (Prof -> Alunos)
router.post('/materiais', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const novoMaterial = req.body;
        
        // Garante que o material tem um ID seguro antes de guardar
        if (!novoMaterial.id) novoMaterial.id = crypto.randomUUID();
        
        // Passo A: Guarda o documento físico na Biblioteca
        await db.collection('workspace_materiais').insertOne(novoMaterial);

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES: Encontrar os alunos e tocar o sininho!
        // ====================================================================
        try {
            const escolaId = novoMaterial.escolaId || 'DEFAULT';
            const destino = novoMaterial.destino || 'global';
            const autor = novoMaterial.autorNome || 'Professor';
            const tituloMat = novoMaterial.titulo || 'Novo Material';

            // 1. Vai buscar a lista de todos os alunos da escola
            const alunos = await db.collection('alunos').find({ escolaId: escolaId }).toArray();
            
           // 2. Filtra apenas os alunos que têm acesso a este material
            let alunosAlvo = [];
            if (destino === 'global' || (Array.isArray(destino) && destino.includes('global'))) {
                alunosAlvo = alunos; // Todos recebem
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    // 🚀 LEITURA MÚLTIPLA NA NUVEM
                    if (Array.isArray(destino)) {
                        return minhasTurmas.some(t => destino.includes(String(t)) || (Array.isArray(novoMaterial.destinoNome) && novoMaterial.destinoNome.includes(String(t))));
                    } else {
                        return minhasTurmas.some(t => String(t).toLowerCase() === String(destino).toLowerCase() || String(t).toLowerCase() === String(novoMaterial.destinoNome).toLowerCase());
                    }
                });
            }

            // 3. Se encontrou alunos, fabrica os bilhetes de notificação
            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                // Transforma a lista de nomes num texto amigável para a notificação
                const nomeDestinoAmigavel = Array.isArray(novoMaterial.destinoNome) ? novoMaterial.destinoNome.join(', ') : (novoMaterial.destinoNome || 'Geral');
                
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    
                    return {
                        id: crypto.randomUUID(),
                        escolaId: escolaId,
                        destinatarioNome: nomeAluno,
                        remetenteNome: autor,
                        mensagem: `compartilhou um novo material: "${tituloMat}"`,
                        origem: 'material',
                        origemId: novoMaterial.id,
                        destinoNome: nomeDestinoAmigavel, // Usa o texto formatado
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                // 4. Salva no cofre e dá o Grito Global em Tempo Real (SSE)
                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    
                    workspaceStream.emit('evento_realtime', { 
                        type: 'NOVA_NOTIFICACAO', 
                        destinatarios: nomesDestinatarios, 
                        escolaId: escolaId 
                    });
                }
            }
        } catch (erroNotificacao) {
            console.error("Aviso: Material guardado, mas falha ao gerar notificações.", erroNotificacao);
        }
        // ====================================================================

        res.status(201).json({ success: true, material: novoMaterial });
    } catch (error) {
        console.error("Erro ao guardar material:", error);
        res.status(500).json({ success: false, error: 'Erro ao registar o material.' });
    }
});

// 2. Procurar Materiais (Geral para Professores, Filtrado para Alunos)
router.get('/materiais', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId;
        const alunoRefId = req.query.alunoRefId;
        
        let filtro = { escolaId: escolaId };
        
        // Se for um aluno a pedir, o servidor só entrega materiais permitidos
        if (alunoRefId && alunoRefId !== 'undefined') {
            const aluno = await db.collection('alunos').findOne({ id: alunoRefId });
            if (aluno) {
                let minhasTurmas = Array.isArray(aluno.turmas) ? aluno.turmas : [aluno.turmas || aluno.turma];
                // 🚀 O MOTOR DE BUSCA DA MONGODB ATUALIZADO:
                // O operador $in cruza naturalmente uma lista com outra lista!
                filtro = { 
                    escolaId: escolaId,
                    $or: [
                        { destino: 'global' }, 
                        { destino: { $in: ['global'] } }, // Prevenção: caso guardem ['global']
                        { destino: { $in: minhasTurmas } }, 
                        { destinoNome: { $in: minhasTurmas } }
                    ] 
                };
            }
        }
        
        const materiais = await db.collection('workspace_materiais').find(filtro).sort({ dataCriacao: -1 }).toArray();
        res.status(200).json({ success: true, materiais });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// 3. Apagar Material
router.delete('/materiais/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_materiais').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// 3.5. Atualizar Material (Metadados) e Disparar Atualização Global
router.put('/materiais/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const materialAtualizado = req.body;
        const materialId = req.params.id;

        const materialAntigo = await db.collection('workspace_materiais').findOne({ id: materialId });
        if(!materialAntigo) return res.status(404).json({ error: 'Material não encontrado.' });

        // 1. Atualiza as informações físicas na base de dados
        await db.collection('workspace_materiais').updateOne(
            { id: materialId }, 
            { $set: {
                titulo: materialAtualizado.titulo,
                descricao: materialAtualizado.descricao,
                destino: materialAtualizado.destino,
                destinoNome: materialAtualizado.destinoNome,
                url: materialAtualizado.url,
                tipoFicheiro: materialAtualizado.tipoFicheiro,
                nomeOriginal: materialAtualizado.nomeOriginal
            }}
        );

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES (Prof -> Alunos sobre a Atualização)
        // ====================================================================
        try {
            const escolaId = materialAtualizado.escolaId || 'DEFAULT';
            const destino = materialAtualizado.destino || 'global';
            const autor = materialAtualizado.autorNome || 'Professor';
            const tituloMat = materialAtualizado.titulo || 'Material Atualizado';

            const alunos = await db.collection('alunos').find({ escolaId: escolaId }).toArray();
            
            let alunosAlvo = [];
            if (destino === 'global' || (Array.isArray(destino) && destino.includes('global'))) {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    if (Array.isArray(destino)) {
                        return minhasTurmas.some(t => destino.includes(String(t)) || (Array.isArray(materialAtualizado.destinoNome) && materialAtualizado.destinoNome.includes(String(t))));
                    } else {
                        return minhasTurmas.some(t => String(t).toLowerCase() === String(destino).toLowerCase() || String(t).toLowerCase() === String(materialAtualizado.destinoNome).toLowerCase());
                    }
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const nomeDestinoAmigavel = Array.isArray(materialAtualizado.destinoNome) ? materialAtualizado.destinoNome.join(', ') : (materialAtualizado.destinoNome || 'Geral');
                
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    
                    return {
                        id: crypto.randomUUID(),
                        escolaId: escolaId,
                        destinatarioNome: nomeAluno,
                        remetenteNome: autor,
                        mensagem: `atualizou o material: "${tituloMat}"`, // Mensagem distinta de Criação
                        origem: 'material', 
                        origemId: materialId,
                        destinoNome: nomeDestinoAmigavel,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    workspaceStream.emit('evento_realtime', { 
                        type: 'NOVA_NOTIFICACAO', 
                        destinatarios: nomesDestinatarios, 
                        escolaId: escolaId 
                    });
                }
            }
        } catch (eNoti) {
            console.error("Aviso: Falha ao gerar notificações de atualização de material.", eNoti);
        }

        // ====================================================================
        // 🚀 O GRITO DE ATUALIZAÇÃO EM TEMPO REAL PARA RECARREGAR A TELA
        // ====================================================================
        workspaceStream.emit('evento_realtime', { 
            type: 'MATERIAL_UPDATE', 
            escolaId: materialAtualizado.escolaId || 'DEFAULT' 
        });

        res.status(200).json({ success: true });
    } catch (error) {
        console.error("Erro ao atualizar material:", error);
        res.status(500).json({ success: false, error: 'Erro ao atualizar.' });
    }
});

// ============================================================================
// 📡 ROTA DE MONITORAMENTO EM TEMPO REAL DO WORKSPACE
// ============================================================================
router.get('/monitoramento/status', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId; 
        const filtro = escolaId ? { escolaId } : {};

        const alunos = await db.collection('alunos').find(filtro).toArray();
        const usuarios = await db.collection('usuarios').find(filtro).toArray();
        
        const agora = new Date();
        const JANELA_ONLINE = 35 * 1000;
        const relatorioFinal = [];

        // 1. Processar Alunos (BLINDADO CONTRA FALSOS POSITIVOS)
        alunos.forEach(aluno => {
            if (!aluno.id) return; 
            
            const contaUser = usuarios.find(u => u.alunoRefId && String(u.alunoRefId) === String(aluno.id));
            const ultimoAcessoStr = contaUser?.ultimoAcesso || null;
            let isOnline = false;
            
            if (ultimoAcessoStr) {
                const ultimaData = new Date(ultimoAcessoStr).getTime();
                if (!isNaN(ultimaData) && (agora.getTime() - ultimaData) <= JANELA_ONLINE) {
                    isOnline = true;
                }
            }
            
            relatorioFinal.push({
                id: aluno.id,
                nome: aluno.nome || contaUser?.login || 'Aluno',
                isOnline,
                ultimoAcesso: ultimoAcessoStr // 🚀 A RESTAURAÇÃO: Devolve a data de acesso ao painel do Gestor!
            });
        });

        // 2. Processar Equipa Pedagógica (Professores e Gestores)
        usuarios.forEach(user => {
            if (user.tipo === 'Aluno') return; 
            if (!user.id) return;

            const ultimoAcessoStr = user.ultimoAcesso || null;
            let isOnline = false;
            
            if (ultimoAcessoStr) {
                const ultimaData = new Date(ultimoAcessoStr).getTime();
                if (!isNaN(ultimaData) && (agora.getTime() - ultimaData) <= JANELA_ONLINE) {
                    isOnline = true;
                }
            }
            
            relatorioFinal.push({
                id: user.id,
                nome: user.nome || user.login || 'Equipa',
                isOnline,
                ultimoAcesso: ultimoAcessoStr // 🚀 A RESTAURAÇÃO: Devolve a data de acesso da Equipa!
            });
        });

        res.status(200).json(relatorioFinal);
    } catch (error) {
        res.status(500).json({ error: 'Erro no radar.' });
    }
});

router.post('/monitoramento/ping', verificarToken, async (req, res) => {
    try {
        // Lemos o ID a partir do corpo do pedido em vez do token quebrado
        const usuarioId = req.body.usuarioId;
        if (!usuarioId) return res.status(400).json({ error: 'ID ausente' });

        const db = await connectDB();
        await db.collection('usuarios').updateOne(
            { id: usuarioId },
            { $set: { ultimoAcesso: new Date().toISOString() } }
        );
        res.status(200).json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro no ping.' }); }
});

router.post('/monitoramento/offline', verificarToken, async (req, res) => {
    try {
        let usuarioId = req.body.usuarioId;
        
        // 🚀 PREVENÇÃO EXTRA: Se o navegador enviar os dados do Beacon como texto puro, nós convertemos!
        if (!usuarioId && typeof req.body === 'string') {
            try { usuarioId = JSON.parse(req.body).usuarioId; } catch(err){}
        }
        
        if (!usuarioId) return res.status(200).json({ success: true });

        const db = await connectDB();
        const tempoExpirado = new Date(Date.now() - 60000).toISOString();
        await db.collection('usuarios').updateOne(
            { id: usuarioId },
            { $set: { ultimoAcesso: tempoExpirado } }
        );
        res.status(200).json({ success: true });
    } catch (e) { res.status(200).json({ success: true }); }
});


// ==================== BACKEND V40 COMPLETO FINAL - ORGANIZADO ====================
// PARTE 1: HUB - dados gerais
// PARTE 2: ECONOMIA - coins bronze/prata/ouro + diamantes + pedras + energia
// PARTE 3: ILHA - salvar, minha, listar, invadir, coletar
// PARTE 4: LOJA - comprar com coins e diamantes (protegido vs roubável)
// PARTE 5: MISSÕES, GUILDAS, GUERRA, RANKING, PORTAL, SEASON
// Tudo compatível com frontend V40, sem quebrar rotas antigas

// BACKEND V11 COMPLETO - ILHA TOP RPG VICIANTE
// Baseado no V10 + suporte a todos os novos sistemas sem quebrar nada
// Novos: energia, baús, pets, ovos, classe, skills, craft, mapa, clima, mercador, guildas

const DEFAULT_LEVEL_CURVE_INGLES_V11 = [0, 100, 250, 450, 700, 1000, 1400, 1900, 2500, 3200, 4000, 5000, 6200];
const calcLevelInglesV11 = (xpTotal, curve = DEFAULT_LEVEL_CURVE_INGLES_V11) => {
    let lvl = 1;
    for (let i = 0; i < curve.length; i++) {
        if (xpTotal >= curve[i]) lvl = i + 1;
        else break;
    }
    return lvl;
};

async function ensureIndexesInglesV11(db){
    try{
        await db.collection('workspace_ingles_stats').createIndex({escolaId:1, xp:-1});
        await db.collection('workspace_ingles_stats').createIndex({userId:1}, {unique:true});
        await db.collection('workspace_ingles_data').createIndex({escolaId:1}, {unique:true});
        await db.collection('workspace_ingles_ilhas').createIndex({userId:1}, {unique:true});
        await db.collection('workspace_ingles_ilhas').createIndex({escolaId:1, cristais:-1});
        await db.collection('workspace_ingles_guildas').createIndex({escolaId:1});
        await db.collection('workspace_ingles_guildas').createIndex({nome:1, escolaId:1}, {unique:true});
    }catch{}
}

// ==================== XP & RANKING ====================
router.post('/ingles/xp', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const { userId, escolaId, nome, xp, streak, level, titulo, tituloEquipado, bordaEquipada, inventario, medalhas, questsProgress, portalStreak, portalRodada, portalTarget, portalRecorde, energia, energiaMax, bausAbertura, petsInventario, petEquipado, ovosChocando, classe, skillPoints, skills, mapaExplorado, nivelIlha, xpIlha, coins, diamantes, pedras } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
        const escolaIdSeguro = escolaId || 'DEFAULT';
        const xpInt = parseInt(xp) || 0;
        const atual = await db.collection('workspace_ingles_stats').findOne({ userId }) || {};
        const updateSet = {
            userId,
            escolaId: escolaIdSeguro,
            nome: nome || atual.nome || 'Aluno',
            xp: xpInt,
            streak: parseInt(streak) || atual.streak || 1,
            level: level ? parseInt(level) : calcLevelInglesV11(xpInt),
            ultimaAtividade: new Date().toISOString()
        };
        if (titulo !== undefined) updateSet.titulo = titulo;
        if (tituloEquipado !== undefined) updateSet.tituloEquipado = tituloEquipado;
        if (bordaEquipada !== undefined) updateSet.bordaEquipada = bordaEquipada;
        if (inventario !== undefined) updateSet.inventario = inventario;
        if (medalhas !== undefined) updateSet.medalhas = medalhas;
        if (questsProgress !== undefined) updateSet.questsProgress = questsProgress;
        if (portalStreak !== undefined) updateSet.portalStreak = parseInt(portalStreak) || 0;
        if (portalRodada !== undefined) updateSet.portalRodada = parseInt(portalRodada) || 1;
        if (portalTarget !== undefined) updateSet.portalTarget = parseInt(portalTarget) || 5;
        if (energia !== undefined) updateSet.energia = parseInt(energia);
        if (energiaMax !== undefined) updateSet.energiaMax = parseInt(energiaMax);
        if (bausAbertura !== undefined) updateSet.bausAbertura = bausAbertura;
        if (petsInventario !== undefined) updateSet.petsInventario = petsInventario;
        if (petEquipado !== undefined) updateSet.petEquipado = petEquipado;
        if (ovosChocando !== undefined) updateSet.ovosChocando = ovosChocando;
        if (classe !== undefined) updateSet.classe = classe;
        if (skillPoints !== undefined) updateSet.skillPoints = parseInt(skillPoints);
        if (skills !== undefined) updateSet.skills = skills;
        if (mapaExplorado !== undefined) updateSet.mapaExplorado = mapaExplorado;
        if (nivelIlha !== undefined) updateSet.nivelIlha = parseInt(nivelIlha);
        if (xpIlha !== undefined) updateSet.xpIlha = parseInt(xpIlha);
        if (coins !== undefined) updateSet.coins = coins;
        if (diamantes !== undefined) updateSet.diamantes = parseInt(diamantes);
        if (pedras !== undefined) updateSet.pedras = pedras;
        const recordeAtual = atual.portalRecorde || 0;
        const novoRecorde = Math.max(recordeAtual, parseInt(portalRecorde) || 0, parseInt(portalStreak) || 0);
        updateSet.portalRecorde = novoRecorde;
        await db.collection('workspace_ingles_stats').updateOne({ userId }, { $set: updateSet }, { upsert: true });
        res.json({ success: true, level: updateSet.level, portalRecorde: novoRecorde });
    } catch (e) {
        console.error('V11 /xp erro', e);
        res.status(500).json({ error: 'Erro sync xp' });
    }
});

router.get('/ingles/ranking', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        const ranking = await db.collection('workspace_ingles_stats').find({ escolaId, xp: { $gt: 0 } }).sort({ xp: -1 }).limit(50).toArray();
        const comLiga = ranking.map((r, i) => ({
            userId: r.userId,
            nome: r.nome,
            xp: r.xp,
            level: r.level || calcLevelInglesV11(r.xp),
            streak: r.streak || 1,
            titulo: r.titulo || 'Aprendiz',
            tituloEquipado: r.tituloEquipado || r.titulo || 'Aprendiz',
            bordaEquipada: r.bordaEquipada || '',
            inventario: r.inventario || [],
            medalhas: r.medalhas || [],
            portalRecorde: r.portalRecorde || 0,
            classe: r.classe || 'mago',
            nivelIlha: r.nivelIlha || 1,
            posicao: i + 1,
            liga: i < 3 ? 'ouro' : i < 10 ? 'prata' : i < 20 ? 'bronze' : 'aprendiz'
        }));
        res.json({ success: true, ranking: comLiga });
    } catch (e) { res.status(500).json({ error: 'Erro ranking' }); }
});

// ==================== DADOS GERAIS - AGORA ACEITA TUDO SEM QUEBRAR ====================
router.get('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const escolaId = req.query.escolaId || 'DEFAULT';
        let d = await db.collection('workspace_ingles_data').findOne({ escolaId }) || {};
        // defaults se não existir
        d.words = d.words || [];
        d.phrases = d.phrases || [];
        d.quizzes = d.quizzes || [];
        d.pictures = d.pictures || [];
        d.wordPickers = d.wordPickers || [];
        d.minimalPairs = d.minimalPairs || [];
        d.debates = d.debates || [];
        d.roleplays = d.roleplays || [];
        d.questions = d.questions || [];
        d.submissions = d.submissions || [];
        d.pool = d.pool || [];
        d.errosRetidos = d.errosRetidos || [];
        d.magoPhrases = d.magoPhrases || [];
        d.magoConfig = d.magoConfig || { vozAtiva: true, modoExibicao: 'aleatorio' };
        d.srs = d.srs || {};
        d.quests = d.quests || [
            { id: 'q_daily_1', tipo: 'diaria', texto: 'Crie 3 frases com conectores (Although/Because/When)', alvo: 3, recompensaXP: 100, icone: '🔗' },
            { id: 'q_daily_2', tipo: 'diaria', texto: 'Acerte 5 Minimal Pairs (ship/sheep)', alvo: 5, recompensaXP: 80, icone: '👂' },
            { id: 'q_daily_3', tipo: 'diaria', texto: 'Debata 4 vezes com IA', alvo: 4, recompensaXP: 120, icone: '🗣️' },
            { id: 'q_daily_4', tipo: 'diaria', texto: 'Treine 5 palavras no Portal Mágico', alvo: 5, recompensaXP: 150, icone: '🌀' },
            { id: 'q_ilha_1', tipo: 'diaria', texto: 'Colete 100 cristais na ilha', alvo: 100, recompensaXP: 200, icone: '💎' },
            { id: 'q_ilha_2', tipo: 'diaria', texto: 'Construa 2 itens na ilha', alvo: 2, recompensaXP: 150, icone: '🔨' }
        ];
        d.achievements = d.achievements || [
            { id: 'ach_first_spell', nome: 'Primeiro Feitiço', desc: 'Complete 1 frase', icone: '✨', condicao: { tipo: 'wordSpark', qtd: 1 }, xpBonus: 50 },
            { id: 'ach_portal_5', nome: 'Viajante Temporal', desc: '5 vitórias seguidas no Portal', icone: '🌀', condicao: { tipo: 'portal', qtd: 5 }, xpBonus: 400 },
            { id: 'ach_ilha_1', nome: 'Construtor', desc: 'Coloque 5 itens na ilha', icone: '🏝️', condicao: { tipo: 'ilha', qtd: 5 }, xpBonus: 200 },
            { id: 'ach_roubo_1', nome: 'Pirata Iniciante', desc: 'Roube 1 vez', icone: '🏴‍☠️', condicao: { tipo: 'roubo', qtd: 1 }, xpBonus: 300 },
            { id: 'ach_pet_1', nome: 'Amigo Fiel', desc: 'Choque 1 ovo de pet', icone: '🐾', condicao: { tipo: 'pet', qtd: 1 }, xpBonus: 400 },
            { id: 'ach_mapa_1', nome: 'Explorador', desc: 'Explore 5 áreas do mapa', icone: '🗺️', condicao: { tipo: 'mapa', qtd: 5 }, xpBonus: 500 }
        ];
        d.season = d.season || { id: 'S1', nome: 'Era dos Feitiços', xpMultiplier: 1, ativa: true, inicio: new Date().toISOString() };
        d.lootTables = d.lootTables || {
            comum: [{ id: 'borda_bronze', nome: 'Borda Bronze', tipo: 'cosmetico', chance: 60 }],
            epico: [{ id: 'borda_prata', nome: 'Borda Prata', tipo: 'cosmetico', chance: 50 }],
            lendario: [{ id: 'borda_ouro', nome: 'Borda Ouro', tipo: 'cosmetico', chance: 40 }]
        };
        d.levelCurve = d.levelCurve || DEFAULT_LEVEL_CURVE_INGLES_V11;
        d.titulos = d.titulos || ['Aprendiz', 'Mago', 'Arquimago', 'Lenda'];
        d.badges = d.badges || [];
        d.portalConfig = d.portalConfig || { jogosPossiveis: ['wordSpark','readAloud','listenType','quiz','wordPicker','picturePop','minimalPairs','sentenceShuffle','answerQuest','questionMaker','contextRole'] };
        d.avatarEquipado = d.avatarEquipado || 'mago_aprendiz';
        d.climas = d.climas || [
            {id:'sol', nome:'Ensolarado', emoji:'☀️', bonus:{cristais:0}},
            {id:'chuva', nome:'Chuva Mágica', emoji:'🌧️', bonus:{cristais:50}, duracao:1800},
            {id:'arco_iris', nome:'Arco-Íris', emoji:'🌈', bonus:{cristais:100, xp:100}, duracao:900}
        ];
        res.json({ success: true, dados: d });
    } catch (e) {
        console.error('GET dados V11', e);
        res.status(500).json({ error: 'Erro ler dados' });
    }
});

router.put('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const { escolaId, ...campos } = req.body;
        const escolaIdSeguro = escolaId || 'DEFAULT';
        const update = { ultimaAtualizacao: new Date().toISOString() };
        // V11: aceita TUDO que vier, sem quebrar - lista expandida
        const permitidos = [
            'words','phrases','quizzes','pictures','submissions','pool','errosRetidos','magoPhrases','magoConfig','srs',
            'wordPickers','minimalPairs','debates','roleplays','questions','quests','achievements','season','lootTables','levelCurve','titulos','badges','portalConfig',
            'avatarEquipado','ferramentaEquipada','energia','energiaMax','bausAbertura','petsInventario','petEquipado','ovosChocando','classe','skillPoints','skills',
            'mapaExplorado','tesourosEnterrados','nivelIlha','xpIlha','climaAtual','climaAte','mercadorAtivo','mercadorAte','guilda','fabricas','visitasFeitas'
        ];
        // Se vier campo novo que não está na lista, ainda salva (para não quebrar futuro)
        Object.keys(campos).forEach(k=>{
            if(permitidos.includes(k) || !k.startsWith('_')){
                update[k] = campos[k];
            }
        });
        console.log('V11 PUT salvando:', Object.keys(update));
        await db.collection('workspace_ingles_data').updateOne({ escolaId: escolaIdSeguro }, { $set: update }, { upsert: true });
        if (global.workspaceStream) global.workspaceStream.emit('evento_realtime', { type: 'BAU_INGLES_UPDATE', escolaId: escolaIdSeguro });
        res.json({ success: true });
    } catch (e) {
        console.error('PUT dados V11', e);
        res.status(500).json({ error: 'Erro salvar' });
    }
});

// ==================== LOJA COM XP COMO MOEDA ====================
router.post('/ingles/loja/comprar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const { userId, escolaId, itemId, tipo, preco, nome } = req.body;
        if (!userId || !itemId || preco===undefined) return res.status(400).json({ error: 'Dados incompletos' });
        const precoInt = parseInt(preco)||0;
        const stats = await db.collection('workspace_ingles_stats').findOne({ userId });
        if (!stats) return res.status(404).json({ error: 'Aluno não encontrado' });
        const xpAtual = stats.xp||0;
        if (xpAtual < precoInt) return res.status(400).json({ error: `XP insuficiente. Você tem ${xpAtual} XP, precisa ${precoInt}` });
        if (tipo==='avatar'){
            const jaTem = (stats.inventario||[]).some(i=>i.id===itemId && i.tipo==='avatar');
            if (jaTem) return res.status(400).json({ error: 'Você já possui esse avatar' });
        }
        const novoXp = xpAtual - precoInt;
        const novoItem = { id: itemId, nome: nome||itemId, tipo: tipo||'geral', preco: precoInt, obtidoEm: new Date().toISOString() };
        await db.collection('workspace_ingles_stats').updateOne({ userId }, { $set: { xp: novoXp, ultimaAtividade: new Date().toISOString() }, $push: { inventario: novoItem } });
        console.log(`V11 LOJA: ${userId} comprou ${itemId} por ${precoInt} XP. Novo XP: ${novoXp}`);
        res.json({ success: true, novoXp, item: novoItem, mensagem: `Comprado por ${precoInt} XP!` });
    } catch (e) {
        console.error('LOJA comprar erro', e);
        res.status(500).json({ error: 'Erro ao comprar' });
    }
});

// ==================== ILHA MÁGICA - COMPATÍVEL V10 + NOVOS CAMPOS ====================
router.post('/ingles/ilha/salvar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const { userId, escolaId, nome, ilha, avatarEquipado, energia, pets, baus, mapaExplorado, tesouros, clima, mercador, skills, skillPoints, classe, nivelIlha } = req.body;
        if (!userId || !ilha) return res.status(400).json({ error: 'Dados incompletos' });
        const escolaIdSeguro = escolaId||'DEFAULT';
        const doc = {
            userId,
            escolaId: escolaIdSeguro,
            nome: nome||'Ilha Mágica',
            nivel: ilha.nivel||nivelIlha||1,
            tamanho: ilha.tamanho||4,
            cristais: ilha.cristais||0,
            layout: ilha.layout||Array(16).fill(null),
            escudoAte: ilha.escudoAte||0,
            invasoesFeitas: ilha.invasoesFeitas||0,
            invasoesRecebidas: ilha.invasoesRecebidas||0,
            historicoInvasoes: (ilha.historicoInvasoes||[]).slice(-50),
            producaoAcumulada: ilha.producaoAcumulada||0,
            limiteProducao: ilha.limiteProducao||500,
            avatarEquipado: avatarEquipado||'mago_aprendiz',
            energia: energia||100,
            pets: pets||[],
            baus: baus||[],
            mapaExplorado: mapaExplorado||{},
            tesouros: tesouros||[],
            clima: clima||{id:'sol'},
            mercador: mercador||null,
            skills: skills||{},
            skillPoints: skillPoints||0,
            classe: classe||'mago',
            ultimaColeta: ilha.ultimaColeta||Date.now(),
            ultimaAtualizacao: new Date().toISOString()
        };
        await db.collection('workspace_ingles_ilhas').updateOne({ userId }, { $set: doc }, { upsert: true });
        res.json({ success: true, ilha: doc });
    } catch (e) {
        console.error('Salvar ilha erro', e);
        res.status(500).json({ error: 'Erro salvar ilha' });
    }
});

router.get('/ingles/ilha/minha', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userId = req.query.userId;
        const escolaId = req.query.escolaId||'DEFAULT';
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
        let ilha = await db.collection('workspace_ingles_ilhas').findOne({ userId });
        if (!ilha){
            ilha = {
                userId,
                escolaId,
                nome: 'Minha Ilha Mágica',
                nivel:1,
                tamanho:4,
                cristais:100,
                layout:Array(16).fill(null),
                escudoAte:0,
                invasoesFeitas:0,
                invasoesRecebidas:0,
                historicoInvasoes:[],
                producaoAcumulada:0,
                limiteProducao:500,
                avatarEquipado:'mago_aprendiz',
                energia:100,
                pets:[],
                baus:[],
                mapaExplorado:{},
                tesouros:[],
                clima:{id:'sol'},
                skills:{},
                skillPoints:0,
                classe:'mago',
                ultimaColeta:Date.now(),
                ultimaAtualizacao:new Date().toISOString()
            };
            await db.collection('workspace_ingles_ilhas').insertOne(ilha);
        }
        res.json({ success: true, ilha });
    } catch (e) {
        res.status(500).json({ error: 'Erro carregar ilha' });
    }
});

router.get('/ingles/ilhas', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId||'DEFAULT';
        const excluir = req.query.excluir;
        const filtro = { escolaId };
        if (excluir) filtro.userId = { $ne: excluir };
        const ilhas = await db.collection('workspace_ingles_ilhas').find(filtro).sort({ nivel:-1, cristais:-1 }).limit(30).toArray();
        const enriquecidas = await Promise.all(ilhas.map(async i=>{
            if (!i.nome || i.nome==='Minha Ilha Mágica'){
                const stats = await db.collection('workspace_ingles_stats').findOne({ userId:i.userId });
                if (stats) i.nome = stats.nome;
            }
            return i;
        }));
        res.json({ success: true, ilhas: enriquecidas });
    } catch (e) {
        res.status(500).json({ error: 'Erro listar ilhas' });
    }
});

router.post('/ingles/ilha/invadir', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await ensureIndexesInglesV11(db);
        const { userId, escolaId, alvoId, acao, sucesso } = req.body;
        if (!userId || !alvoId) return res.status(400).json({ error: 'Dados incompletos' });
        const escolaIdSeguro = escolaId||'DEFAULT';
        const atacanteIlha = await db.collection('workspace_ingles_ilhas').findOne({ userId });
        const alvoIlha = await db.collection('workspace_ingles_ilhas').findOne({ userId: alvoId });
        const atacanteStats = await db.collection('workspace_ingles_stats').findOne({ userId });
        if (!atacanteIlha || !alvoIlha) return res.status(404).json({ error: 'Ilha não encontrada' });
        const agora = Date.now();
        if (alvoIlha.escudoAte && alvoIlha.escudoAte > agora){
            return res.status(400).json({ error: `Ilha protegida até ${new Date(alvoIlha.escudoAte).toLocaleTimeString()}` });
        }
        const histAtacante = atacanteIlha.historicoInvasoes||[];
        const ultimo = histAtacante.filter(h=>h.alvoId===alvoId).sort((a,b)=>b.data-a.data)[0];
        if (ultimo && (agora - ultimo.data) < 60*60*1000){
            const falta = Math.ceil((60*60*1000 - (agora - ultimo.data))/60000);
            return res.status(400).json({ error: `Cooldown! Espere ${falta} min` });
        }
        if (sucesso){
            const temVarinha = (atacanteStats?.inventario||[]).some(i=>i.id==='varinha_roubo' || i.id==='varinha_roubo_suprema');
            if (!temVarinha) return res.status(400).json({ error: 'Precisa de Varinha 🪄' });
        }
        let roubado = 0;
        if (sucesso){
            const cristaisAlvo = alvoIlha.cristais||0;
            roubado = Math.floor(cristaisAlvo * 0.10);
            const temSuprema = (atacanteStats?.inventario||[]).some(i=>i.id==='varinha_roubo_suprema');
            if(temSuprema) roubado = Math.floor(cristaisAlvo * 0.20);
            roubado = Math.max(10, Math.min(300, roubado));
            if (cristaisAlvo < 10) roubado = cristaisAlvo;
            await db.collection('workspace_ingles_ilhas').updateOne({ userId: alvoId }, { 
                $inc: { cristais: -roubado, invasoesRecebidas:1 },
                $set: { escudoAte: agora + 2*60*60*1000, ultimaAtualizacao: new Date().toISOString() },
                $push: { historicoInvasoes: { $each: [{ alvoId: userId, alvoNome: atacanteIlha.nome||'Atacante', data: agora, sucesso:false, cristais:roubado, tipo:'defesa', detalhe:`Foi roubado por ${atacanteIlha.nome} - perdeu ${roubado}💎` }], $slice: -50 } }
            });
            await db.collection('workspace_ingles_ilhas').updateOne({ userId }, { 
                $inc: { cristais: roubado, invasoesFeitas:1 },
                $set: { ultimaAtualizacao: new Date().toISOString() },
                $push: { historicoInvasoes: { $each: [{ alvoId, alvoNome: alvoIlha.nome||'Ilha', data: agora, sucesso:true, cristais:roubado, tipo:'ataque', detalhe:`Roubou ${roubado}💎 de ${alvoIlha.nome}` }], $slice: -50 } }
            });
            await db.collection('workspace_ingles_stats').updateOne({ userId }, { $pull: { inventario: { id:'varinha_roubo' } } });
            console.log(`V11 ROUBO: ${userId} roubou ${roubado} de ${alvoId}`);
            res.json({ success: true, roubado, mensagem: `Roubo! +${roubado}💎` });
        } else {
            await db.collection('workspace_ingles_stats').updateOne({ userId }, { $inc: { xp: -50 } });
            await db.collection('workspace_ingles_ilhas').updateOne({ userId: alvoId }, { 
                $set: { escudoAte: agora + 2*60*60*1000 },
                $push: { historicoInvasoes: { $each: [{ alvoId: userId, alvoNome: atacanteIlha.nome, data: agora, sucesso:false, cristais:0, tipo:'defesa', detalhe:`Defendeu ataque de ${atacanteIlha.nome}` }], $slice: -50 } }
            });
            await db.collection('workspace_ingles_ilhas').updateOne({ userId }, { 
                $push: { historicoInvasoes: { $each: [{ alvoId, alvoNome: alvoIlha.nome, data: agora, sucesso:false, cristais:0, tipo:'ataque', detalhe:`Falhou ao invadir ${alvoIlha.nome} - perdeu 50 XP` }], $slice: -50 } }
            });
            res.json({ success: true, roubado:0, mensagem: 'Falhou! -50 XP' });
        }
    } catch (e) {
        console.error('Invadir erro', e);
        res.status(500).json({ error: 'Erro ao invadir' });
    }
});

// ==================== GUILDAS - NOVO SEM QUEBRAR ====================
router.post('/ingles/guilda/criar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, escolaId, nome, descricao } = req.body;
        if(!userId || !nome) return res.status(400).json({error:'Dados incompletos'});
        const existe = await db.collection('workspace_ingles_guildas').findOne({escolaId:escolaId||'DEFAULT', nome});
        if(existe) return res.status(400).json({error:'Guilda já existe'});
        const guilda = {
            nome,
            descricao:descricao||'',
            escolaId:escolaId||'DEFAULT',
            lider:userId,
            membros:[userId],
            nivel:1,
            xp:0,
            cristais:0,
            criadoEm:new Date().toISOString()
        };
        await db.collection('workspace_ingles_guildas').insertOne(guilda);
        await db.collection('workspace_ingles_ilhas').updateOne({userId}, {$set:{guilda:nome}});
        res.json({success:true, guilda});
    } catch(e){ res.status(500).json({error:'Erro criar guilda'}); }
});

router.get('/ingles/guildas', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const guildas = await db.collection('workspace_ingles_guildas').find({escolaId:req.query.escolaId||'DEFAULT'}).sort({nivel:-1, xp:-1}).limit(20).toArray();
        res.json({success:true, guildas});
    } catch(e){ res.status(500).json({error:'Erro listar guildas'}); }
});

router.post('/ingles/guilda/entrar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, escolaId, nomeGuilda } = req.body;
        const guilda = await db.collection('workspace_ingles_guildas').findOne({escolaId:escolaId||'DEFAULT', nome:nomeGuilda});
        if(!guilda) return res.status(404).json({error:'Guilda não encontrada'});
        if(guilda.membros.length>=5) return res.status(400).json({error:'Guilda cheia (max 5)'});
        await db.collection('workspace_ingles_guildas').updateOne({escolaId:escolaId||'DEFAULT', nome:nomeGuilda}, {$addToSet:{membros:userId}});
        await db.collection('workspace_ingles_ilhas').updateOne({userId}, {$set:{guilda:nomeGuilda}});
        res.json({success:true});
    } catch(e){ res.status(500).json({error:'Erro entrar guilda'}); }
});

// ==================== QUESTS, RECOMPENSA, SEASON, PORTAL (igual V10) ====================
router.get('/ingles/quests', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        const userId = req.query.userId;
        const dados = await db.collection('workspace_ingles_data').findOne({ escolaId });
        const questsBase = dados?.quests || [];
        let progresso = {};
        if (userId) {
            const stats = await db.collection('workspace_ingles_stats').findOne({ userId });
            progresso = stats?.questsProgress || {};
        }
        res.json({ success: true, quests: questsBase.map(q => ({ ...q, progresso: progresso[q.id]?.atual || 0, completo: (progresso[q.id]?.atual || 0) >= q.alvo, coletado: progresso[q.id]?.coletado || false })) });
    } catch (e) { res.status(500).json({ error: 'Erro quests' }); }
});

router.post('/ingles/quests/completar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, questId, escolaId } = req.body;
        const dados = await db.collection('workspace_ingles_data').findOne({ escolaId: escolaId || 'DEFAULT' });
        const quest = dados?.quests?.find(q => q.id === questId);
        if (!quest) return res.status(404).json({ error: 'Quest não encontrada' });
        const mult = dados?.season?.xpMultiplier || 1;
        const bonusXP = Math.floor((quest.recompensaXP || 100) * mult);
        await db.collection('workspace_ingles_stats').updateOne({ userId }, { $inc: { xp: bonusXP, energia: 5 }, $set: { [`questsProgress.${questId}.atual`]: quest.alvo, [`questsProgress.${questId}.coletado`]: true, ultimaAtividade: new Date().toISOString() } }, { upsert: true });
        res.json({ success: true, bonusXP, energia:5 });
    } catch (e) { res.status(500).json({ error: 'Erro completar quest' }); }
});

router.post('/ingles/recompensa/abrir', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, escolaId, raridade, xpSessao } = req.body;
        const escolaIdSeguro = escolaId || 'DEFAULT';
        const rar = raridade || (xpSessao > 300 ? 'lendario' : xpSessao > 150 ? 'epico' : 'comum');
        const dados = await db.collection('workspace_ingles_data').findOne({ escolaId: escolaIdSeguro });
        const tabela = dados?.lootTables?.[rar] || [];
        if (!tabela.length) return res.json({ success: true, recompensa: null, raridade: rar });
        const total = tabela.reduce((s, i) => s + (i.chance || 50), 0);
        let r = Math.random() * total;
        let escolhido = tabela[0];
        for (const item of tabela) {
            r -= (item.chance || 50);
            if (r <= 0) { escolhido = item; break; }
        }
        await db.collection('workspace_ingles_stats').updateOne({ userId }, { $push: { inventario: { ...escolhido, obtidoEm: new Date().toISOString(), raridade: rar } }, $inc:{energia:10} }, { upsert: true });
        res.json({ success: true, recompensa: escolhido, raridade: rar });
    } catch (e) { res.status(500).json({ error: 'Erro loot' }); }
});

router.get('/ingles/season/atual', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const dados = await db.collection('workspace_ingles_data').findOne({ escolaId: req.query.escolaId || 'DEFAULT' });
        res.json({ success: true, season: dados?.season || { id: 'S1', nome: 'Era dos Feitiços', xpMultiplier: 1, ativa: true } });
    } catch (e) { res.status(500).json({ error: 'Erro season' }); }
});

router.post('/ingles/season/reset', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId, novaSeason } = req.body;
        const escolaIdSeguro = escolaId || 'DEFAULT';
        const rankingAtual = await db.collection('workspace_ingles_stats').find({ escolaId: escolaIdSeguro }).toArray();
        if (rankingAtual.length) {
            await db.collection('workspace_ingles_historico').insertOne({ escolaId: escolaIdSeguro, seasonId: novaSeason?.id || `S_${Date.now()}`, ranking: rankingAtual, encerradoEm: new Date().toISOString() });
        }
        await db.collection('workspace_ingles_stats').updateMany({ escolaId: escolaIdSeguro }, { $set: { xp: 0, questsProgress: {}, portalStreak: 0 } });
        await db.collection('workspace_ingles_data').updateOne({ escolaId: escolaIdSeguro }, { $set: { season: { ...novaSeason, inicio: new Date().toISOString() }, ultimaAtualizacao: new Date().toISOString() } }, { upsert: true });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro reset' }); }
});

router.post('/ingles/portal/progresso', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, portalStreak, portalRodada, portalTarget, xpGanho, xpPerda } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
        const atual = await db.collection('workspace_ingles_stats').findOne({ userId }) || {};
        const set = { ultimaAtividade: new Date().toISOString() };
        const inc = {};
        if (portalStreak !== undefined) set.portalStreak = parseInt(portalStreak) || 0;
        if (portalRodada !== undefined) set.portalRodada = parseInt(portalRodada) || 1;
        if (portalTarget !== undefined) set.portalTarget = parseInt(portalTarget) || 5;
        if (xpGanho) inc.xp = parseInt(xpGanho);
        if (xpPerda) inc.xp = -parseInt(xpPerda);
        if (xpGanho) inc.energia = 2;
        const recordeAtual = atual.portalRecorde || 0;
        const novoRecorde = Math.max(recordeAtual, parseInt(portalStreak) || 0);
        if (novoRecorde > recordeAtual) set.portalRecorde = novoRecorde;
        const update = {};
        if (Object.keys(set).length) update.$set = set;
        if (Object.keys(inc).length) update.$inc = inc;
        await db.collection('workspace_ingles_stats').updateOne({ userId }, update, { upsert: true });
        res.json({ success: true, recorde: novoRecorde });
    } catch (e) {
        res.status(500).json({ error: 'Erro portal' });
    }
});

router.get('/ingles/portal/ranking', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const ranking = await db.collection('workspace_ingles_stats').find({ escolaId: req.query.escolaId || 'DEFAULT', portalRecorde: { $gt: 0 } }).sort({ portalRecorde: -1 }).limit(20).toArray();
        res.json({ success: true, ranking });
    } catch (e) { res.status(500).json({ error: 'Erro ranking portal' }); }
});


module.exports = router;