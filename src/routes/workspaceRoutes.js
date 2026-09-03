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

// ============================================================================
// 🧠 INICIALIZAÇÃO DO CÉREBRO DA IA (PTT CURSOS)
// ============================================================================
const PttAIEngine = require('./PttAIEngine'); 

// Inicia o Cérebro assim que o servidor arranca
PttAIEngine.init();

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


// ============================================================================
// 🏴‍☠️ BAÚ DO INGLÊS - MOTOR DE DADOS PURIFICADO E OTIMIZADO
// ============================================================================

// 1. SINCRONIZAR MOEDAS E STREAK (ANTIGO XP)
router.post('/ingles/xp', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, escolaId, nome, coins, streak } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
        
        const escolaIdSeguro = escolaId || 'DEFAULT';
        const moedas = coins || { bronze: 0, prata: 0, ouro: 0 };
        
        await db.collection('workspace_ingles_stats').updateOne(
            { userId }, 
            { 
                $set: { 
                    escolaId: escolaIdSeguro,
                    nome: nome || 'Aluno',
                    coins: moedas,
                    streak: parseInt(streak) || 1,
                    ultimaAtividade: new Date().toISOString()
                } 
            }, 
            { upsert: true }
        );
        res.json({ success: true });
    } catch (e) {
        console.error('Erro sync stats', e);
        res.status(500).json({ error: 'Erro sync stats' });
    }
});

// 2. RANKING DA ESCOLA (BASEADO EM MOEDAS DE BRONZE)
router.get('/ingles/ranking', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        
        const ranking = await db.collection('workspace_ingles_stats')
            .find({ escolaId, "coins.bronze": { $gt: 0 } })
            .sort({ "coins.bronze": -1 })
            .limit(50)
            .toArray();
            
        const comLiga = ranking.map((r, i) => ({
            userId: r.userId,
            nome: r.nome,
            coins: r.coins || {bronze: 0, prata: 0, ouro: 0},
            streak: r.streak || 1,
            posicao: i + 1,
            liga: i < 3 ? 'ouro' : i < 10 ? 'prata' : i < 20 ? 'bronze' : 'aprendiz'
        }));
        
        res.json({ success: true, ranking: comLiga });
    } catch (e) { res.status(500).json({ error: 'Erro ranking' }); }
});

// 3. CARREGAR DADOS DA BIBLIOTECA E ALGORITMO
router.get('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        let d = await db.collection('workspace_ingles_data').findOne({ escolaId }) || {};
        
        // Retorna exclusivamente o que o Baú do Inglês utiliza
        const dadosLimpos = {
            ultimaAtualizacao: d.ultimaAtualizacao,
            words: d.words || [],
            phrases: d.phrases || [],
            quizzes: d.quizzes || [],
            pictures: d.pictures || [],
            wordPickers: d.wordPickers || [],
            minimalPairs: d.minimalPairs || [],
            debates: d.debates || [],
            roleplays: d.roleplays || [],
            questions: d.questions || [],
            submissions: d.submissions || [],
            pool: d.pool || [],
            errosRetidos: d.errosRetidos || [],
            srs: d.srs || {}
        };
        
        res.json({ success: true, dados: dadosLimpos });
    } catch (e) {
        console.error('GET dados Ingles', e);
        res.status(500).json({ error: 'Erro ler dados' });
    }
});

// 4. SALVAR DADOS DA BIBLIOTECA
router.put('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId, ...campos } = req.body;
        const escolaIdSeguro = escolaId || 'DEFAULT';
        
        const update = { ultimaAtualizacao: new Date().toISOString() };
        
        const permitidos = [
            'words','phrases','quizzes','pictures','submissions','pool','errosRetidos','srs',
            'wordPickers','minimalPairs','debates','roleplays','questions'
        ];
        
        Object.keys(campos).forEach(k => {
            if(permitidos.includes(k)){
                update[k] = campos[k];
            }
        });
        
        await db.collection('workspace_ingles_data').updateOne({ escolaId: escolaIdSeguro }, { $set: update }, { upsert: true });
        res.json({ success: true });
    } catch (e) {
        console.error('PUT dados Ingles', e);
        res.status(500).json({ error: 'Erro salvar' });
    }
});

// ============================================================================
// 🧙‍♂️ SUPER MAGO IA (IA NATIVA AVANÇADA COM ANÁLISE HEURÍSTICA E REGEX)
// ============================================================================

router.post('/ingles/debate', verificarToken, async (req, res) => {
    try {
        const { topico, historico } = req.body;
        
        const ultimaMensagem = historico[historico.length - 1];
        const mensagemDoAluno = ultimaMensagem.text.trim();
        const textoMinusculo = mensagemDoAluno.toLowerCase();
        const totalTurnos = historico.length;
        const topicoLimpo = topico.replace(/[^a-zA-Z0-9 ]/g, '');

        let respostaGerada = "";
        let dicaGramatical = "";

        // Simulamos o tempo de pensamento para realismo
        await new Promise(resolve => setTimeout(resolve, 1200));

        // 🧠 CAMADA 1: SIMULADOR DE CORREÇÃO GRAMATICAL (RegEx)
        // Expressões regulares procuram por padrões de erros clássicos de quem aprende inglês
        if (/\b(he|she|it)\s+(dont|do)\b/i.test(textoMinusculo)) {
            dicaGramatical = " 🧙‍♂️ Magic Tip: Remember to use 'doesn't' or 'does' with He, She, and It!";
        } else if (/\bi\s+(is|has)\b/i.test(textoMinusculo)) {
            dicaGramatical = " 🧙‍♂️ Magic Tip: With 'I', we always use 'am' or 'have'.";
        } else if (/\b(more better|more good)\b/i.test(textoMinusculo)) {
            dicaGramatical = " 🧙‍♂️ Magic Tip: We just say 'better', no need for 'more'!";
        }

        // 🧠 CAMADA 2: ANÁLISE DE ESFORÇO (O aluno escreveu pouco?)
        const quantidadePalavras = mensagemDoAluno.split(/\s+/).length;
        if (quantidadePalavras < 4) {
            respostaGerada = `That's a very short answer! Come on, use your English skills. Tell me exactly WHY you think that about ${topicoLimpo}.`;
        } 
        // 🧠 CAMADA 3: ANÁLISE DE INTENÇÃO (É uma pergunta?)
        else if (/^(why|how|what|when|where|is|are|do|does|can|could|would)\b/i.test(textoMinusculo) || textoMinusculo.includes('?')) {
            respostaGerada = `You are asking the right questions! However, in the context of ${topicoLimpo}, I want to hear YOUR perspective first. How would you answer that?`;
        } 
        // 🧠 CAMADA 4: CONCORDÂNCIA E DISCORDÂNCIA COM CONTEXTO
        else if (/\b(agree|yes|absolutely|true|right)\b/.test(textoMinusculo)) {
            respostaGerada = `I'm glad we are on the same page. But what if the opposite were true? How would society handle ${topicoLimpo} if we took away the main benefits you just mentioned?`;
        } 
        else if (/\b(disagree|no|false|wrong|dont think so)\b/.test(textoMinusculo)) {
            respostaGerada = `A strong counter-argument! You clearly disagree. But consider this: many experts believe ${topicoLimpo} brings hidden advantages. Can you think of at least one positive aspect?`;
        } 
        // 🧠 CAMADA 5: JUSTIFICATIVAS E EXEMPLOS
        else if (/\b(because|since|for example|like)\b/.test(textoMinusculo)) {
            respostaGerada = `Excellent point, applying reasons and examples makes your English sound very natural! But let's dig deeper: does that rule apply to everyone, everywhere?`;
        } 
        // 🧠 CAMADA 6: RESPOSTA DINÂMICA PADRÃO
        else {
            const respostasDinâmicas = [
                `That is a fascinating way to look at ${topicoLimpo}. But let me challenge you: what is the biggest flaw in that line of thought?`,
                `You express yourself very well. Still, regarding ${topicoLimpo}, don't you think technology or culture will change that perspective in 10 years?`,
                `I see your point. To keep our debate moving, what would you say to someone who completely disagrees with what you just wrote?`
            ];
            respostaGerada = respostasDinâmicas[Math.floor(Math.random() * respostasDinâmicas.length)];
        }

        // 🧠 CAMADA 7: GESTÃO DO FIM DO DEBATE
        if (totalTurnos > 8 && totalTurnos < 11) {
            respostaGerada = `We have explored ${topicoLimpo} thoroughly! Your English argumentation is getting stronger. Please, give me your final concluding statement on this matter.`;
        } else if (totalTurnos >= 11) {
            respostaGerada = `Debate successfully concluded! 🌟 You did an amazing job defending your thoughts. Feel free to close this training and collect your Bronze Coins!`;
        }

        // Juntamos a resposta inteligente com a dica gramatical (se o aluno tiver cometido algum erro rastreado)
        const respostaFinal = respostaGerada + dicaGramatical;

        res.json({ success: true, resposta: respostaFinal });

    } catch (error) {
        console.error("🚨 Erro na Super IA Nativa:", error);
        res.status(500).json({ success: false, error: 'O Mago IA está focado noutro feitiço. Tente novamente!' });
    }
});

// ============================================================================
// 🧠 ROTAS DA NOSSA IA NATIVA PTT (JOGO DE TESTE / LABORATÓRIO)
// ============================================================================

// 1. Rota para o Aluno conversar com a Ptt AI
router.post('/ingles/ia-teste/falar', verificarToken, async (req, res) => {
    try {
        const { mensagem } = req.body;
        if (!mensagem) return res.status(400).json({ error: 'Mensagem vazia.' });

        // O Cérebro processa a mensagem
        const pensamento = PttAIEngine.pensar(mensagem);

        res.json({ 
            success: true, 
            resposta: pensamento.resposta,
            // Enviamos também o que a IA pensou "nos bastidores" para podermos ver no painel!
            bastidores: `A Ptt AI classificou esta frase como: [${pensamento.intencaoDetetada}]`
        });

    } catch (error) {
        console.error("🚨 Erro na Ptt AI de Teste:", error);
        res.status(500).json({ success: false, error: 'O cérebro falhou.' });
    }
});

// 2. Rota para o Professor (O Paulo) ensinar coisas novas à Ptt AI!
router.post('/ingles/ia-teste/ensinar', verificarToken, async (req, res) => {
    try {
        const { frase, categoria, resposta } = req.body;
        if (!frase || !categoria) return res.status(400).json({ error: 'Faltam dados principais para ensinar a IA.' });

        // Agora a IA recebe a frase, a categoria, e a resposta que deve dar!
        const resultadoAprendizagem = await PttAIEngine.ensinarNovaFrase(frase, categoria, resposta);

        res.json({ success: true, mensagem: resultadoAprendizagem });
    } catch (error) {
        console.error("🚨 Erro ao ensinar a Ptt AI:", error);
        res.status(500).json({ success: false, error: 'Erro ao treinar o cérebro.' });
    }
});

// 3. Rota para o Professor (O Paulo) ensinar CORREÇÕES ORTOGRÁFICAS
router.post('/ingles/ia-teste/ensinar-correcao', verificarToken, async (req, res) => {
    try {
        const { erro, certo } = req.body;
        if (!erro || !certo) return res.status(400).json({ error: 'Faltam dados para ensinar a correção.' });

        // A IA guarda a regra ortográfica
        const resultadoAprendizagem = await PttAIEngine.ensinarCorrecao(erro, certo);

        res.json({ success: true, mensagem: resultadoAprendizagem });
    } catch (error) {
        console.error("🚨 Erro ao ensinar correção:", error);
        res.status(500).json({ success: false, error: 'Erro ao treinar o olheiro ortográfico.' });
    }
});

// ============================================================================
// 🚀 ROTA DA IA GERATIVA PREMIUM (GROQ) - COM MEMÓRIA ATIVADA
// ============================================================================
router.post('/ingles/ia-teste/groq', verificarToken, async (req, res) => {
    try {
        // 1. CAPTURA DE DADOS: Agora recebemos a 'mensagem' e o 'historico'.
        // Se for a primeira mensagem, o historico será um array vazio [].
        const { mensagem, historico = [] } = req.body;
        
        if (!mensagem) return res.status(400).json({ error: 'Mensagem vazia.' });

        // 2. CARREGAMENTO DINÂMICO E SEGURANÇA
        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;

        if (!chaveApi) {
            console.error("🚨 ERRO: A chave GROQ_API_KEY não foi encontrada no servidor!");
            return res.status(500).json({ success: false, error: 'A chave API não está configurada no servidor (.env ou Render).' });
        }

        const groq = new Groq({ apiKey: chaveApi.trim() });

        // 3. SYSTEM PROMPT (A alma do professor)
        const INSTRUCOES_PROFESSOR = `
            You are 'Ptt AI', an expert, friendly, and highly motivating English teacher.
            Follow these rules strictly:
            1. Maintain a positive, didactic, and helpful tone.
            2. If the student makes a grammatical or spelling mistake, kindly correct them first, explain the rule briefly, and then answer their message.
            3. Do not answer questions outside the scope of English learning. If asked about other subjects, politely redirect the conversation back to English practice.
            4. Keep your answers relatively short (max 3-4 sentences) so the student is not overwhelmed.
            5. Always end by asking a question to keep the conversation flowing.
        `;

        // 4. A FUSÃO DA MEMÓRIA 🧠
        // Construímos a ordem cronológica perfeita para a IA ler:
        const mensagensParaNuvem = [
            { role: 'system', content: INSTRUCOES_PROFESSOR }, // Regras primeiro
            ...historico,                                      // Espalha as mensagens anteriores aqui (Memória)
            { role: 'user', content: mensagem }                // Adiciona a nova mensagem no fim
        ];

        // 5. PROCESSAMENTO NA NUVEM
        const respostaGroq = await groq.chat.completions.create({
            messages: mensagensParaNuvem, // Passamos o pacote completo (Regras + Memória + Nova Mensagem)
            
            // Usando o modelo escolhido e funcional
            model: 'openai/gpt-oss-120b', 
            temperature: 0.7,
        });

        // 6. DEVOLUÇÃO
        const textoGerado = respostaGroq.choices[0]?.message?.content || 'A IA ficou sem palavras.';
        res.json({ success: true, resposta: textoGerado });

    } catch (error) {
        console.error("🚨 Erro no Motor Groq:", error);
        res.status(500).json({ success: false, error: 'Falha de comunicação com a Nuvem da Inteligência Artificial.' });
    }
});

// ============================================================================
// 🎮 ROTA GENÉRICA DE AVALIAÇÃO DOS JOGOS COM IA (Atualizada e Robusta)
// ============================================================================
router.post('/ingles/jogo/avaliar', verificarToken, async (req, res) => {
    try {
        const { jogo, palavra, fraseAluno, cenario, pergunta, tarefaEspecifica, respostaAluno, historico = [] } = req.body;
        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        
        if (!chaveApi) return res.status(500).json({ success: false, error: 'Chave API em falta' });
        
        const groq = new Groq({ apiKey: chaveApi.trim() });

        let systemPrompt = "";
        let userPrompt = "";

        // 🪄 Jogo 1: Feitiço das Palavras (Formar Frase com palavra)
        if (jogo === 'wordSpark') {
            systemPrompt = `Você é um professor de inglês amigável avaliando a frase de um aluno. A palavra obrigatória era "${palavra}".
            Regras:
            1. Verifique se o aluno usou a palavra (ou variação correta) e se a frase faz sentido.
            2. Seja flexível com pequenos erros ortográficos secundários.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Curto elogio ou explicação em PT-BR", "correcao": "Frase ideal em inglês", "coins": 50}`;
            userPrompt = fraseAluno;
        }
        
        // 📜 Jogo 2: Pergaminho do Herói (Perguntas e Respostas abertas)
        if (jogo === 'answerQuest') {
            systemPrompt = `Você é um professor de inglês. 
            Pergunta proposta: "${pergunta}" 
            Resposta do aluno: "${respostaAluno}"
            Regras:
            1. Verifique se a resposta tem sentido e responde à pergunta em inglês.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Feedback em PT-BR", "correcao": "Versão mais natural da resposta", "coins": 50}`;
            userPrompt = respostaAluno;
        }

        // 🌀 Jogo 3: Labirinto Ilusório (Transformação de Frases / Sentence Shuffle)
        if (jogo === 'sentenceShuffle') {
            systemPrompt = `Você é um professor de inglês avaliando transformação de frases.
            Frase original: "${pergunta}"
            Instrução aplicada: "${tarefaEspecifica}"
            Resposta enviada pelo aluno: "${respostaAluno}"
            Regras:
            1. Verifique se o aluno aplicou corretamente a instrução ("${tarefaEspecifica}") sobre a frase original.
            2. Se a estrutura gramatical estiver correta, "correto" é true.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Explicação curta em PT-BR", "correcao": "A frase transformada perfeitamente", "coins": 50}`;
            userPrompt = respostaAluno;
        }

        // 🔮 Jogo 4: Espelho do Oráculo (Question Maker)
        if (jogo === 'questionMaker') {
            systemPrompt = `Você é um professor de inglês rigoroso, mas justo.
            A seguinte RESPOSTA foi dada ao aluno: "${pergunta}" (Sim, a variável chama-se pergunta, mas trata-se da resposta base).
            A PERGUNTA que o aluno formulou foi: "${respostaAluno}"
            Regras de avaliação:
            1. Verifique se a PERGUNTA criada pelo aluno é gramaticalmente correta em inglês.
            2. Verifique se essa pergunta faria sentido lógico para obter a resposta base.
            3. Aceite diferentes formas de perguntar, desde que a lógica se mantenha.
            4. Se houver erro, preencha o campo "correcao" com a pergunta ideal.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Avaliação curta em PT-BR", "correcao": "A pergunta ideal", "coins": 50}`;
            userPrompt = respostaAluno;
        }

        // 🎭 Jogo 5: Manto do Metamorfo (Roleplay conversacional)
        if (jogo === 'contextRole') {
            systemPrompt = `You are an actor in an English roleplay. 
            Scenario: "${cenario?.title}" - "${cenario?.prompt}". 
            History: ${JSON.stringify(historico.slice(-4))}
            Student said: "${respostaAluno}"
            Rules:
            1. "correto" is ALWAYS true unless they speak pure nonsense.
            2. Continue the roleplay naturally in character ("npcResponse"). Keep it to 1 sentence and end with a question.
            3. If there is a grammar error, put a short fix in "correcao", else null.
            Return ONLY JSON: {"correto": true, "feedback": "Short PT-BR encouragement", "correcao": "correction or null", "npcResponse": "Your next character line in English"}`;
            userPrompt = respostaAluno;
        }

        const completion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt }
            ],
            model: 'openai/gpt-oss-120b',
            temperature: 0.3,
            response_format: { type: 'json_object' } 
        });

        let resultadoTexto = completion.choices[0].message.content;
        let resultado;
        try {
            resultado = JSON.parse(resultadoTexto);
        } catch(parseErr) {
            resultado = { correto: false, feedback: "Houve um pequeno desvio na avaliação.", correcao: "Tente enviar novamente." };
        }

        res.json({ success: true, ...resultado });

    } catch (e) {
        console.error("Erro jogo IA:", e);
        res.status(500).json({ success: false, error: 'Falha na IA do jogo' });
    }
});


// ============================================================================
// 🚀 LOUSA DIGITAL - ROTAS FINAIS v3 - SEM FALLBACK GLOBAL QUE TRAVA EM TRUE
// ============================================================================

// PUT - Professor ativa/desativa
router.put('/sala/workspace-lousa/status', verificarToken, async (req, res) => {
    try {
        const { turmaId, ativa, recursos, escolaId } = req.body;
        if (!turmaId) return res.status(400).json({ success: false, error: 'turmaId é obrigatório' });
        
        const database = await connectDB();
        const idLimpo = String(turmaId).trim();
        const escolaFinal = escolaId || req.query.escolaId || req.body.escolaId || req.usuario?.escolaId || 'DEFAULT';
        
        let turmaDoc = null;
        try { turmaDoc = await database.collection('turmas').findOne({ $or: [{ id: idLimpo }, { nome: idLimpo }] }); } catch(e){}
        const nomeTurma = turmaDoc?.nome || null;

        // 1. Salva para ID limpo
        await database.collection('workspace_lousa_status').updateOne(
            { id: idLimpo },
            { $set: { 
                id: idLimpo, 
                nome: nomeTurma, 
                ativa: !!ativa, 
                recursos: !!recursos, 
                lousaAtiva: !!ativa, 
                lousaRecursos: !!recursos, 
                atualizadoEm: new Date().toISOString(), 
                escolaId: escolaFinal, 
                professorId: req.usuario?.id || null 
            }},
            { upsert: true }
        );

        // 2. Se tem nome diferente, salva para nome também
        if(nomeTurma && nomeTurma !== idLimpo){
            await database.collection('workspace_lousa_status').updateOne(
                { id: nomeTurma },
                { $set: { 
                    id: nomeTurma, 
                    idOriginal: idLimpo, 
                    nome: nomeTurma, 
                    ativa: !!ativa, 
                    recursos: !!recursos, 
                    lousaAtiva: !!ativa, 
                    lousaRecursos: !!recursos, 
                    atualizadoEm: new Date().toISOString(), 
                    escolaId: escolaFinal 
                }},
                { upsert: true }
            );
        }

        // 3. Se desativou, LIMPA TUDO: status e dados
        if(!ativa){
            try{
                // Apaga status da turma
                await database.collection('workspace_lousa_status').deleteOne({ id: idLimpo });
                if(nomeTurma && nomeTurma !== idLimpo) await database.collection('workspace_lousa_status').deleteOne({ id: nomeTurma });
                // Apaga dados da lousa
                await database.collection('workspace_lousa_dados').deleteOne({ id: idLimpo });
                if(nomeTurma && nomeTurma !== idLimpo) await database.collection('workspace_lousa_dados').deleteOne({ id: nomeTurma });
                // IMPORTANTE: também apaga global se foi a última turma ativa
                const restantes = await database.collection('workspace_lousa_status').countDocuments({ ativa: true });
                if(restantes === 0){
                    await database.collection('workspace_lousa_status').deleteOne({ id: 'global' });
                }
                console.log(`[LOUSA] Encerrada e limpa turma ${idLimpo} nome=${nomeTurma} restantes ativas=${restantes}`);
            }catch(e){ console.warn('Erro limpar ao desativar', e); }
        }

        // 4. Broadcast
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { 
                type: 'LOUSA_STATUS_CHANGED', 
                turmaId: idLimpo, 
                turmaNome: nomeTurma, 
                ativa: !!ativa, 
                recursos: !!recursos, 
                escolaId: escolaFinal 
            });
        }

        res.json({ success: true, turmaId: idLimpo, turmaNome: nomeTurma, ativa: !!ativa, recursos: !!recursos });
    } catch (e) {
        console.error('🚨 Erro PUT lousa:', e);
        res.status(500).json({ success: false, error: 'Erro ao sincronizar lousa.' });
    }
});

// GET - Aluno verifica status - SEM fallback global travado
router.get('/sala/workspace-lousa/status/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const turmaIdReq = String(req.params.turmaId || 'global').trim();

        // 1. Busca direta
        let status = await database.collection('workspace_lousa_status').findOne({ id: turmaIdReq });

        // 2. Se não achou, tenta por nome ou idOriginal
        if(!status){
            status = await database.collection('workspace_lousa_status').findOne({ 
                $or: [{ nome: turmaIdReq }, { idOriginal: turmaIdReq }] 
            });
        }

        // 3. Se ainda não achou e turmaIdReq é um ID, busca turma para resolver nome
        if(!status){
            const turmaDoc = await database.collection('turmas').findOne({ $or: [{ id: turmaIdReq }, { nome: turmaIdReq }] });
            if(turmaDoc){
                status = await database.collection('workspace_lousa_status').findOne({ 
                    $or: [{ id: turmaDoc.id }, { id: turmaDoc.nome }, { idOriginal: turmaDoc.id }] 
                });
            }
        }

        // 4. Só usa global se solicitou global
        if(!status && turmaIdReq === 'global'){
            status = await database.collection('workspace_lousa_status').findOne({ id: 'global' });
        }

        // Se não achou nada, está desativada
        const ativa = !!(status?.ativa || status?.lousaAtiva);
        const recursos = !!(status?.recursos || status?.lousaRecursos);

        console.log(`[LOUSA GET v3] turma=${turmaIdReq} found=${status?.id || 'none'} ativa=${ativa}`);

        res.json({ 
            success: true, 
            ativa, 
            recursos, 
            turmaId: turmaIdReq,
            statusId: status?.id || null,
            debug: { requested: turmaIdReq, found: status?.id || null, ativa }
        });
    } catch (e) {
        console.error('🚨 Erro GET lousa v3:', e);
        res.status(500).json({ success: false, ativa: false, recursos: false });
    }
});

// DELETE - Limpa TUDO (use para reset)
router.delete('/sala/workspace-lousa/status/tudo', verificarToken, async (req, res) => {
    try{
        const db = await connectDB();
        const r1 = await db.collection('workspace_lousa_status').deleteMany({});
        const r2 = await db.collection('workspace_lousa_dados').deleteMany({});
        console.log(`[LOUSA] RESET TOTAL: status ${r1.deletedCount} dados ${r2.deletedCount}`);
        res.json({ success:true, deletedStatus: r1.deletedCount, deletedDados: r2.deletedCount });
    }catch(e){
        console.error('Erro DELETE tudo', e);
        res.status(500).json({ success:false });
    }
});

// Dados - O Filtro Destrutivo foi removido!
router.put('/sala/workspace-lousa/dados/:turmaId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const turmaId = String(req.params.turmaId).trim();
        const { records } = req.body;
        if(!turmaId) return res.status(400).json({ success:false });
        
        // Só salva se status estiver ativo
        const status = await db.collection('workspace_lousa_status').findOne({ 
            $or: [{ id: turmaId }, { nome: turmaId }, { idOriginal: turmaId }] 
        });
        if(!status?.ativa){
            return res.json({ success:false, error:'Lousa não está ativa' });
        }

        // 🚀 O FILTRO FOI REMOVIDO: Salvamos a "records" integral para proteger a estrutura do Tldraw
        await db.collection('workspace_lousa_dados').updateOne(
            { id: turmaId },
            { $set: { id: turmaId, records: records || [], atualizadoEm: new Date().toISOString() } },
            { upsert: true }
        );
        res.json({ success:true, count: (records||[]).length });
    } catch(e){ res.status(500).json({ success:false }); }
});

router.get('/sala/workspace-lousa/dados/:turmaId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const turmaId = String(req.params.turmaId).trim();
        const doc = await db.collection('workspace_lousa_dados').findOne({ id: turmaId });
        res.json({ success:true, turmaId, records: doc?.records || [] });
    } catch(e){ res.status(500).json({ success:false, records:[] }); }
});

module.exports = router;