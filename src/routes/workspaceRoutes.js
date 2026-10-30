const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const multerCloudinary = require('multer-storage-cloudinary');
const CloudinaryStorage = multerCloudinary.CloudinaryStorage || multerCloudinary;
const fs = require('fs');
const os = require('os');

const { enviarParaR2 } = require('../config/cloudflareR2');
const { filtroTenant } = require('../middlewares/auth');

// 🛡️ FILTRO GLOBAL DE ALUNOS ATIVOS: Ignora alunos Cancelados, Trancados, Excluídos ou Inativos em todo o WorkSpace
const ehAlunoAtivo = (aluno) => {
    if (!aluno) return false;
    const st = String(aluno.status || 'Ativo').trim().toLowerCase();
    if (st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist')) {
        return false;
    }
    return st === 'ativo' || st === '';
};

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
    
    // A presença online passa a ser controlada EXCLUSIVAMENTE pelo Heartbeat (/ping) e só quando a aba está aberta.
    next();
};

// ============================================================================
// 🚀 TÚNEL DE CONEXÃO EM TEMPO REAL E VIA VERDE
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
        
        if (!nomeFicheiro || !tipoFicheiro) {
            return res.status(400).json({ error: 'Faltam dados do ficheiro para gerar a autorização.' });
        }

        // 🚀 BLINDAGEM DE NUVEM: Remove espaços e acentos que quebram o link na Cloudflare R2!
        const nomeSeguro = String(nomeFicheiro).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const nomeFinal = `doc_${Date.now()}_${nomeSeguro}`;

        const { gerarLinkUploadDireto } = require('../config/cloudflareR2');
        const dadosAutorizacao = await gerarLinkUploadDireto(nomeFinal, tipoFicheiro);

        res.status(200).json({ success: true, ...dadosAutorizacao });
    } catch (erro) {
        console.error('🚨 Erro na Via Verde:', erro);
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
                const promessasUpload = req.files.map(file => {
                    return new Promise(async (resolve, reject) => { 
                        try {
                            let nomeOriginal = file.originalname || `ficheiro_${Date.now()}.jpg`;
                            let nomeSeguro = String(nomeOriginal).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
                            
                            const ehDocumento = nomeSeguro.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|pps|ppsx|txt|zip|rar|csv)$/i);
                            
                            if (ehDocumento) {
                                try {
                                    console.log(`🚀 Enviando DOCUMENTO para Cloudflare R2: ${nomeSeguro}`);
                                    const fileStream = fs.createReadStream(file.path);
                                    const urlR2 = await enviarParaR2(fileStream, nomeOriginal, file.mimetype);
                                    resolve({ url: urlR2, nome: file.originalname, tipo: file.mimetype });
                                } finally {
                                    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                                }
                           } else {
                                console.log(`📸 Enviando MULTIMÉDIA para Cloudinary: ${nomeSeguro}`);
                                let recursoTipo = 'auto'; 
                                if (file.mimetype.startsWith('video/') || file.mimetype.startsWith('audio/')) {
                                    recursoTipo = 'video';
                                } else if (file.mimetype.startsWith('image/')) {
                                    recursoTipo = 'image';
                                }
                                
                                let publicId = `${Date.now()}_${nomeSeguro.split('.')[0]}`;

                                cloudinary.uploader.upload(file.path, { folder: 'workspace_escola', resource_type: recursoTipo, public_id: publicId }, (error, result) => {
                                    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                                    
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
        const resultado = await cloudinary.api.ping();
        res.status(200).json({
            success: true,
            mensagem: "✅ Conexão com o Cloudinary estabelecida com sucesso!",
            detalhes: resultado
        });
    } catch (error) {
        console.error("🚨 Erro no Ping do Cloudinary:", error);
        res.status(500).json({
            success: false,
            mensagem: "❌ Falha de comunicação com o Cloudinary.",
            erro: error.message || error
        });
    }
});

// ============================================================================
// 💬 CHAT DO FÓRUM (COM TEMPO REAL E INDICADOR DE DIGITAÇÃO)
// ============================================================================
router.get('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mensagens = await database.collection('workspace_chats').find({ turmaId: req.params.turmaId }).sort({ data: 1 }).toArray();
        res.status(200).json(mensagens);
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar o chat.' }); }
});

router.post('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, anexoUrl, anexoTipo, anexoNome, escolaId, turmaNome } = req.body;
        const database = await connectDB();
        const turmaId = req.params.turmaId;
        
        const novaMensagem = { 
            id: crypto.randomUUID(), 
            turmaId: turmaId, 
            autorNome: autorNome || 'Desconhecido', 
            texto: texto || '', 
            anexoUrl: anexoUrl || null,
            anexoTipo: anexoTipo || null,
            anexoNome: anexoNome || null,
            data: new Date().toISOString() 
        };
        
        await database.collection('workspace_chats').insertOne(novaMensagem);
        
        // Dispara o Evento ao Vivo para quem está Online
        workspaceStream.emit('evento_realtime', { 
            type: 'NOVA_MENSAGEM', 
            turmaId: turmaId,
            turmaNome: turmaNome || 'Fórum da Turma', 
            mensagem: novaMensagem,
            escolaId: escolaId || 'DEFAULT'
        });

        // ====================================================================
        // 🚀 VARREDURA COMPLETA: Geração de Notificações Offline
        // ====================================================================
        try {
            const nomeTurmaOficial = turmaNome || 'Fórum da Turma';
            const idTurmaLower = String(turmaId).toLowerCase().trim();
            const nomeTurmaLower = String(nomeTurmaOficial).toLowerCase().trim();
            const isGlobal = idTurmaLower === 'global' || idTurmaLower === 'geral';

           // Puxa Utilizadores e Alunos ATIVOS para cruzar os dados
            const usuarios = await database.collection('usuarios').find({}).toArray();
            const alunosBrutos = await database.collection('alunos').find({}).toArray();
            const alunos = alunosBrutos.filter(ehAlunoAtivo);
            const idsAlunosInativos = new Set(alunosBrutos.filter(a => !ehAlunoAtivo(a)).map(a => String(a.id)));
            
            const destinatarios = new Set();
            const remetenteLimpo = String(novaMensagem.autorNome).trim();

            usuarios.forEach(user => {
                const nomeDeLogin = (user.nome || user.login || '').trim();
                if (!nomeDeLogin || nomeDeLogin === remetenteLimpo) return;
                if (user.alunoRefId && idsAlunosInativos.has(String(user.alunoRefId))) return;                

                if (user.tipo === 'Professor' || user.tipo === 'Gestor') {
                    destinatarios.add(nomeDeLogin);
                } else if (user.tipo === 'Aluno') {
                    let turmasDoAluno = [];
                    
                    // 1. Busca turmas diretamente no documento do Utilizador
                    if (user.turma) turmasDoAluno.push(user.turma);
                    if (user.turmas) {
                        if (Array.isArray(user.turmas)) turmasDoAluno.push(...user.turmas);
                        else turmasDoAluno.push(user.turmas);
                    }
                    
                    // 2. Busca turmas no documento oficial do Aluno (alunoRefId)
                    if (user.alunoRefId) {
                        const perfilAluno = alunos.find(a => String(a.id) === String(user.alunoRefId));
                        if (perfilAluno) {
                            if (perfilAluno.turma) turmasDoAluno.push(perfilAluno.turma);
                            if (perfilAluno.turmaId) turmasDoAluno.push(perfilAluno.turmaId);
                            if (perfilAluno.turmas) {
                                if (Array.isArray(perfilAluno.turmas)) turmasDoAluno.push(...perfilAluno.turmas);
                                else turmasDoAluno.push(perfilAluno.turmas);
                            }
                        }
                    }

                    // Verifica se o aluno pertence à turma do bate-papo
                    const pertence = isGlobal || turmasDoAluno.some(t => {
                        if (!t) return false;
                        const tLower = String(t).toLowerCase().trim();
                        return tLower === idTurmaLower || tLower === nomeTurmaLower;
                    });

                    if (pertence) {
                        destinatarios.add(nomeDeLogin);
                    }
                }
            });

            let textoResumo = texto || (anexoNome ? `Enviou um arquivo: ${anexoNome}` : 'Partilhou um anexo');
            textoResumo = textoResumo.length > 35 ? textoResumo.substring(0, 35) + '...' : textoResumo;

            const notificacoesArray = Array.from(destinatarios).map(dest => ({
                id: 'notif_chat_' + Date.now() + '_' + Math.random().toString(36).substring(7),
                escolaId: escolaId || 'DEFAULT',
                destinatarioNome: dest,
                remetenteNome: novaMensagem.autorNome,
                mensagem: `enviou uma mensagem lá no chat: "${textoResumo}"`,
                origem: 'chat',
                origemId: turmaId,
                destinoNome: nomeTurmaOficial,
                lida: false,
                data: new Date().toISOString()
            }));

            if (notificacoesArray.length > 0) {
                await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
            }
        } catch (erroNotificacao) {
            console.error("Falha ao gerar notificação de chat:", erroNotificacao);
        }
        // ====================================================================

        res.status(201).json({ success: true, mensagem: novaMensagem });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao enviar mensagem.' }); 
    }
});

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
        const { texto, autorNome, autorTipo, escolaId, anexos, destino, destinoNome, categoria } = req.body;
        if (!texto && (!anexos || anexos.length === 0)) return res.status(400).json({ error: 'Vazio.' });

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(), escolaId: escolaId || 'DEFAULT', autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor', destino: destino || 'global', destinoNome: destinoNome || 'Público Geral',
            categoria: categoria || 'normal', // 🚀 NOVO: Guarda a categoria do post (Música ou Normal)
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
        const posts = await database.collection('workspace_posts').find(filtro).sort({ fixado: -1, dataCriacao: -1 }).limit(50).toArray();
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
                origemId: `${postId}|${novoComentario.id}`, 
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

        await database.collection('workspace_posts').updateOne(
            { id: postId, "comentarios.id": comentarioId },
            { $set: { "comentarios.$.likes": likes, "comentarios.$.dislikes": dislikes } }
        );
        
        workspaceStream.emit('evento_realtime', { type: 'POST_UPDATE', postId: postId, escolaId: post.escolaId });

        if (autorNome && comentario.autorNome !== autorNome && tipo !== 'remove') { 
            const acaoRealizada = tipo === 'like' ? 'curtiu' : 'não curtiu';
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(), escolaId: post.escolaId, destinatarioNome: comentario.autorNome, remetenteNome: autorNome,
                mensagem: `${acaoRealizada} o seu comentário.`, 
                origem: 'comentario_reacao', 
                origemId: `${postId}|${comentarioId}`,
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
        await database.collection('workspace_posts').deleteOne({ id: req.params.id });
        workspaceStream.emit('evento_realtime', { type: 'POST_APAGADO', postId: req.params.id, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_posts').updateOne(
            { id: req.params.id }, 
            { $set: { 
                texto: req.body.texto,
                categoria: req.body.categoria || 'normal'
            } }
        );
        res.status(200).json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro.' }); 
    }
});

// 📌 FIXAR OU DESAFIXAR PUBLICAÇÃO NO TOPO DO FEED
router.put('/posts/:id/fixar', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novoEstadoFixado = Boolean(req.body.fixado);
        const post = await database.collection('workspace_posts').findOne({ id: req.params.id });
        if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });

        await database.collection('workspace_posts').updateOne(
            { id: req.params.id },
            { $set: { fixado: novoEstadoFixado } }
        );

        workspaceStream.emit('evento_realtime', {
            type: 'POST_FIXADO',
            postId: req.params.id,
            fixado: novoEstadoFixado,
            escolaId: post.escolaId || 'DEFAULT'
        });

        res.status(200).json({ success: true, fixado: novoEstadoFixado });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao fixar publicação.' });
    }
});

// 👥 BUSCAR NOMES E FOTOS DE QUEM CURTIU / REAGIU A UMA PUBLICAÇÃO
router.post('/posts/reacoes-detalhes', verificarToken, async (req, res) => {
    try {
        const { likesIds = [], dislikesIds = [] } = req.body;
        const todosIds = Array.from(new Set([...likesIds, ...dislikesIds].map(id => String(id))));

        if (todosIds.length === 0) {
            return res.status(200).json({ success: true, likes: [], dislikes: [] });
        }

        const database = await connectDB();
        const usuarios = await database.collection('usuarios').find({
            $or: [{ id: { $in: todosIds } }, { alunoRefId: { $in: todosIds } }]
        }).toArray();

        const mapaUsuarios = {};
        usuarios.forEach(u => {
            const info = {
                id: u.id,
                nome: u.nome || u.login || 'Membro',
                tipo: u.tipo || 'Aluno',
                avatar: u.avatar || null
            };
            if (u.id) mapaUsuarios[String(u.id)] = info;
            if (u.alunoRefId) mapaUsuarios[String(u.alunoRefId)] = info;
        });

        const likesDetalhados = likesIds.map(id => mapaUsuarios[String(id)] || { id, nome: 'Membro da Escola', tipo: 'Aluno', avatar: null });
        const dislikesDetalhados = dislikesIds.map(id => mapaUsuarios[String(id)] || { id, nome: 'Membro da Escola', tipo: 'Aluno', avatar: null });

        res.status(200).json({ success: true, likes: likesDetalhados, dislikes: dislikesDetalhados });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar detalhes das reações.' });
    }
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
// 🔄 MOTOR DE AUTO-CURA RETROATIVA (CURA NOMES E FOTOS ALTERADOS NO PASSADO)
// ============================================================================
let _autoCuraExecutada = false;
async function executarAutoCuraRetroativa(database) {
    if (_autoCuraExecutada) return;
    _autoCuraExecutada = true;
    try {
        const usuarios = await database.collection('usuarios').find({}).toArray();
        const alunos = await database.collection('alunos').find({}).toArray();

        for (const u of usuarios) {
            const fichaAluno = alunos.find(a =>
                (u.alunoRefId && (String(a.id) === String(u.alunoRefId) || String(a._id) === String(u.alunoRefId))) ||
                (u.id && String(a.id) === String(u.id)) ||
                (u.login && a.login && String(a.login).toLowerCase().trim() === String(u.login).toLowerCase().trim())
            );

            const nomeEscolhido = String(u.nome || u.login || '').trim();
            const fotoAtual = u.avatar || (fichaAluno && fichaAluno.avatar) || null;

            // 1. Garante que a foto está sincronizada em ambas as coleções
            if (fotoAtual) {
                if (!u.avatar) {
                    await database.collection('usuarios').updateOne({ id: u.id }, { $set: { avatar: fotoAtual } });
                }
                if (fichaAluno && !fichaAluno.avatar) {
                    await database.collection('alunos').updateOne({ id: fichaAluno.id }, { $set: { avatar: fotoAtual } });
                }
            }

            // 2. Atualiza registos antigos (incluindo nomes completos da matrícula ou formatos "Nome Completo (@Apelido)")
            if (nomeEscolhido) {
                const variacoesAntigas = [
                    fichaAluno ? fichaAluno.nome : null,
                    u.login,
                    fichaAluno && fichaAluno.nome ? `${fichaAluno.nome.trim()} (@${nomeEscolhido})` : null
                ]
                    .map(n => String(n || '').trim())
                    .filter(n => n && n.toLowerCase() !== nomeEscolhido.toLowerCase());

                const regexesAntigos = variacoesAntigas.map(n => {
                    const escapado = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    return new RegExp(`^\\s*${escapado}(?:\\s*\\(@.*\\))?\\s*$`, 'i');
                });

                // Adiciona também regex para "Nome Escolhido (@...)" caso exista
                const nomeEscapado = nomeEscolhido.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                regexesAntigos.push(new RegExp(`^\\s*${nomeEscapado}\\s*\\(@.*\\)\\s*$`, 'i'));

                if (regexesAntigos.length > 0) {
                    const setNotiRemetente = { remetenteNome: nomeEscolhido };
                    if (fotoAtual) setNotiRemetente.remetenteAvatar = fotoAtual;

                    await database.collection('workspace_notificacoes').updateMany(
                        { remetenteNome: { $in: regexesAntigos } },
                        { $set: setNotiRemetente }
                    );
                    await database.collection('workspace_notificacoes').updateMany(
                        { destinatarioNome: { $in: regexesAntigos } },
                        { $set: { destinatarioNome: nomeEscolhido } }
                    );
                    await database.collection('workspace_posts').updateMany(
                        { autorNome: { $in: regexesAntigos } },
                        { $set: { autorNome: nomeEscolhido } }
                    );
                    await database.collection('workspace_chats').updateMany(
                        { autorNome: { $in: regexesAntigos } },
                        { $set: { autorNome: nomeEscolhido } }
                    );
                    await database.collection('workspace_entregas').updateMany(
                        { alunoNome: { $in: regexesAntigos } },
                        { $set: { alunoNome: nomeEscolhido } }
                    );
                    await database.collection('workspace_entregas_provas').updateMany(
                        { alunoNome: { $in: regexesAntigos } },
                        { $set: { alunoNome: nomeEscolhido } }
                    );
                }

                // Se a notificação já está com o nome escolhido mas ainda não tinha a foto gravada nela, injeta a foto!
                if (fotoAtual) {
                    await database.collection('workspace_notificacoes').updateMany(
                        { remetenteNome: new RegExp(`^\\s*${nomeEscapado}\\s*$`, 'i') },
                        { $set: { remetenteNome: nomeEscolhido, remetenteAvatar: fotoAtual } }
                    );
                }

                await database.collection('workspace_ingles_stats').updateMany(
                    { userId: String(u.id) },
                    { $set: { nome: nomeEscolhido } }
                );
            }
        }
        console.log("✅ Auto-Cura Retroativa concluída com sucesso!");
    } catch (e) {
        _autoCuraExecutada = false;
        console.error("Aviso na Auto-Cura Retroativa:", e);
    }
}

router.get('/notificacoes/:nomeDono', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await executarAutoCuraRetroativa(database);

        const nomeRecebido = String(req.params.nomeDono ? req.params.nomeDono : '').trim();
        const usuarios = await database.collection('usuarios').find({}).toArray();
        const alunos = await database.collection('alunos').find({}).toArray();

        // 1. Dicionário inteligente que mapeia ID, Nome Completo, Login e Nome Escolhido -> { nomeAtual, avatar }
        const mapaIdentidade = {};
        const mapaPorId = {};

        const registarVariacao = (chave, nomeEscolhidoAtual, avatarOficial) => {
            if (!chave) return;
            const k = String(chave).trim().toLowerCase();
            if (!k) return;
            const existente = mapaIdentidade[k];
            mapaIdentidade[k] = {
                nomeAtual: nomeEscolhidoAtual || (existente && existente.nomeAtual),
                avatar: avatarOficial || (existente && existente.avatar) || null
            };
        };

        // Primeiro mapeia a ficha bruta de alunos como base
        alunos.forEach(a => {
            const k = String(a.nome || '').trim().toLowerCase();
            if (k) {
                registarVariacao(a.nome, a.nome.trim(), a.avatar || null);
            }
            if (a.id) {
                mapaPorId[String(a.id)] = { nomeAtual: String(a.nome || '').trim(), avatar: a.avatar || null };
            }
        });

        // Em seguida, 'usuarios' (onde mora o Nome Escolhido pelo aluno no Perfil e a Foto dele) tem PRIORIDADE TOTAL!
        usuarios.forEach(u => {
            const fichaAluno = alunos.find(a =>
                (u.alunoRefId && (String(a.id) === String(u.alunoRefId) || String(a._id) === String(u.alunoRefId))) ||
                (u.id && String(a.id) === String(u.id)) ||
                (u.login && a.login && String(a.login).toLowerCase().trim() === String(u.login).toLowerCase().trim()) ||
                (u.nome && a.nome && String(a.nome).toLowerCase().trim() === String(u.nome).toLowerCase().trim())
            );

            const nomeEscolhido = String(u.nome || (fichaAluno && fichaAluno.nome) || u.login || '').trim();
            const avatarAtual = u.avatar || (fichaAluno && fichaAluno.avatar) || null;

            if (u.id) mapaPorId[String(u.id)] = { nomeAtual: nomeEscolhido, avatar: avatarAtual };
            if (u.alunoRefId) mapaPorId[String(u.alunoRefId)] = { nomeAtual: nomeEscolhido, avatar: avatarAtual };

            registarVariacao(u.nome, nomeEscolhido, avatarAtual);
            registarVariacao(u.login, nomeEscolhido, avatarAtual);
            if (fichaAluno && fichaAluno.nome) {
                // Mapeia o Nome Completo da matrícula para apontar SEMPRE para o Nome Escolhido no Perfil!
                mapaIdentidade[String(fichaAluno.nome).trim().toLowerCase()] = {
                    nomeAtual: nomeEscolhido,
                    avatar: avatarAtual || mapaIdentidade[String(fichaAluno.nome).trim().toLowerCase()]?.avatar || null
                };
            }
        });

        // 2. Descobre todos os nomes possíveis do dono do Sininho (nome escolhido, login e nome completo de matrícula)
        const nomesDoDono = new Set([nomeRecebido]);
        const userDono = usuarios.find(u =>
            String(u.nome || '').trim().toLowerCase() === nomeRecebido.toLowerCase() ||
            String(u.login || '').trim().toLowerCase() === nomeRecebido.toLowerCase()
        );
        if (userDono) {
            if (userDono.nome) nomesDoDono.add(userDono.nome.trim());
            if (userDono.login) nomesDoDono.add(userDono.login.trim());
            if (userDono.alunoRefId) {
                const alunoDono = alunos.find(a => String(a.id) === String(userDono.alunoRefId) || String(a._id) === String(userDono.alunoRefId));
                if (alunoDono && alunoDono.nome) nomesDoDono.add(alunoDono.nome.trim());
            }
        }

        const regexesDono = Array.from(nomesDoDono).map(n => {
            const limpo = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return new RegExp(`^\\s*${limpo}\\s*$`, 'i');
        });

        const notificacoes = await database.collection('workspace_notificacoes').find({
            $or: [
                { destinatarioNome: { $in: regexesDono } },
                { loginDestino: { $in: regexesDono } }
            ],
            lida: false
        }).sort({ data: -1 }).toArray();

        // 3. Traduz qualquer remetente (mesmo "Nome Completo" ou "Nome Completo (@Apelido)") para o Nome Escolhido e Foto Atual!
        const notificacoesCuradas = notificacoes.map(n => {
            const remBruto = String(n.remetenteNome || '').trim();
            const matchApelido = remBruto.match(/^(.*?)\s*\(@([^)]+)\)\s*$/);
            const parteNomeCompleto = matchApelido ? matchApelido[1].trim().toLowerCase() : remBruto.toLowerCase();
            const parteApelido = matchApelido ? matchApelido[2].trim().toLowerCase() : null;

            const infoRem = (n.remetenteId && mapaPorId[String(n.remetenteId)])
                || (parteApelido && mapaIdentidade[parteApelido])
                || mapaIdentidade[parteNomeCompleto]
                || mapaIdentidade[remBruto.toLowerCase()]
                || null;

            if (infoRem) {
                return {
                    ...n,
                    remetenteNome: infoRem.nomeAtual || (matchApelido ? matchApelido[2].trim() : n.remetenteNome),
                    remetenteAvatar: infoRem.avatar || n.remetenteAvatar || null
                };
            }
            if (matchApelido) {
                return {
                    ...n,
                    remetenteNome: matchApelido[2].trim()
                };
            }
            return n;
        });

        res.status(200).json(notificacoesCuradas);
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/notificacoes/:id/ler', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_notificacoes').updateOne({ id: req.params.id }, { $set: { lida: true } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.put('/notificacoes/usuario/:nomeDono/ler-todas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const nomeLimpo = String(req.params.nomeDono ? req.params.nomeDono : '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regexNome = new RegExp(`^${nomeLimpo}$`, 'i');
        await database.collection('workspace_notificacoes').updateMany(
            {
                $or: [
                    { destinatarioNome: { $regex: regexNome } },
                    { loginDestino: { $regex: regexNome } }
                ],
                lida: false
            },
            { $set: { lida: true } }
        );
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao limpar notificações.' }); }
});

// ============================================================================
// ⚙️ ROTA DE ALTERAÇÃO DE SENHA, AVATAR E NOME (PERFIL)
// ============================================================================
router.put('/perfil', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, senhaAtual, novaSenha } = req.body;
        const database = await connectDB();
        
        const senhaLimpa = String(senhaAtual || '').trim();
        const novaSenhaLimpa = String(novaSenha || '').trim();

        if (!senhaLimpa || !novaSenhaLimpa) {
            return res.status(400).json({ error: 'Preencha a senha atual e a nova senha.' });
        }

        const user = await database.collection('usuarios').findOne({ id: id });
        if (!user) return res.status(404).json({ error: 'Conta de acesso não encontrada.' });

        let bcrypt;
        try { bcrypt = require('bcrypt'); } catch(e) { try { bcrypt = require('bcryptjs'); } catch(e) { bcrypt = null; } }

        let senhaCorreta = false;
        let novaSenhaParaGuardar = novaSenhaLimpa; 

        if (bcrypt && user.senha && String(user.senha).startsWith('$2')) {
            senhaCorreta = await bcrypt.compare(senhaLimpa, user.senha);
            if (senhaCorreta) novaSenhaParaGuardar = await bcrypt.hash(novaSenhaLimpa, 10);
        } else {
            const senhasValidas = [
                String(user.senha || '').trim(),
                String(user.senha_provisoria || '').trim(),
                String(user.senhaProvisoria || '').trim()
            ].filter(Boolean);
            senhaCorreta = senhasValidas.includes(senhaLimpa) || senhasValidas.includes(String(Number(senhaLimpa)));
            if (senhaCorreta && bcrypt) {
                novaSenhaParaGuardar = await bcrypt.hash(novaSenhaLimpa, 10);
            }
        }

        if (!senhaCorreta) return res.status(400).json({ error: 'A senha atual está incorreta. Verifique e tente novamente.' });

        const updateDoc = {
            $set: { senha: novaSenhaParaGuardar },
            $unset: { senha_provisoria: "", senhaProvisoria: "" } 
        };

        await database.collection('usuarios').updateOne({ id: id }, updateDoc);
        
        const refIdFinal = alunoRefId || user.alunoRefId;
        if (refIdFinal) {
            await database.collection('alunos').updateOne({ id: String(refIdFinal) }, updateDoc);
        }

        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro interno ao tentar atualizar a senha.' }); }
});

router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, avatarUrl } = req.body; 
        const database = await connectDB();

        const user = await database.collection('usuarios').findOne({ id: id });
        await database.collection('usuarios').updateOne({ id: id }, { $set: { avatar: avatarUrl } });

        const refId = alunoRefId || (user && user.alunoRefId ? user.alunoRefId : null);
        if (refId) {
            await database.collection('alunos').updateOne({ id: String(refId) }, { $set: { avatar: avatarUrl } });
        }

        const nomeAtual = user ? (user.nome || user.login) : null;
        const escolaId = user ? (user.escolaId || 'DEFAULT') : 'DEFAULT';

        // Dispara atualização em tempo real para todos os ecrãs abertos
        if (global.workspaceStream && nomeAtual) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'PERFIL_ATUALIZADO',
                userId: id,
                nomeAntigo: nomeAtual,
                novoNome: nomeAtual,
                login: user ? user.login : '',
                avatar: avatarUrl,
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) { res.status(500).json({ error: 'Erro ao guardar a foto de perfil.' }); }
});

// ============================================================================
// 🙍 PERFIL: BUSCAR INFO PÚBLICA E ATUALIZAR BIO
// ============================================================================
router.get('/perfil/info/:identificador', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const idBusca = req.params.identificador;
        
        const user = await database.collection('usuarios').findOne({ $or: [{ id: idBusca }, { nome: idBusca }, { login: idBusca }] });
        const aluno = await database.collection('alunos').findOne({ $or: [{ id: idBusca }, { nome: idBusca }, { login: idBusca }, ...(user && user.alunoRefId ? [{ id: String(user.alunoRefId) }] : [])] });
        
        // Se o aluno foi cancelado/trancado/excluído no sistema principal, avisa o aparelho para encerrar a sessão
        if (aluno && !ehAlunoAtivo(aluno)) {
            return res.status(403).json({ error: 'Matrícula inativa.', revogado: true });
        }

        let perfilFinal = user || aluno;
        
        if (perfilFinal) {
            let stats = perfilFinal.arenaStats;
            if (!stats && user && user.arenaStats) stats = user.arenaStats;
            if (!stats && aluno && aluno.arenaStats) stats = aluno.arenaStats;

            const nomeEscolhido = (user && user.nome) ? user.nome : (perfilFinal.nome || perfilFinal.login || 'Utilizador');
            const avatarReal = (user && user.avatar !== undefined) ? user.avatar : (aluno && aluno.avatar ? aluno.avatar : null);
            const turmaAtual = (aluno && aluno.turma) ? aluno.turma : (user && user.turma ? user.turma : null);
            const turmasAtuais = (aluno && aluno.turmas) ? aluno.turmas : (user && user.turmas ? user.turmas : null);

            res.status(200).json({ 
                success: true, 
                id: user ? user.id : perfilFinal.id,
                alunoRefId: (user && user.alunoRefId) ? user.alunoRefId : (aluno ? aluno.id : null),
                nome: nomeEscolhido,
                login: user ? user.login : perfilFinal.login,
                bio: (user && user.bio !== undefined) ? user.bio : (perfilFinal.bio || "A evoluir e a participar ativamente na nossa comunidade de aprendizagem."),
                tipo: perfilFinal.tipo || "Aluno",
                avatar: avatarReal,
                turma: turmaAtual,
                turmas: turmasAtuais,
                arenaStats: stats || null
            });
        } else {
            res.status(404).json({ error: 'Usuário não encontrado.', revogado: true });
        }
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao buscar perfil.' }); 
    }
});

router.put('/perfil/bio', verificarToken, async (req, res) => {
    try {
        const { id, bio } = req.body;
        const database = await connectDB();
        const bioSegura = String(bio).substring(0, 150);
        
        await database.collection('usuarios').updateOne({ id: id }, { $set: { bio: bioSegura } });
        res.status(200).json({ success: true, bio: bioSegura });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao atualizar a frase de perfil.' }); 
    }
});

// ============================================================================
// ✏️ PERFIL: ALTERAR NOME DO UTILIZADOR E SINCRONIZAR FEED/COMENTÁRIOS
// ============================================================================
router.put('/perfil/nome', verificarToken, async (req, res) => {
    try {
        const { id, novoNome } = req.body;
        
        if (!id || !novoNome) {
            return res.status(400).json({ error: 'Faltam dados obrigatórios para atualizar o nome.' });
        }

        const database = await connectDB();
        const nomeLimpo = String(novoNome).trim();
        
        const userAntigo = await database.collection('usuarios').findOne({ id: id });
        const nomeAntigo = userAntigo ? (userAntigo.nome || userAntigo.login) : null;
        const loginUsuario = userAntigo ? userAntigo.login : null;
        const escolaId = userAntigo ? (userAntigo.escolaId || 'DEFAULT') : 'DEFAULT';

        // 1. Atualiza o nome na coleção 'usuarios' (preservando a coleção 'alunos' da secretaria)
        await database.collection('usuarios').updateOne(
            { id: id },
            { $set: { nome: nomeLimpo } }
        );

        // 2. Atualiza o nome nos Posts, Comentários, Chats e Notificações do Sininho!
        const nomesAnteriores = [nomeAntigo, loginUsuario].filter(Boolean);
        if (nomesAnteriores.length > 0) {
            await database.collection('workspace_posts').updateMany(
                { autorNome: { $in: nomesAnteriores } },
                { $set: { autorNome: nomeLimpo } }
            );

            await database.collection('workspace_posts').updateMany(
                { "comentarios.autorNome": { $in: nomesAnteriores } },
                { $set: { "comentarios.$[elem].autorNome": nomeLimpo } },
                { arrayFilters: [{ "elem.autorNome": { $in: nomesAnteriores } }] }
            );

            await database.collection('workspace_chats').updateMany(
                { autorNome: { $in: nomesAnteriores } },
                { $set: { autorNome: nomeLimpo } }
            );

            // 🔔 Sincroniza o nome nas notificações enviadas e recebidas no Sininho
            await database.collection('workspace_notificacoes').updateMany(
                { remetenteNome: { $in: nomesAnteriores } },
                { $set: { remetenteNome: nomeLimpo } }
            );

            await database.collection('workspace_notificacoes').updateMany(
                { destinatarioNome: { $in: nomesAnteriores } },
                { $set: { destinatarioNome: nomeLimpo } }
            );
        }

        await database.collection('workspace_ingles_stats').updateMany(
            { userId: id },
            { $set: { nome: nomeLimpo } }
        );

        // 3. Descobre o avatar atual (seja de 'usuarios' ou de 'alunos') para enviá-lo já garantido
        let avatarAtual = userAntigo ? userAntigo.avatar : null;
        if (!avatarAtual && userAntigo && userAntigo.alunoRefId) {
            const fichaAluno = await database.collection('alunos').findOne({ id: String(userAntigo.alunoRefId) });
            if (fichaAluno && fichaAluno.avatar) avatarAtual = fichaAluno.avatar;
        }

        // 4. Emite evento em tempo real para atualizar todos os ecrãs instantaneamente
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'PERFIL_ATUALIZADO',
                userId: id,
                nomeAntigo: nomeAntigo,
                novoNome: nomeLimpo,
                login: loginUsuario || '',
                avatar: avatarAtual || null,
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, nomeAntigo: nomeAntigo, novoNome: nomeLimpo, avatar: avatarAtual || null });
    } catch (error) { 
        console.error("Erro ao atualizar o nome:", error);
        res.status(500).json({ error: 'Erro interno ao atualizar o nome na Base de Dados.' }); 
    }
});

// ============================================================================
// 💬 GESTÃO DE FEEDBACKS DO PROFESSOR (EDITAR E APAGAR) E ENTREGAS
// ============================================================================
router.put('/entregas/:entregaId/feedback/:feedbackId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const { texto } = req.body;
        await database.collection('workspace_entregas').updateOne(
            { id: req.params.entregaId, "feedbacks.id": req.params.feedbackId },
            { $set: { "feedbacks.$.texto": texto } }
        );
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

router.post('/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novaEntrega = { ...req.body, id: crypto.randomUUID(), dataEntrega: new Date().toISOString() };
        await database.collection('workspace_entregas').insertOne(novaEntrega);

        try {
            const escolaId = novaEntrega.escolaId || 'DEFAULT';
            const nomeAluno = novaEntrega.alunoNome || 'Um aluno';
            const tituloTarefa = novaEntrega.eventoTitulo || 'uma tarefa';
            const turmaNome = novaEntrega.turmaNome || 'a sua turma';

            const professoresEGestores = await database.collection('usuarios').find({ 
                escolaId: escolaId,
                tipo: { $in: ['Professor', 'Gestor'] }
            }).toArray();

            if (professoresEGestores.length > 0) {
                const nomesDestinatarios = [];
                const notificacoesArray = professoresEGestores.map(prof => {
                    const nomeProf = prof.nome || prof.login;
                    if (nomeProf) nomesDestinatarios.push(nomeProf);
                    return {
                        id: crypto.randomUUID(), escolaId: escolaId, destinatarioNome: nomeProf, remetenteNome: nomeAluno,
                        mensagem: `da turma de <strong>${turmaNome}</strong>, enviou o exercício intitulado <strong>"${tituloTarefa}"</strong> e já está disponível na área de exercícios. Confira 👀`,
                        origem: 'tarefa', origemId: novaEntrega.eventoId, destinoNome: turmaNome, lida: false, data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escolaId });
                }
            }
        } catch (erroNoti) { console.error("Aviso: Falha ao notificar professores sobre a entrega.", erroNoti); }
        res.status(201).json({ success: true, entrega: novaEntrega });
    } catch (error) { res.status(500).json({ error: 'Erro interno.' }); }
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

router.get('/entregas/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const entrega = await db.collection('workspace_entregas').findOne({ id: req.params.id });
        if (!entrega) return res.status(404).json({ error: 'Entrega não encontrada' });
        res.status(200).json({ success: true, entrega });
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar entrega.' }); }
});

router.post('/entregas/:id/feedback', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { texto, professorNome } = req.body;
        const entregaId = req.params.id;

        const entrega = await db.collection('workspace_entregas').findOne({ id: entregaId });
        if (!entrega) return res.status(404).json({ error: 'Entrega não encontrada.' });

        const novoFeedback = { id: crypto.randomUUID(), autorNome: professorNome || 'Professor', texto: texto, data: new Date().toISOString() };

        await db.collection('workspace_entregas').updateOne(
            { id: entregaId },
            { $push: { feedbacks: novoFeedback } }
        );

        const escolaId = entrega.escolaId || 'DEFAULT';
        const eventoId = entrega.eventoId;
        const nomeAluno = entrega.alunoNome;

        const notificacao = {
            id: 'notif_fb_' + Date.now(), escolaId: escolaId, destinatarioNome: nomeAluno, remetenteNome: professorNome,
            mensagem: `avaliou e enviou um feedback no seu exercício: "${entrega.eventoTitulo}"`,
            origem: 'feedback_tarefa', origemId: `${eventoId}|${entrega.id}`, destinoNome: 'Área de Exercícios', lida: false, data: new Date().toISOString()
        };

        await db.collection('workspace_notificacoes').insertOne(notificacao);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: [nomeAluno], escolaId: escolaId });
            global.workspaceStream.emit('evento_realtime', { type: 'NOVO_FEEDBACK', entregaId: entregaId, feedback: novoFeedback, escolaId: escolaId });
        }

        res.status(201).json({ success: true, feedback: novoFeedback });
    } catch (error) { res.status(500).json({ error: 'Erro interno.' }); }
});

// ============================================================================
// 🎭 RADAR DE AVATARES (Filtro Rigoroso: Apenas Alunos Ativos com Login)
// ============================================================================
router.get('/avatars', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await executarAutoCuraRetroativa(database);

        const mapaAvatars = {};
        const alunosTodos = await database.collection('alunos').find({}).toArray();
        const alunos = alunosTodos.filter(ehAlunoAtivo);
        const idsAlunosInativos = new Set(alunosTodos.filter(a => !ehAlunoAtivo(a)).map(a => String(a.id)));

        const usuariosTodos = await database.collection('usuarios').find({}).toArray();
        const usuarios = usuariosTodos.filter(u => !(u.alunoRefId && idsAlunosInativos.has(String(u.alunoRefId))));
        
        const guardarFotoSegura = (chave, urlFoto) => {
            if (!chave || !urlFoto) return;
            const k = String(chave).trim();
            if (k) mapaAvatars[k] = urlFoto;
        };

        // 1. Mapeia fotos da ficha de alunos
        alunos.forEach(aluno => {
            if (aluno.avatar) {
                guardarFotoSegura(aluno.nome, aluno.avatar);
                guardarFotoSegura(aluno.login, aluno.avatar);
            }
        });

        // 2. Mapeia fotos da coleção 'usuarios' (associando ao Nome Escolhido, ao Login e ao Nome Completo da matrícula)
        usuarios.forEach(u => {
            const fichaAluno = alunos.find(a =>
                (u.alunoRefId && (String(a.id) === String(u.alunoRefId) || String(a._id) === String(u.alunoRefId))) ||
                (u.id && String(a.id) === String(u.id)) ||
                (u.login && a.login && String(a.login).toLowerCase().trim() === String(u.login).toLowerCase().trim()) ||
                (u.nome && a.nome && String(a.nome).toLowerCase().trim() === String(u.nome).toLowerCase().trim())
            );

            const fotoFinal = u.avatar || (fichaAluno && fichaAluno.avatar) || null;
            if (fotoFinal) {
                guardarFotoSegura(u.nome, fotoFinal);
                guardarFotoSegura(u.login, fotoFinal);
                if (fichaAluno && fichaAluno.nome) {
                    guardarFotoSegura(fichaAluno.nome, fotoFinal);
                    if (u.nome) {
                        guardarFotoSegura(`${fichaAluno.nome.trim()} (@${u.nome.trim()})`, fotoFinal);
                    }
                }
            }
        });
        
        res.status(200).json(mapaAvatars);
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao carregar o diretório de utilizadores.' }); 
    }
});

// ============================================================================
// 📝 CRIAR E GERIR TAREFAS / EXERCÍCIOS
// ============================================================================
router.post('/eventos', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const novoEvento = { ...req.body, id: crypto.randomUUID(), dataCriacao: new Date().toISOString() };
        await db.collection('eventos').insertOne(novoEvento);

        try {
            const escola = req.body.escolaId || 'DEFAULT'; 
            const tituloTarefa = req.body.titulo || 'Novo Exercício';
            const autorDaTarefa = req.body.autorNome || 'Professor';
            const destinoTarefa = req.body.turma || 'global';
            const destinoNomeTarefa = req.body.turmaNome || 'Geral';

            const alunos = (await db.collection('alunos').find({ escolaId: escola }).toArray()).filter(ehAlunoAtivo);
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
                        escolaId: escola, destinatarioNome: nomeAluno, remetenteNome: autorDaTarefa,
                        mensagem: `agendou um novo exercício: "${tituloTarefa}"`,
                        origem: 'tarefa', origemId: novoEvento.id, destinoNome: destinoNomeTarefa, lida: false, data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    if (global.workspaceStream) {
                        global.workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escola });
                    }
                }
            }
        } catch (erroNotificacao) {}

        res.status(201).json({ success: true, evento: novoEvento });
    } catch (error) { res.status(500).json({ error: 'Erro ao registar a atividade no servidor.' }); }
});

router.put('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const eventoId = req.params.id;
        const eventoOriginal = await database.collection('eventos').findOne({ id: eventoId });
        if (!eventoOriginal) return res.status(404).json({ error: 'Atividade não encontrada.' });

        const updateFields = {};
        if (req.body.titulo) updateFields.titulo = req.body.titulo;
        if (req.body.data) updateFields.data = req.body.data;
        if (req.body.turma) updateFields.turma = req.body.turma;
        if (req.body.turmaNome) updateFields.turmaNome = req.body.turmaNome;
        if (req.body.descricao !== undefined) updateFields.descricao = req.body.descricao;
        if (req.body.anexoUrl !== undefined) updateFields.anexoUrl = req.body.anexoUrl;

        await database.collection('eventos').updateOne({ id: eventoId }, { $set: updateFields });

        try {
            const entregasAnteriores = await database.collection('workspace_entregas').find({ eventoId: eventoId }).toArray();
            const alunosQueEntregaramIds = entregasAnteriores.map(e => String(e.alunoId));
            const alunosQueEntregaramNomes = entregasAnteriores.map(e => e.alunoNome);

            if (entregasAnteriores.length > 0) {
                await database.collection('workspace_entregas').deleteMany({ eventoId: eventoId });
            }

            const escolaId = eventoOriginal.escolaId || 'DEFAULT';
            const autorDaTarefa = eventoOriginal.autorNome || 'Professor';
            const tituloNovo = req.body.titulo || eventoOriginal.titulo || 'Exercício Atualizado';
            const turmaAlvo = req.body.turma || eventoOriginal.turma || 'global';
            
            const todosAlunosBrutos = await database.collection('alunos').find({ escolaId: escolaId }).toArray();
            const todosAlunos = todosAlunosBrutos.filter(ehAlunoAtivo);
            const alunosDaTurma = todosAlunos.filter(a => {
                if (turmaAlvo === 'global') return true;
                const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                return minhasTurmas.some(t => String(t).toLowerCase() === String(turmaAlvo).toLowerCase() || String(t).toLowerCase() === String(req.body.turmaNome || eventoOriginal.turmaNome).toLowerCase());
            });

            const notificacoesArray = [];
            const destinatariosGeral = [];

            alunosDaTurma.forEach(aluno => {
                const nomeAluno = aluno.nome || aluno.login;
                if (!nomeAluno) return;
                destinatariosGeral.push(nomeAluno);

                const jaTinhaEntregue = alunosQueEntregaramIds.includes(String(aluno.id)) || alunosQueEntregaramNomes.includes(nomeAluno);
                let mensagemAviso = jaTinhaEntregue 
                    ? `fez modificações estruturais no exercício <strong>"${tituloNovo}"</strong>. <span style="color:#e74c3c;">A sua entrega anterior foi anulada. Por favor, leia as novas instruções e refaça a atividade.</span>` 
                    : `atualizou as instruções e regras do exercício <strong>"${tituloNovo}"</strong>. Confirme as novidades antes de enviar!`;

                notificacoesArray.push({
                    id: 'notif_upd_' + Date.now() + Math.random().toString(36).substring(7),
                    escolaId: escolaId, destinatarioNome: nomeAluno, remetenteNome: autorDaTarefa,
                    mensagem: mensagemAviso, origem: 'tarefa', origemId: eventoId, destinoNome: req.body.turmaNome || eventoOriginal.turmaNome || 'Geral', lida: false, data: new Date().toISOString()
                });
            });

            if (notificacoesArray.length > 0) {
                await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
                if (global.workspaceStream) global.workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: destinatariosGeral, escolaId: escolaId });
            }
        } catch (erroLogica) {}

        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar edição da atividade.' }); }
});

router.delete('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('eventos').deleteOne({ id: req.params.id });
        await database.collection('workspace_entregas').deleteMany({ eventoId: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar o exercício.' }); }
});

// ============================================================================
// 🧹 ROTAS DE DESTRUIÇÃO E REATIVAÇÃO (DELETE GERAIS)
// ============================================================================
router.delete('/chat/:turmaId/mensagens/massa', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const { ids } = req.body; 
        if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Nenhuma mensagem selecionada.' });

        await database.collection('workspace_chats').deleteMany({ id: { $in: ids }, turmaId: req.params.turmaId });
        workspaceStream.emit('evento_realtime', { type: 'MSG_APAGADA_MASSA', turmaId: req.params.turmaId, mensagensIds: ids, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true, message: "Mensagens apagadas com sucesso!" });
    } catch (error) { res.status(500).json({ error: 'Erro interno.' }); }
});

router.delete('/chat/:turmaId/mensagem/:mensagemId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_chats').deleteOne({ id: req.params.mensagemId, turmaId: req.params.turmaId });
        workspaceStream.emit('evento_realtime', { type: 'MSG_APAGADA', turmaId: req.params.turmaId, mensagemId: req.params.mensagemId, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true, message: "Mensagem apagada com sucesso!" });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar a mensagem do chat.' }); }
});

router.delete('/chat/:turmaId/limpar', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_chats').deleteMany({ turmaId: req.params.turmaId });
        workspaceStream.emit('evento_realtime', { type: 'SALA_UPDATE', turmaId: req.params.turmaId, escolaId: 'DEFAULT' });
        res.status(200).json({ success: true, message: "Chat limpo com sucesso!" });
    } catch (error) { res.status(500).json({ error: 'Erro ao limpar o chat.' }); }
});

router.delete('/entregas/:entregaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteOne({ id: req.params.entregaId });
        res.status(200).json({ success: true, message: "Acesso reativado!" });
    } catch (error) { res.status(500).json({ error: 'Erro ao reativar aluno.' }); }
});

router.delete('/avaliacoes/:id/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteMany({ avaliacaoId: req.params.id });
        res.status(200).json({ success: true, message: "Sala reativada para todos!" });
    } catch (error) { res.status(500).json({ error: 'Erro ao limpar presenças.' }); }
});

// ============================================================================
// 🧰 BAÚ DAS MEMÓRIAS (NOTAS E ALARMES) E MATERIAIS
// ============================================================================
router.get('/bau/notas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const notas = await database.collection('workspace_bau_notas').find({ usuarioId: req.query.usuarioId }).sort({ dataAtualizacao: -1 }).toArray();
        res.status(200).json({ dados: notas });
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar notas.' }); }
});

router.post('/bau/notas', verificarToken, async (req, res) => {
    try {
        const { usuarioId, titulo, texto } = req.body;
        const database = await connectDB();
        const novaNota = { id: crypto.randomUUID(), usuarioId, titulo: titulo || 'Nota sem título', texto, dataCriacao: new Date().toISOString(), dataAtualizacao: new Date().toISOString() };
        await database.collection('workspace_bau_notas').insertOne(novaNota);
        res.status(201).json({ success: true, nota: novaNota });
    } catch (error) { res.status(500).json({ error: 'Erro ao criar nota.' }); }
});

router.put('/bau/notas/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_notas').updateOne({ id: req.params.id }, { $set: { titulo: req.body.titulo, texto: req.body.texto, dataAtualizacao: new Date().toISOString() } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar nota.' }); }
});

router.delete('/bau/notas/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_notas').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar nota.' }); }
});

router.get('/bau/alarmes', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const alarmes = await database.collection('workspace_bau_alarmes').find({ usuarioId: req.query.usuarioId }).sort({ tempoDisparo: 1 }).toArray();
        res.status(200).json({ dados: alarmes });
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar alarmes.' }); }
});

router.post('/bau/alarmes', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novoAlarme = { id: crypto.randomUUID(), usuarioId: req.body.usuarioId, mensagem: req.body.mensagem, tempoDisparo: req.body.tempoDisparo, criadoEm: new Date().toISOString() };
        await database.collection('workspace_bau_alarmes').insertOne(novoAlarme);
        res.status(201).json({ success: true, id: novoAlarme.id });
    } catch (error) { res.status(500).json({ error: 'Erro ao criar alarme.' }); }
});

router.put('/bau/alarmes/:id/disparado', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_alarmes').updateOne({ id: req.params.id }, { $set: { disparado: true } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar alarme.' }); }
});

router.delete('/bau/alarmes/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_bau_alarmes').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar alarme.' }); }
});

// MATERIAIS
router.post('/materiais', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const novoMaterial = { ...req.body, id: req.body.id || crypto.randomUUID() };
        await db.collection('workspace_materiais').insertOne(novoMaterial);

        try {
            const escolaId = novoMaterial.escolaId || 'DEFAULT';
            const destino = novoMaterial.destino || 'global';
            const autor = novoMaterial.autorNome || 'Professor';
            const tituloMat = novoMaterial.titulo || 'Novo Material';

            const alunos = (await db.collection('alunos').find({ escolaId: escolaId }).toArray()).filter(ehAlunoAtivo);
            let alunosAlvo = [];
            if (destino === 'global' || (Array.isArray(destino) && destino.includes('global'))) {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    if (Array.isArray(destino)) return minhasTurmas.some(t => destino.includes(String(t)) || (Array.isArray(novoMaterial.destinoNome) && novoMaterial.destinoNome.includes(String(t))));
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(destino).toLowerCase() || String(t).toLowerCase() === String(novoMaterial.destinoNome).toLowerCase());
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const nomeDestinoAmigavel = Array.isArray(novoMaterial.destinoNome) ? novoMaterial.destinoNome.join(', ') : (novoMaterial.destinoNome || 'Geral');
                
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    return {
                        id: crypto.randomUUID(), escolaId: escolaId, destinatarioNome: nomeAluno, remetenteNome: autor,
                        mensagem: `compartilhou um novo material: "${tituloMat}"`, origem: 'material', origemId: novoMaterial.id, destinoNome: nomeDestinoAmigavel, lida: false, data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escolaId });
                }
            }
        } catch (erroNotificacao) {}

        res.status(201).json({ success: true, material: novoMaterial });
    } catch (error) { res.status(500).json({ success: false, error: 'Erro ao registar o material.' }); }
});

router.get('/materiais', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId;
        const alunoRefId = req.query.alunoRefId;
        const filtroEscola = (escolaId && escolaId !== 'DEFAULT')
            ? { $in: [escolaId, 'DEFAULT', null] }
            : { $exists: true };

        let filtro = { escolaId: filtroEscola };
        
        if (alunoRefId && alunoRefId !== 'undefined') {
            let aluno = await db.collection('alunos').findOne({ id: String(alunoRefId) });
            if (!aluno) {
                const contaUser = await db.collection('usuarios').findOne({ id: String(alunoRefId) });
                if (contaUser && contaUser.alunoRefId) {
                    aluno = await db.collection('alunos').findOne({ id: String(contaUser.alunoRefId) });
                }
            }
            if (aluno) {
                let minhasTurmas = Array.isArray(aluno.turmas) ? [...aluno.turmas] : [];
                if (aluno.turma) minhasTurmas.push(aluno.turma);
                if (aluno.turmaId) minhasTurmas.push(aluno.turmaId);
                minhasTurmas = minhasTurmas.filter(Boolean);

                if (minhasTurmas.length > 0) {
                    filtro = {
                        escolaId: filtroEscola,
                        $or: [
                            { destino: 'global' },
                            { destino: { $in: ['global', ...minhasTurmas] } },
                            { destinoNome: { $in: ['Todas as Turmas', 'Global', ...minhasTurmas] } }
                        ]
                    };
                }
            }
        }
        const materiais = await db.collection('workspace_materiais').find(filtro).sort({ dataCriacao: -1 }).toArray();
        res.status(200).json({ success: true, materiais });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.delete('/materiais/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_materiais').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.put('/materiais/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const materialAtualizado = req.body;
        const materialId = req.params.id;

        const materialAntigo = await db.collection('workspace_materiais').findOne({ id: materialId });
        if(!materialAntigo) return res.status(404).json({ error: 'Material não encontrado.' });

        await db.collection('workspace_materiais').updateOne(
            { id: materialId }, 
            { $set: {
                titulo: materialAtualizado.titulo, 
                descricao: materialAtualizado.descricao, 
                tags: materialAtualizado.tags, // 🚀 NOVO: Guarda as palavras-chave na BD
                destino: materialAtualizado.destino,
                destinoNome: materialAtualizado.destinoNome, 
                url: materialAtualizado.url, 
                tipoFicheiro: materialAtualizado.tipoFicheiro, 
                nomeOriginal: materialAtualizado.nomeOriginal
            }}
        );

        try {
            const escolaId = materialAtualizado.escolaId || 'DEFAULT';
            const destino = materialAtualizado.destino || 'global';
            const autor = materialAtualizado.autorNome || 'Professor';
            const tituloMat = materialAtualizado.titulo || 'Material Atualizado';

            const alunos = (await db.collection('alunos').find({ escolaId: escolaId }).toArray()).filter(ehAlunoAtivo);
            let alunosAlvo = [];
            if (destino === 'global' || (Array.isArray(destino) && destino.includes('global'))) {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    if (Array.isArray(destino)) return minhasTurmas.some(t => destino.includes(String(t)) || (Array.isArray(materialAtualizado.destinoNome) && materialAtualizado.destinoNome.includes(String(t))));
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(destino).toLowerCase() || String(t).toLowerCase() === String(materialAtualizado.destinoNome).toLowerCase());
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const nomeDestinoAmigavel = Array.isArray(materialAtualizado.destinoNome) ? materialAtualizado.destinoNome.join(', ') : (materialAtualizado.destinoNome || 'Geral');
                
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    return {
                        id: crypto.randomUUID(), escolaId: escolaId, destinatarioNome: nomeAluno, remetenteNome: autor,
                        mensagem: `atualizou o material: "${tituloMat}"`, origem: 'material', origemId: materialId, destinoNome: nomeDestinoAmigavel, lida: false, data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escolaId });
                }
            }
        } catch (eNoti) {}

        workspaceStream.emit('evento_realtime', { type: 'MATERIAL_UPDATE', escolaId: materialAtualizado.escolaId || 'DEFAULT' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ success: false, error: 'Erro ao atualizar.' }); }
});

// ============================================================================
// 📡 ROTA DE MONITORAMENTO EM TEMPO REAL DO WORKSPACE
// ============================================================================
router.get('/monitoramento/status', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId; 
        const filtro = escolaId ? { escolaId } : {};

        const alunos = (await db.collection('alunos').find(filtro).toArray()).filter(ehAlunoAtivo);
        const usuarios = await db.collection('usuarios').find(filtro).toArray();
        
        const agora = new Date();
        const JANELA_ONLINE = 35 * 1000;
        const relatorioFinal = [];

        alunos.forEach(aluno => {
            if (!aluno.id) return; 
            const contaUser = usuarios.find(u => u.alunoRefId && String(u.alunoRefId) === String(aluno.id));
            const ultimoAcessoStr = contaUser?.ultimoAcesso || null;
            let isOnline = false;
            
            if (ultimoAcessoStr) {
                const ultimaData = new Date(ultimoAcessoStr).getTime();
                if (!isNaN(ultimaData) && (agora.getTime() - ultimaData) <= JANELA_ONLINE) isOnline = true;
            }
            relatorioFinal.push({ id: aluno.id, nome: aluno.nome || contaUser?.login || 'Aluno', isOnline, ultimoAcesso: ultimoAcessoStr });
        });

        usuarios.forEach(user => {
            if (user.tipo === 'Aluno') return; 
            if (!user.id) return;

            const ultimoAcessoStr = user.ultimoAcesso || null;
            let isOnline = false;
            
            if (ultimoAcessoStr) {
                const ultimaData = new Date(ultimoAcessoStr).getTime();
                if (!isNaN(ultimaData) && (agora.getTime() - ultimaData) <= JANELA_ONLINE) isOnline = true;
            }
            relatorioFinal.push({ id: user.id, nome: user.nome || user.login || 'Equipa', isOnline, ultimoAcesso: ultimoAcessoStr });
        });

        res.status(200).json(relatorioFinal);
    } catch (error) { res.status(500).json({ error: 'Erro no radar.' }); }
});

router.post('/monitoramento/ping', verificarToken, async (req, res) => {
    try {
        const usuarioId = req.body.usuarioId;
        if (!usuarioId) return res.status(400).json({ error: 'ID ausente' });

        const db = await connectDB();
        await db.collection('usuarios').updateOne({ id: usuarioId }, { $set: { ultimoAcesso: new Date().toISOString() } });
        res.status(200).json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro no ping.' }); }
});

router.post('/monitoramento/offline', verificarToken, async (req, res) => {
    try {
        let usuarioId = req.body.usuarioId;
        if (!usuarioId && typeof req.body === 'string') {
            try { usuarioId = JSON.parse(req.body).usuarioId; } catch(err){}
        }
        if (!usuarioId) return res.status(200).json({ success: true });

        const db = await connectDB();
        const tempoExpirado = new Date(Date.now() - 60000).toISOString();
        await db.collection('usuarios').updateOne({ id: usuarioId }, { $set: { ultimoAcesso: tempoExpirado } });
        res.status(200).json({ success: true });
    } catch (e) { res.status(200).json({ success: true }); }
});

// ============================================================================
// 🏴‍☠️ BAÚ DO INGLÊS E IA (Ptt Cursos)
// ============================================================================
router.post('/ingles/xp', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, escolaId, nome, coins, streak, streakFreeze, srs, itensConcluidos, itensComprados, mascoteAtivo, tituloAtivo } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });

        let nomeReal = (nome && nome !== 'Aluno') ? String(nome).trim() : null;
        if (!nomeReal) {
            const contaUser = await db.collection('usuarios').findOne({ id: String(userId) });
            if (contaUser && (contaUser.nome || contaUser.login)) {
                nomeReal = String(contaUser.nome || contaUser.login).trim();
            }
        }

        const camposUpdate = {
            escolaId: escolaId || 'DEFAULT',
            coins: coins || { bronze: 0, prata: 0, ouro: 0 },
            streak: parseInt(streak) || 1,
            streakFreeze: parseInt(streakFreeze) || 0,
            ultimaAtividade: new Date().toISOString()
        };

        if (nomeReal) camposUpdate.nome = nomeReal;
        if (srs && typeof srs === 'object') camposUpdate.srs = srs;
        if (Array.isArray(itensConcluidos)) camposUpdate.itensConcluidos = itensConcluidos;
        if (Array.isArray(itensComprados)) camposUpdate.itensComprados = itensComprados;
        if (mascoteAtivo !== undefined) camposUpdate.mascoteAtivo = mascoteAtivo;
        if (tituloAtivo !== undefined) camposUpdate.tituloAtivo = tituloAtivo;

        await db.collection('workspace_ingles_stats').updateOne(
            { userId: String(userId) },
            { 
                $set: camposUpdate,
                $setOnInsert: { nome: nomeReal || 'Aluno' }
            },
            { upsert: true }
        );
        res.json({ success: true, nome: nomeReal || 'Aluno' });
    } catch (e) { res.status(500).json({ error: 'Erro sync stats' }); }
});

router.get('/ingles/ranking', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        
        const ranking = await db.collection('workspace_ingles_stats')
            .find({ escolaId: escolaId, "coins.bronze": { $gt: 0 } })
            .sort({ "coins.bronze": -1 })
            .limit(50)
            .toArray();
        
        const alunos = await db.collection('alunos').find({}).toArray();
        const usuarios = await db.collection('usuarios').find({}).toArray();
        
        const mapaAvatars = {};
        const mapaNomes = {};

        alunos.forEach(a => { 
            if (a.id && a.nome) mapaNomes[String(a.id)] = a.nome.trim();
            if (a.avatar) {
                if (a.id) mapaAvatars[String(a.id)] = a.avatar; 
                if (a.nome) mapaAvatars[a.nome.trim()] = a.avatar; 
            }
        });

        // A coleção 'usuarios' sobrescreve com prioridade total para usar o Nome Escolhido pelo aluno no WorkSpace!
        usuarios.forEach(u => { 
            const fichaAluno = alunos.find(a => u.alunoRefId && String(a.id) === String(u.alunoRefId));
            const nomeU = (u.nome || (fichaAluno && fichaAluno.nome) || u.login || '').trim();
            const fotoU = u.avatar || (fichaAluno && fichaAluno.avatar) || null;

            if (u.id && nomeU) mapaNomes[String(u.id)] = nomeU;
            if (u.alunoRefId && nomeU) mapaNomes[String(u.alunoRefId)] = nomeU;

            if (fotoU) {
                if (u.id) mapaAvatars[String(u.id)] = fotoU; 
                if (u.alunoRefId) mapaAvatars[String(u.alunoRefId)] = fotoU;
                if (nomeU) mapaAvatars[nomeU] = fotoU; 
                if (u.login) mapaAvatars[u.login.trim()] = fotoU; 
            }
        });

        const comLiga = ranking.map((r, i) => {
            // Prioriza sempre o nome atualizado de 'usuarios' mapeado pelo userId!
            const nomeExibicao = mapaNomes[String(r.userId)] || r.nome || 'Aluno';

            const totalBronze = Math.max(r.coins?.bronze || 0, r.coins?.maiorSaldo || 0);
            let ligaCalculada = 'bronze';
            if (totalBronze >= 500000000) ligaCalculada = 'diamante';
            else if (totalBronze >= 1000000 || i === 0) ligaCalculada = 'ouro';
            else if (totalBronze >= 100000 || (i >= 1 && i < 3)) ligaCalculada = 'prata';

            return { 
                userId: r.userId, 
                nome: nomeExibicao, 
                avatar: mapaAvatars[String(r.userId)] || mapaAvatars[nomeExibicao.trim()] || null,
                coins: r.coins || { bronze: 0, prata: 0, ouro: 0 }, 
                streak: r.streak || 1, 
                mascoteAtivo: r.mascoteAtivo || '',
                tituloAtivo: r.tituloAtivo || '',
                posicao: i + 1, 
                liga: ligaCalculada 
            };
        });
        
        res.json({ success: true, ranking: comLiga });
    } catch (e) { res.status(500).json({ error: 'Erro ranking' }); }
});

router.get('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        const userId = req.query.userId || null;

        let d = await db.collection('workspace_ingles_data').findOne({ escolaId: escolaId }) || {};
        let statsAluno = null;
        if (userId) {
            statsAluno = await db.collection('workspace_ingles_stats').findOne({ userId: String(userId) });
        }

        res.json({ 
            success: true, 
            dados: { 
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
                answerStatements: d.answerStatements || [],
                recompensasProf: d.recompensasProf || [],
                submissions: d.submissions || [], 
                pool: d.pool || [], 
                errosRetidos: d.errosRetidos || [], 
                srs: (statsAluno && statsAluno.srs) ? statsAluno.srs : (d.srs || {}),
                statsAluno: statsAluno ? {
                    coins: statsAluno.coins,
                    streak: statsAluno.streak,
                    streakFreeze: statsAluno.streakFreeze || 0,
                    itensComprados: statsAluno.itensComprados || [],
                    mascoteAtivo: statsAluno.mascoteAtivo || '',
                    tituloAtivo: statsAluno.tituloAtivo || '',
                    ultimaAtividade: statsAluno.ultimaAtividade,
                    itensConcluidos: statsAluno.itensConcluidos || []
                } : null
            } 
        });
    } catch (e) { res.status(500).json({ error: 'Erro ler dados' }); }
});

router.put('/ingles/dados', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId, modoAluno, ...campos } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';

        // 🛡️ BLINDAGEM: Se vier de um aluno (modoAluno: true), atualiza apenas envios/resgates e erros retidos
        if (modoAluno) {
            const updateAluno = {};
            if (Array.isArray(campos.submissions)) updateAluno.submissions = campos.submissions;
            if (Array.isArray(campos.errosRetidos)) updateAluno.errosRetidos = campos.errosRetidos;
            if (Object.keys(updateAluno).length > 0) {
                await db.collection('workspace_ingles_data').updateOne(
                    { escolaId: escolaAlvo },
                    { $set: updateAluno },
                    { upsert: true }
                );
            }
            return res.json({ success: true });
        }

        // 👨‍🏫 Salvamento do Professor: Atualiza toda a biblioteca e cupons e avisa os alunos em Tempo Real!
        const update = { ultimaAtualizacao: new Date().toISOString() };
        const permitidos = ['words','phrases','quizzes','pictures','submissions','pool','errosRetidos','srs','wordPickers','minimalPairs','debates','roleplays','questions','answerStatements','recompensasProf'];
        Object.keys(campos).forEach(k => { if (permitidos.includes(k)) update[k] = campos[k]; });
        
        await db.collection('workspace_ingles_data').updateOne(
            { escolaId: escolaAlvo }, 
            { $set: update }, 
            { upsert: true }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'BAU_INGLES_UPDATE',
                escolaId: escolaAlvo
            });
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro salvar' }); }
});

router.post('/ingles/debate', verificarToken, async (req, res) => {
    try {
        const { topico, historico } = req.body;
        const ultimaMensagem = historico[historico.length - 1];
        const textoMinusculo = ultimaMensagem.text.trim().toLowerCase();
        const totalTurnos = historico.length;
        const topicoLimpo = topico.replace(/[^a-zA-Z0-9 ]/g, '');

        let respostaGerada = "", dicaGramatical = "";
        await new Promise(resolve => setTimeout(resolve, 1200));

        if (/\b(he|she|it)\s+(dont|do)\b/i.test(textoMinusculo)) dicaGramatical = " 🧙‍♂️ Magic Tip: Remember to use 'doesn't' or 'does' with He, She, and It!";
        else if (/\bi\s+(is|has)\b/i.test(textoMinusculo)) dicaGramatical = " 🧙‍♂️ Magic Tip: With 'I', we always use 'am' or 'have'.";
        else if (/\b(more better|more good)\b/i.test(textoMinusculo)) dicaGramatical = " 🧙‍♂️ Magic Tip: We just say 'better', no need for 'more'!";

        const quantidadePalavras = ultimaMensagem.text.trim().split(/\s+/).length;
        if (quantidadePalavras < 4) respostaGerada = `That's a very short answer! Come on, use your English skills. Tell me exactly WHY you think that about ${topicoLimpo}.`;
        else if (/^(why|how|what|when|where|is|are|do|does|can|could|would)\b/i.test(textoMinusculo) || textoMinusculo.includes('?')) respostaGerada = `You are asking the right questions! However, in the context of ${topicoLimpo}, I want to hear YOUR perspective first. How would you answer that?`;
        else if (/\b(agree|yes|absolutely|true|right)\b/.test(textoMinusculo)) respostaGerada = `I'm glad we are on the same page. But what if the opposite were true? How would society handle ${topicoLimpo} if we took away the main benefits you just mentioned?`;
        else if (/\b(disagree|no|false|wrong|dont think so)\b/.test(textoMinusculo)) respostaGerada = `A strong counter-argument! You clearly disagree. But consider this: many experts believe ${topicoLimpo} brings hidden advantages. Can you think of at least one positive aspect?`;
        else if (/\b(because|since|for example|like)\b/.test(textoMinusculo)) respostaGerada = `Excellent point, applying reasons and examples makes your English sound very natural! But let's dig deeper: does that rule apply to everyone, everywhere?`;
        else {
            const respostasDinâmicas = [`That is a fascinating way to look at ${topicoLimpo}. But let me challenge you: what is the biggest flaw in that line of thought?`, `You express yourself very well. Still, regarding ${topicoLimpo}, don't you think technology or culture will change that perspective in 10 years?`, `I see your point. To keep our debate moving, what would you say to someone who completely disagrees with what you just wrote?`];
            respostaGerada = respostasDinâmicas[Math.floor(Math.random() * respostasDinâmicas.length)];
        }

        if (totalTurnos > 8 && totalTurnos < 11) respostaGerada = `We have explored ${topicoLimpo} thoroughly! Your English argumentation is getting stronger. Please, give me your final concluding statement on this matter.`;
        else if (totalTurnos >= 11) respostaGerada = `Debate successfully concluded! 🌟 You did an amazing job defending your thoughts. Feel free to close this training and collect your Bronze Coins!`;

        res.json({ success: true, resposta: respostaGerada + dicaGramatical });
    } catch (error) { res.status(500).json({ success: false, error: 'O Mago IA está focado noutro feitiço.' }); }
});

router.post('/ingles/ia-teste/falar', verificarToken, async (req, res) => {
    try {
        const { mensagem, historico = [] } = req.body;
        if (!mensagem) return res.status(400).json({ error: 'Mensagem vazia.' });
        
        const pensamento = await PttAIEngine.pensar(mensagem, historico);
        const infoBastidores = pensamento.bastidoresAviso 
            ? `🛡️ ${pensamento.bastidoresAviso} | Classificação: [${pensamento.intencaoDetetada}]`
            : `A Ptt AI classificou esta frase como: [${pensamento.intencaoDetetada}]`;
        
        res.json({ 
            success: true, 
            resposta: pensamento.resposta, 
            bastidores: infoBastidores 
        });
    } catch (error) { 
        console.error(error);
        res.status(500).json({ success: false, error: 'O cérebro falhou.' }); 
    }
});

router.post('/ingles/ia-teste/ensinar', verificarToken, async (req, res) => {
    try {
        if (!req.body.frase || !req.body.categoria) return res.status(400).json({ error: 'Faltam dados principais para ensinar a IA.' });
        const resultadoAprendizagem = await PttAIEngine.ensinarNovaFrase(req.body.frase, req.body.categoria, req.body.resposta);
        res.json({ success: true, mensagem: resultadoAprendizagem });
    } catch (error) { res.status(500).json({ success: false, error: 'Erro ao treinar o cérebro.' }); }
});

router.post('/ingles/ia-teste/ensinar-correcao', verificarToken, async (req, res) => {
    try {
        if (!req.body.erro || !req.body.certo) return res.status(400).json({ error: 'Faltam dados para ensinar a correção.' });
        const resultadoAprendizagem = await PttAIEngine.ensinarCorrecao(req.body.erro, req.body.certo);
        res.json({ success: true, mensagem: resultadoAprendizagem });
    } catch (error) { res.status(500).json({ success: false, error: 'Erro ao treinar o olheiro ortográfico.' }); }
});

// 🚀 ROTA DA IA GERATIVA PREMIUM (GROQ) E AVALIAÇÃO DE JOGOS
router.post('/ingles/ia-teste/groq', verificarToken, async (req, res) => {
    try {
        const { mensagem, historico = [] } = req.body;
        if (!mensagem) return res.status(400).json({ error: 'Mensagem vazia.' });

        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ success: false, error: 'Chave API não configurada.' });

        const groq = new Groq({ apiKey: chaveApi.trim() });
        const INSTRUCOES_PROFESSOR = `
            You are 'Ptt AI', an expert, friendly, and highly motivating English teacher.
            Follow these rules strictly:
            1. Maintain a positive, didactic, and helpful tone.
            2. If the student makes a grammatical or spelling mistake, kindly correct them first, explain the rule briefly, and then answer their message.
            3. Do not answer questions outside the scope of English learning. If asked about other subjects, politely redirect the conversation back to English practice.
            4. Keep your answers relatively short (max 3-4 sentences) so the student is not overwhelmed.
            5. Always end by asking a question to keep the conversation flowing.
        `;

        const respostaGroq = await groq.chat.completions.create({
            messages: [{ role: 'system', content: INSTRUCOES_PROFESSOR }, ...historico, { role: 'user', content: mensagem }],
            model: 'openai/gpt-oss-120b', // 🚀 MODELO ORIGINAL RESTAURADO!
            temperature: 0.7,
        });

        res.json({ success: true, resposta: respostaGroq.choices[0]?.message?.content || 'A IA ficou sem palavras.' });
    } catch (error) { res.status(500).json({ success: false, error: 'Falha de comunicação com a Nuvem.' }); }
});

router.post('/ingles/jogo/avaliar', verificarToken, async (req, res) => {
    try {
        const { jogo, palavra, fraseAluno, cenario, pergunta, tarefaEspecifica, respostaAluno, historico = [] } = req.body;
        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ success: false, error: 'Chave API em falta' });
        
        const groq = new Groq({ apiKey: chaveApi.trim() });
        let systemPrompt = "", userPrompt = "";

        if (jogo === 'wordSpark') {
            systemPrompt = `Você é um professor de inglês amigável avaliando a frase de um aluno. A palavra obrigatória era "${palavra}".
            Regras:
            1. Verifique se o aluno usou a palavra (ou variação correta) e se a frase faz sentido.
            2. Seja flexível com pequenos erros ortográficos secundários.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Curto elogio ou explicação em PT-BR", "correcao": "Frase ideal em inglês", "coins": 50}`;
            userPrompt = fraseAluno;
        }
        
        if (jogo === 'answerQuest') {
            systemPrompt = `Você é um professor de inglês. 
            Pergunta proposta: "${pergunta}" 
            Resposta do aluno: "${respostaAluno}"
            Regras:
            1. Verifique se a resposta tem sentido e responde à pergunta em inglês.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Feedback em PT-BR", "correcao": "Versão mais natural da resposta", "coins": 50}`;
            userPrompt = respostaAluno;
        }

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

        if (jogo === 'picturePop') {
            systemPrompt = `Você é um professor de inglês avaliando a criatividade do aluno.
            A imagem mostrada ao aluno representa a palavra/conceito: "${palavra}".
            A frase criada pelo aluno foi: "${respostaAluno}"
            Regras de avaliação:
            1. Verifique se a frase tem relação lógica com a palavra/imagem e se está escrita em inglês.
            2. Se o aluno escreveu uma frase completa (ex: "This is an apple"), elogie muito!
            3. Se o aluno escreveu apenas a palavra solta (ex: "apple"), "correto" é true, mas no feedback incentive-o fortemente a formar frases completas da próxima vez.
            4. Se houver erro gramatical, corrija no campo "correcao".
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Avaliação em PT-BR", "correcao": "Frase ideal", "coins": 75}`;
            userPrompt = respostaAluno;
        }

        if (jogo === 'readAloud' || jogo === 'picturePopSpeech') {
            systemPrompt = `Você é um professor de inglês especialista em fonética.
            A ${jogo === 'readAloud' ? 'frase' : 'palavra'} que o aluno tinha de ler era: "${pergunta}".
            O microfone captou (transcrição do áudio): "${respostaAluno}".
            Regras de avaliação:
            1. O reconhecimento de voz erra muito em palavras homófonas (ex: "two", "to", "too" / "pear", "pair"). Se o que o microfone ouviu soa muito parecido com a palavra original, APROVE ("correto": true), pois significa que o aluno pronunciou o som certo!
            2. Se a transcrição tiver pequenas omissões causadas pelo microfone, mas o sentido global estiver lá, "correto" é true.
            3. Se o aluno disse palavras que não têm nada a ver sonoramente com o texto original, "correto" é false.
            Retorne APENAS um JSON válido: {"correto": true/false, "feedback": "Explicação pedagógica em PT-BR avaliando a pronúncia", "correcao": "Dica de como fazer o som certo (se errou) ou elogio (se acertou)", "coins": 50}`;
            userPrompt = respostaAluno;
        }

        const completion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt }
            ],
            model: 'openai/gpt-oss-120b', // 🚀 MODELO ORIGINAL RESTAURADO!
            temperature: 0.3,
            response_format: { type: 'json_object' } 
        });

        let resultado;
        try { resultado = JSON.parse(completion.choices[0].message.content); } 
        catch(parseErr) { resultado = { correto: false, feedback: "Houve um pequeno desvio na avaliação.", correcao: "Tente enviar novamente." }; }

        res.json({ success: true, ...resultado });
    } catch (e) { res.status(500).json({ success: false, error: 'Falha na IA do jogo' }); }
});

// ============================================================================
// 🚀 LOUSA DIGITAL - ROTAS FINAIS v5 (TEMPO REAL INSTANTÂNEO + TRAVA DE RECURSOS)
// ============================================================================

async function resolverIdentidadeTurmaLousa(database, turmaInput) {
    const chave = String(turmaInput || 'global').trim();
    if (!chave || chave.toLowerCase() === 'global') {
        return { idCanonico: 'global', nomeTurma: 'Público Geral', chavesBusca: ['global'] };
    }
    try {
        const regexNome = new RegExp(`^\\s*${chave.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'i');
        const criterios = [{ id: chave }, { nome: regexNome }];
        if (/^[0-9a-fA-F]{24}$/.test(chave)) {
            const { ObjectId } = require('mongodb');
            criterios.push({ _id: new ObjectId(chave) });
        }
        const turmaDoc = await database.collection('turmas').findOne({ $or: criterios });
        if (turmaDoc) {
            const idC = String(turmaDoc.id || turmaDoc._id || chave).trim();
            const nomeC = String(turmaDoc.nome || chave).trim();
            return {
                idCanonico: idC,
                nomeTurma: nomeC,
                chavesBusca: Array.from(new Set([idC, String(turmaDoc._id || ''), nomeC, chave].filter(Boolean)))
            };
        }
    } catch (e) {}
    return { idCanonico: chave, nomeTurma: chave, chavesBusca: [chave] };
}

router.put('/sala/workspace-lousa/status', verificarToken, async (req, res) => {
    try {
        const { turmaId, ativa, recursos, escolaId } = req.body;
        if (!turmaId) return res.status(400).json({ success: false, error: 'turmaId é obrigatório' });
        
        const database = await connectDB();
        const escolaFinal = escolaId || req.query.escolaId || req.body.escolaId || req.usuario?.escolaId || 'DEFAULT';
        const { idCanonico, nomeTurma } = await resolverIdentidadeTurmaLousa(database, turmaId);
        const agoraIso = new Date().toISOString();

        // 🔒 Recursos só ficam disponíveis se a lousa estiver ativa!
        const lousaAtiva = !!ativa;
        const recursosAtivos = lousaAtiva ? !!recursos : false;

        // Verifica se já estava ativa para manter o cronómetro contínuo ao alternar apenas os recursos
        const statusAnterior = await database.collection('workspace_lousa_status').findOne({ id: idCanonico });
        const ativadaEm = lousaAtiva
            ? ((statusAnterior && statusAnterior.ativa && statusAnterior.ativadaEm) ? statusAnterior.ativadaEm : Date.now())
            : null;

        if (lousaAtiva) {
            await database.collection('workspace_lousa_status').updateMany(
                { id: { $nin: [idCanonico, nomeTurma] } },
                { $set: { ativa: false, lousaAtiva: false, recursos: false, lousaRecursos: false, ativadaEm: null } }
            );
        }

        const dadosStatus = {
            id: idCanonico,
            idOriginal: idCanonico,
            nome: nomeTurma,
            ativa: lousaAtiva,
            recursos: recursosAtivos,
            lousaAtiva: lousaAtiva,
            lousaRecursos: recursosAtivos,
            ativadaEm: ativadaEm,
            atualizadoEm: agoraIso,
            escolaId: escolaFinal,
            professorId: req.usuario?.id || null
        };

        await database.collection('workspace_lousa_status').updateOne(
            { id: idCanonico },
            { $set: dadosStatus },
            { upsert: true }
        );

        if (nomeTurma && nomeTurma !== idCanonico) {
            await database.collection('workspace_lousa_status').updateOne(
                { id: nomeTurma },
                { $set: { ...dadosStatus, id: nomeTurma } },
                { upsert: true }
            );
        }

        if (global.workspaceStream) {
            const payloadEvento = {
                type: 'LOUSA_STATUS_CHANGED',
                turmaId: idCanonico,
                turmaNome: nomeTurma,
                ativa: lousaAtiva,
                recursos: recursosAtivos,
                ativadaEm: ativadaEm,
                escolaId: 'DEFAULT'
            };
            global.workspaceStream.emit('evento_realtime', payloadEvento);
            if (escolaFinal !== 'DEFAULT') {
                global.workspaceStream.emit('evento_realtime', { ...payloadEvento, escolaId: escolaFinal });
            }
        }

        res.json({ success: true, turmaId: idCanonico, turmaNome: nomeTurma, ativa: lousaAtiva, recursos: recursosAtivos, ativadaEm });
    } catch (e) {
        res.status(500).json({ success: false, error: 'Erro ao sincronizar lousa.' });
    }
});

router.get('/sala/workspace-lousa/status/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const turmaIdReq = String(req.params.turmaId || 'global').trim();
        const { idCanonico, nomeTurma, chavesBusca } = await resolverIdentidadeTurmaLousa(database, turmaIdReq);

        if (req.query.estrito === 'true') {
            const statusEstrito = await database.collection('workspace_lousa_status').findOne({
                $or: [
                    { id: { $in: chavesBusca } },
                    { nome: { $in: chavesBusca } },
                    { idOriginal: { $in: chavesBusca } }
                ]
            });
            const ativaE = !!(statusEstrito?.ativa || statusEstrito?.lousaAtiva);
            const recursosE = ativaE ? !!(statusEstrito?.recursos || statusEstrito?.lousaRecursos) : false;
            return res.json({
                success: true,
                ativa: ativaE,
                recursos: recursosE,
                ativadaEm: ativaE ? (statusEstrito?.ativadaEm || Date.now()) : null,
                turmaId: turmaIdReq,
                idCanonico,
                nomeTurma,
                salaAtivaId: 'LOUSA_MESTRA_UNIFICADA'
            });
        }

        const candidatos = new Set([...chavesBusca, 'global', 'Público Geral']);
        const userId = req.query.userId ? String(req.query.userId).trim() : '';
        const alunoRefId = req.query.alunoRefId ? String(req.query.alunoRefId).trim() : '';

        if (userId || alunoRefId) {
            const criteriosAluno = [];
            if (alunoRefId && alunoRefId !== 'undefined') criteriosAluno.push({ id: alunoRefId });
            if (userId && userId !== 'undefined') criteriosAluno.push({ id: userId });

            if (criteriosAluno.length > 0) {
                const fichaAluno = await database.collection('alunos').findOne({ $or: criteriosAluno });
                if (fichaAluno) {
                    const extrair = (v) => {
                        if (!v) return;
                        if (Array.isArray(v)) v.forEach(extrair);
                        else if (typeof v === 'object') {
                            if (v.id) candidatos.add(String(v.id).trim());
                            if (v.nome) candidatos.add(String(v.nome).trim());
                        } else {
                            candidatos.add(String(v).trim());
                        }
                    };
                    extrair(fichaAluno.turma);
                    extrair(fichaAluno.turmaId);
                    extrair(fichaAluno.turmas);
                }
            }
        }

        const listaCandidatos = Array.from(candidatos).filter(Boolean);
        for (const cand of listaCandidatos) {
            if (cand !== 'global' && cand !== 'Público Geral') {
                const infoT = await resolverIdentidadeTurmaLousa(database, cand);
                infoT.chavesBusca.forEach(k => candidatos.add(k));
            }
        }

        const todasChavesAluno = Array.from(candidatos);

        let statusAtivo = await database.collection('workspace_lousa_status')
            .find({
                $and: [
                    { $or: [{ ativa: true }, { lousaAtiva: true }] },
                    {
                        $or: [
                            { id: { $in: todasChavesAluno } },
                            { nome: { $in: todasChavesAluno } },
                            { idOriginal: { $in: todasChavesAluno } }
                        ]
                    }
                ]
            })
            .sort({ atualizadoEm: -1 })
            .limit(1)
            .next();

        if (!statusAtivo) {
            statusAtivo = await database.collection('workspace_lousa_status')
                .find({ $or: [{ ativa: true }, { lousaAtiva: true }] })
                .sort({ atualizadoEm: -1 })
                .limit(1)
                .next();
        }

        const ativa = !!(statusAtivo?.ativa || statusAtivo?.lousaAtiva);
        const recursos = ativa ? !!(statusAtivo?.recursos || statusAtivo?.lousaRecursos) : false;

        res.json({
            success: true,
            ativa,
            recursos,
            ativadaEm: ativa ? (statusAtivo?.ativadaEm || Date.now()) : null,
            turmaId: turmaIdReq,
            idCanonico,
            nomeTurma: statusAtivo?.nome || nomeTurma,
            salaAtivaId: 'LOUSA_MESTRA_UNIFICADA'
        });
    } catch (e) {
        res.status(500).json({ success: false, ativa: false, recursos: false });
    }
});

router.delete('/sala/workspace-lousa/status/tudo', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const r1 = await db.collection('workspace_lousa_status').deleteMany({});
        const r2 = await db.collection('workspace_lousa_dados').deleteMany({});
        res.json({ success: true, deletedStatus: r1.deletedCount, deletedDados: r2.deletedCount });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

router.put('/sala/workspace-lousa/dados/:turmaId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { records, senderId } = req.body;
        const agoraIso = new Date().toISOString();

        const tiposValidos = new Set(['shape', 'asset', 'binding']);
        const listaRecords = Array.isArray(records)
            ? records.filter(r => r && tiposValidos.has(r.typeName))
            : [];

        // Grava sempre no Quadro Mestre Unificado para que Professor e Alunos vejam SEMPRE as mesmas Telas Numeradas!
        await db.collection('workspace_lousa_dados').updateOne(
            { id: 'LOUSA_MESTRA_UNIFICADA' },
            { $set: { id: 'LOUSA_MESTRA_UNIFICADA', records: listaRecords, atualizadoEm: agoraIso } },
            { upsert: true }
        );

        // ⚡ VELOCIDADE DA LUZ: Envia os 'records' diretamente dentro do evento SSE para atualização instantânea em 0ms!
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'LOUSA_DADOS_CHANGED',
                turmaId: 'LOUSA_MESTRA_UNIFICADA',
                senderId: senderId || null,
                records: listaRecords,
                escolaId: 'DEFAULT'
            });
        }

        res.json({ success: true, count: listaRecords.length });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

router.get('/sala/workspace-lousa/dados/:turmaId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        let doc = await db.collection('workspace_lousa_dados').findOne({ id: 'LOUSA_MESTRA_UNIFICADA' });

        // Se ainda não existir o documento unificado, recupera o mais recente que existir na coleção
        if (!doc || !Array.isArray(doc.records) || doc.records.length === 0) {
            doc = await db.collection('workspace_lousa_dados')
                .find({ "records.0": { $exists: true } })
                .sort({ atualizadoEm: -1 })
                .limit(1)
                .next();
        }

        const tiposValidos = new Set(['shape', 'asset', 'binding']);
        const recordsLimpos = Array.isArray(doc?.records)
            ? doc.records.filter(r => r && tiposValidos.has(r.typeName))
            : [];

        res.json({ success: true, turmaId: 'LOUSA_MESTRA_UNIFICADA', records: recordsLimpos });
    } catch (e) {
        res.status(500).json({ success: false, records: [] });
    }
});

// ============================================================================
// 🧠 HUB DE ESTUDO: IMERSÃO ESPECÍFICA (Curadoria Aguçada, Quiz e Recursos)
// ============================================================================
router.post('/posts/imersao', verificarToken, async (req, res) => {
    try {
        const { termoBusca, alunoRefId, escolaId } = req.body;
        const database = await connectDB();
        
        let filtro = { escolaId: escolaId || 'DEFAULT' };
        if (alunoRefId && alunoRefId !== 'undefined') {
            const aluno = await database.collection('alunos').findOne({ id: alunoRefId });
            if (aluno) {
                let minhasTurmas = Array.isArray(aluno.turmas) ? aluno.turmas : [aluno.turmas || aluno.turma];
                filtro = { 
                    $and: [
                        { escolaId: escolaId || 'DEFAULT' },
                        { $or: [{ destino: 'global' }, { destino: { $in: minhasTurmas } }, { destinoNome: { $in: minhasTurmas } }] }
                    ]
                };
            }
        }

       // 🚀 OTIMIZAÇÃO DE TOKENS: Reduzido de 40/30 para 12/8 para não estourar a memória da Groq
        const postsBrutos = await database.collection('workspace_posts').find(filtro).sort({ dataCriacao: -1 }).limit(12).toArray();
        const materiaisBrutos = await database.collection('workspace_materiais').find(filtro).sort({ dataCriacao: -1 }).limit(8).toArray();
        
        const conteudoPosts = postsBrutos.map(p => {
            let infoAnexos = (p.anexos || []).map(a => a.nome + ' (' + a.tipo + ')').join(', ');
            
            // 🚀 CORTADOR DE TEXTO: Se o post for gigantesco, enviamos apenas os primeiros 400 caracteres
            let textoSeguro = p.texto ? p.texto.substring(0, 400) + (p.texto.length > 400 ? '...' : '') : '';
            
            return `[POST_ID: ${p.id} | Autor: ${p.autorNome}]: ${textoSeguro} ${infoAnexos ? '(Anexos: ' + infoAnexos + ')' : ''}`;
        }).join('\n\n');

        const conteudoMateriais = materiaisBrutos.map(m => {
            const tagsInfo = m.tags ? ` | Palavras-Chave: ${m.tags}` : '';
            
            // 🚀 CORTADOR DE TEXTO: Limita a descrição do material também
            let descSegura = m.descricao ? m.descricao.substring(0, 200) + (m.descricao.length > 200 ? '...' : '') : '';
            
            return `[MATERIAL_ID: ${m.id} | Título: ${m.titulo || ''}${tagsInfo}]: Descrição: ${descSegura}`;
        }).join('\n\n');

        const conteudoParaIA = `--- PUBLICAÇÕES DO FEED ---\n${conteudoPosts}\n\n--- MATERIAIS DA ESCOLA ---\n${conteudoMateriais}`;

        if (!conteudoPosts.trim() && !conteudoMateriais.trim()) {
            return res.status(400).json({ error: 'Não há conteúdo suficiente na plataforma para criar uma imersão.' });
        }

        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ error: 'Chave API da Groq em falta.' });
        const groq = new Groq({ apiKey: chaveApi.trim() });

        // 🚀 MÁGICA 1: O Prompt Dinâmico Bilingue
        const instrucaoFoco = termoBusca 
            ? `O aluno quer focar-se em: "${termoBusca}". Filtra a análise estritamente neste tema. IMPORTANTE: Aja como um professor bilingue. Se o termo de busca estiver em Inglês (ex: "Phrasal verbs"), todo o resumo, explicações e o quiz DEVEM SER EM INGLÊS. Se o termo estiver em Português, use PORTUGUÊS.` 
            : `Cria uma imersão com base nos temas mais importantes. Responda em Português.`;

       const systemPrompt = `Você é a Inteligência Artificial de elite da área 'Imersão Específica' de uma escola de INGLÊS.
        Abaixo estão as publicações recentes do Feed e os Materiais Oficiais do Professor.
        ${instrucaoFoco}
        
        REGRAS ABSOLUTAS E INQUEBRÁVEIS:
        1. IDIOMA: Respeite rigorosamente a instrução de idioma acima (Inglês ou Português).
        2. PROFUNDIDADE (GATILHO DE EXAUSTÃO): O seu "resumo" deve ser massivo, aprofundado e digno de uma aula universitária. Dê exemplos e explique detalhes.
        3. FORMATAÇÃO RICA: Use HTML puro (<strong>, <em>, <ul>, <li>, <table>).
        
        A sua missão:
        1. Crie um "titulo" cativante.
        2. Escreva o "resumo" ENORME e ricamente detalhado.
        3. Guarde IDs sugeridos em "postsRelacionados" ou "materiaisRelacionados".
        4. Crie um "quiz" com 3 perguntas difíceis. A "respostaCorreta" deve ser o NÚMERO 1, 2, 3 ou 4. É OBRIGATÓRIO incluir o campo "explicacao" detalhando o motivo da resposta certa.
        5. Crie o "tituloNota" e "conteudoParaNota".
        
        Retorne APENAS JSON válido. NÃO use formatação Markdown como \`\`\`json no início ou no fim. Apenas o objeto puro.`;

        const completion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: conteudoParaIA }
            ],
            model: 'openai/gpt-oss-120b', 
            temperature: 0.4, 
            max_tokens: 6000, 
            response_format: { type: 'json_object' } 
        });

        // 🚀 MÁGICA 2: A "Lavandaria" do JSON (Filtro Anti-Erro 500)
        let conteudoLimpo = completion.choices[0].message.content.trim();
        
        // Arranca o código Markdown se a IA teimar em enviá-lo
        if (conteudoLimpo.startsWith('```')) {
            conteudoLimpo = conteudoLimpo.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
        }
        
        const imersaoGerada = JSON.parse(conteudoLimpo);
        
        let materiaisDetalhados = [];
        if (imersaoGerada.materiaisRelacionados && imersaoGerada.materiaisRelacionados.length > 0) {
            materiaisDetalhados = materiaisBrutos.filter(m => imersaoGerada.materiaisRelacionados.includes(m.id));
        }

        res.status(200).json({ success: true, imersao: imersaoGerada, materiaisExtras: materiaisDetalhados });

    } catch (error) {
        console.error("🚨 Erro na Imersão Específica:", error);
        res.status(500).json({ error: 'O motor de imersão falhou. A IA enviou dados incompreensíveis. Tente de novo.' });
    }
});

// ============================================================================
// 🧠 HUB DE ESTUDO: GERAR MAIS QUIZ (Imersão Específica)
// ============================================================================
router.post('/posts/imersao/mais-quiz', verificarToken, async (req, res) => {
    try {
        const { titulo, resumo } = req.body;
        
        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ error: 'Chave API da Groq em falta.' });
        const groq = new Groq({ apiKey: chaveApi.trim() });

        const instrucaoFoco = `Baseie-se na aula "${titulo || 'Inglês'}" e no seguinte resumo: ${String(resumo || '').substring(0, 1500)}. Crie 3 novas perguntas inéditas no mesmo idioma do resumo.`;

        const systemPrompt = `Você é a Inteligência Artificial de elite da área 'Imersão Específica' de uma escola de INGLÊS.
        ${instrucaoFoco}
        
        A sua missão é retornar APENAS um JSON válido contendo 3 novas perguntas difíceis no formato abaixo, sem formatação Markdown:
        {
            "quiz": [
                {
                    "pergunta": "Sua pergunta difícil aqui?",
                    "opcoes": ["A", "B", "C", "D"],
                    "respostaCorreta": 1,
                    "explicacao": "A explicação pedagógica e detalhada do porquê desta resposta estar correta."
                }
            ]
        }`;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'system', content: systemPrompt }],
            model: 'openai/gpt-oss-120b', 
            temperature: 0.5, 
            response_format: { type: 'json_object' } 
        });

        let conteudoLimpo = completion.choices[0].message.content.trim();
        if (conteudoLimpo.startsWith('```')) {
            conteudoLimpo = conteudoLimpo.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
        }
        const novasPerguntas = JSON.parse(conteudoLimpo);
        res.status(200).json({ success: true, novasPerguntas: novasPerguntas.quiz });

    } catch (error) {
        console.error("🚨 Erro ao gerar mais quiz:", error);
        res.status(500).json({ error: 'A IA falhou ao gerar as perguntas. Tente de novo.' });
    }
});

// ============================================================================
// 🎶 HUB DE ESTUDO LMS: IMERSÃO MUSICAL (Montra, Histórico e Treino Ativo)
// ============================================================================

// 1. Verificar o Estado Musical do Aluno
router.get('/ingles/musica/status', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userId = req.query.userId;
        const escolaId = req.query.escolaId || 'DEFAULT';

        if (!userId) return res.status(400).json({ error: 'ID de utilizador ausente.' });
        
        const data = await db.collection('workspace_ingles_data').findOne({ userId: userId }) || {};
        
        // 🚀 O SEGREDO DO CATÁLOGO: Puxamos TODAS as músicas da escola, ignorando o limite de 50 do Feed!
        const catalogo = await db.collection('workspace_posts')
            .find({ escolaId: escolaId, categoria: 'musica' })
            .sort({ dataCriacao: -1 })
            .toArray();

        res.json({ 
            success: true, 
            musicaAtiva: data.musicaAtiva || null, 
            historicoMusicas: data.historicoMusicas || [],
            catalogo: catalogo // Envia a biblioteca inteira para o Frontend
        });
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar o seu estúdio musical.' }); }
});

// 2. Concluir um Treino Musical (ou Apenas Trocar de Música)
router.post('/ingles/musica/concluir', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { userId, postId, apenasTrocar } = req.body;
        if (!userId) return res.status(400).json({ error: 'Utilizador não identificado.' });

        const operacaoUpdate = { $unset: { musicaAtiva: "" } };

        // Se o aluno concluiu o treino (e não está apenas a voltar ao catálogo), guarda no Histórico sem duplicar
        if (!apenasTrocar && postId) {
            operacaoUpdate.$addToSet = { historicoMusicas: postId };
        }

        await db.collection('workspace_ingles_data').updateOne(
            { userId: userId },
            operacaoUpdate,
            { upsert: true }
        );
        res.json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao atualizar o estado do treino musical.' }); 
    }
});

// 3. Iniciar um Treino Específico (Selecionado da Montra)
router.post('/posts/imersao-musical', verificarToken, async (req, res) => {
    try {
        const { postId, userId } = req.body;
        const database = await connectDB();
        
        // Puxa exatamente o post que o aluno clicou
        const postOriginal = await database.collection('workspace_posts').findOne({ id: postId });
        if (!postOriginal) return res.status(404).json({ error: 'A música desapareceu dos arquivos da escola.' });

      // 🚀 OTIMIZAÇÃO DE TOKENS: Lemos diretamente a música clicada (postOriginal)
        // e cortamos a letra se ultrapassar os 1200 caracteres de forma segura.
        let letraSegura = postOriginal.texto ? postOriginal.texto.substring(0, 1200) + (postOriginal.texto.length > 1200 ? '\n[...Música Cortada por Segurança...]' : '') : '';
        const conteudoParaIA = `[POST_ID: ${postOriginal.id} | Autor: ${postOriginal.autorNome}]: ${letraSegura}`;

        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ error: 'Chave API da Groq em falta.' });
        const groq = new Groq({ apiKey: chaveApi.trim() });

        const systemPrompt = `Você é um professor de INGLÊS especialista em fluência através da música.
        Abaixo está uma publicação do Feed da plataforma contendo a letra de uma música.
        
        REGRAS ABSOLUTAS:
        1. IDIOMA: Ensine EXCLUSIVAMENTE Inglês (explicando em Português).
        2. ESTRUTURA MÁXIMA: Extraia EXATAMENTE 14 frases vitais dessa música. É OBRIGATÓRIO GERAR O PLANO DO DIA 1 ATÉ AO DIA 14. NÃO PARE A MEIO.
        3. MINIJOGO: Para CADA frase, escolha UMA palavra vital e esconda-a na "fraseOculta" substituindo-a por "____". Coloque a palavra correta em "palavraEscondida".
        4. CONCISÃO: Seja muito direto e breve nas explicações e desafios para poupar memória.
        
        Retorne APENAS JSON válido com a estrutura exata:
        {
            "tituloMusica": "Nome da Música e Artista",
            "planoEstudos": [
                {
                    "dia": 1,
                    "fraseOriginal": "Frase exata e completa da música",
                    "fraseOculta": "Frase com a palavra substituída por ____",
                    "palavraEscondida": "A palavra exata",
                    "traducao": "Tradução curta",
                    "explicacao": "Explicação muito breve (use HTML <strong> se precisar)",
                    "desafio": "Desafio muito curto"
                }
            ]
        }`;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: conteudoParaIA }],
            model: 'openai/gpt-oss-120b', 
            temperature: 0.3,
            max_tokens: 3000, // 🚀 Reduzido para libertar espaço para o pedido
            response_format: { type: 'json_object' } 
        });

        const imersaoGerada = JSON.parse(completion.choices[0].message.content);

        // 🚀 O SEGREDO DO LMS: Guarda o plano gerado na Base de Dados atrelado ao aluno!
        await database.collection('workspace_ingles_data').updateOne(
            { userId: userId },
            { $set: { musicaAtiva: { plano: imersaoGerada, postOriginal: postOriginal } } },
            { upsert: true }
        );

        res.status(200).json({ success: true, plano: imersaoGerada, postOriginal: postOriginal });

    } catch (error) {
        console.error("🚨 Erro na Imersão Musical:", error);
        res.status(500).json({ error: 'O motor musical falhou. A IA precisa de uma afinação.' });
    }
});

// 4. Gerar Mais Dias (e atualizar a BD)
router.post('/posts/imersao-musical/mais-dias', verificarToken, async (req, res) => {
    try {
        const { userId, postId, ultimoDia } = req.body;
        const database = await connectDB();
        
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        if (!post) return res.status(404).json({ error: 'A publicação com a música original já não existe.' });

        const maxDiasGeracao = Math.min(7, 30 - ultimoDia); 
        if (maxDiasGeracao <= 0) return res.status(400).json({ error: 'Já atingiu o limite de 30 dias!' });

        const conteudoParaIA = `[LETRA DA MÚSICA]: ${post.texto || ''}`;

        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });

        const systemPrompt = `Você é um professor de INGLÊS especialista em música.
        O aluno já completou os primeiros ${ultimoDia} dias desta música.
        Extraia ${maxDiasGeracao} NOVAS frases da letra. O plano deve iniciar no dia ${ultimoDia + 1} e ir até o dia ${ultimoDia + maxDiasGeracao}.
        
        Retorne APENAS JSON: {"planoEstudos": [{"dia": ${ultimoDia + 1}, "fraseOriginal": "...", "fraseOculta": "...", "palavraEscondida": "...", "traducao": "...", "explicacao": "...", "desafio": "..."}]}`;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: conteudoParaIA }],
            model: 'openai/gpt-oss-120b', 
            temperature: 0.5, 
            max_tokens: 4500,
            response_format: { type: 'json_object' } 
        });

        const planoGerado = JSON.parse(completion.choices[0].message.content);

        // 🚀 Atualiza a Base de Dados do Aluno juntando as novas lições!
        await database.collection('workspace_ingles_data').updateOne(
            { userId: userId },
            { $push: { "musicaAtiva.plano.planoEstudos": { $each: planoGerado.planoEstudos } } }
        );

        res.status(200).json({ success: true, plano: planoGerado.planoEstudos });

    } catch (error) {
        console.error("🚨 Erro ao gerar mais dias:", error);
        res.status(500).json({ error: 'A IA falhou ao gerar as novas frases.' });
    }
});

// ============================================================================
// 🎙️ REVISOR DE TRANSCRIÇÃO INTELIGENTE (PONTUAÇÃO PERFEITA)
// ============================================================================
router.post('/ingles/transcricao/corrigir', verificarToken, async (req, res) => {
    try {
        const { textoCru } = req.body;
        if (!textoCru) return res.status(400).json({ error: 'Texto vazio.' });

        const Groq = require('groq-sdk');
        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) return res.status(500).json({ error: 'Chave API da Groq em falta.' });
        
        const groq = new Groq({ apiKey: chaveApi.trim() });
        
        const systemPrompt = `Você é um Revisor de Transcrição de Áudio super inteligente.
        A sua ÚNICA função é receber um texto cru captado por um microfone e aplicar a pontuação correta (interrogações, exclamações, vírgulas e letras maiúsculas iniciais).
        
        REGRAS ABSOLUTAS:
        1. NÃO adicione palavras novas. NÃO altere o sentido. Apenas corrija a pontuação e maiúsculas.
        2. Analise a gramática criticamente: Se começar com Wh- (What, Where, Why, How, Who) ou auxiliares (Do, Does, Are, Is, Can, Could, Would, Should), termine OBRIGATORIAMENTE com "?".
        3. Se for uma expressão curta de emoção, surpresa ou entusiasmo (ex: "Wow", "Oh my god", "Stop"), termine com "!".
        4. Retorne APENAS o texto corrigido, sem aspas, sem explicações, sem introduções e sem formatação extra.`;

        const completion = await groq.chat.completions.create({
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: textoCru }
            ],
            model: 'openai/gpt-oss-120b', 
            temperature: 0.1, // Temperatura muito baixa para ser um revisor estrito que não inventa texto
            max_tokens: 150
        });

        const textoCorrigido = completion.choices[0].message.content.trim();
        res.status(200).json({ success: true, textoCorrigido });
    } catch (error) {
        console.error("🚨 Erro no Revisor de Transcrição:", error);
        // Fallback rápido: Se a IA falhar por limite de taxa, devolvemos o texto original com a primeira letra maiúscula para a UX não quebrar
        const textoFallback = textoCru.charAt(0).toUpperCase() + textoCru.slice(1) + '.';
        res.status(200).json({ success: true, textoCorrigido: textoFallback });
    }
});


module.exports = router;