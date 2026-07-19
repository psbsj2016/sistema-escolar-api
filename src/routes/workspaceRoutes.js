const express = require('express');
const router = express.Router();
// 🚀 PROTEÇÃO ANTI-502: Interceta a demora aos 90 segundos e liberta a memória!
router.use((req, res, next) => {
    // Usamos req.setTimeout para poder destruir a conexão física se congelar
    req.setTimeout(90000, () => {
        console.log('⚠️ Timeout na requisição atingido (90s). Destruindo conexão.');
        if (!res.headersSent) {
            res.status(408).json({ error: 'Tempo esgotado. O ficheiro é demasiado pesado para a nuvem.' });
        }
        req.destroy(); // <--- O SEGREDO: Corta a linha fisicamente antes do Render!
    });
    next();
});
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const multerCloudinary = require('multer-storage-cloudinary');
const CloudinaryStorage = multerCloudinary.CloudinaryStorage || multerCloudinary;

// ⚡ MOTOR DE TEMPO REAL (Túnel SSE)
const EventEmitter = require('events');
const workspaceStream = new EventEmitter();
workspaceStream.setMaxListeners(0); // Permite infinitas conexões simultâneas

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ============================================================================
// 🛡️ CONFIGURAÇÃO DE UPLOAD SEGURO (USANDO MEMÓRIA TEMPORÁRIA)
// ============================================================================
// Em vez de enviar direto, guardamos na memória rápida do Render primeiro
const storage = multer.memoryStorage();

// ============================================================================
// 🛡️ CONFIGURAÇÃO DE UPLOAD COM LIMITES DE SEGURANÇA (10MB)
// ============================================================================
const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 10 * 1024 * 1024 // Limite estrito de 10MB
    }
});
const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    next();
};

// ============================================================================
// 🚀 TÚNEL DE CONEXÃO EM TEMPO REAL (SERVER-SENT EVENTS)
// ============================================================================
router.get('/stream', (req, res) => {
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
// 1. UPLOAD BLINDADO COM ENVIO MANUAL PARA O CLOUDINARY
// ============================================================================
router.post('/upload', verificarToken, (req, res) => {
    try {
        const uploadProcess = upload.array('anexos', 10);
        
        uploadProcess(req, res, async (err) => {
            if (res.headersSent) return; // Se o timeout (90s) já respondeu, paramos aqui.

            if (err) {
                if (err.message === 'Request aborted' || err.code === 'ECONNRESET') {
                    return res.status(400).json({ error: 'A ligação do aluno foi interrompida.' }); 
                }
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'O ficheiro excede o limite de 10MB.' });
                }
                console.error('🚨 Erro ao receber ficheiro:', err);
                return res.status(500).json({ error: 'Falha ao processar o ficheiro no servidor.' });
            }

            if (!req.files || req.files.length === 0) {
                return res.status(400).json({ error: 'Nenhum ficheiro recebido.' });
            }

            try {
                // 🚀 O NOVO MOTOR: Envia ficheiros da memória para o Cloudinary de forma segura
                const promessasUpload = req.files.map(file => {
                    return new Promise((resolve, reject) => {
                        // Limpa o nome do ficheiro (remove acentos e espaços)
                        let nomeOriginal = file.originalname || `ficheiro_${Date.now()}.jpg`;
                        let nomeSeguro = String(nomeOriginal).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
                        
                        const ehDocumento = nomeSeguro.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|zip)$/i);
                        
                        // Configura o destino
                        let recursoTipo = ehDocumento ? 'raw' : 'auto';
                        let publicId = ehDocumento ? `${Date.now()}_${nomeSeguro}` : `${Date.now()}_${nomeSeguro.split('.')[0]}`;

                        // Abre o canal de envio com o Cloudinary
                        const streamEnvio = cloudinary.uploader.upload_stream(
                            { folder: 'workspace_escola', resource_type: recursoTipo, public_id: publicId },
                            (error, result) => {
                                if (error) reject(error);
                                else resolve({ url: result.secure_url, nome: file.originalname, tipo: file.mimetype });
                            }
                        );
                        
                        // Despeja o ficheiro da memória para o Cloudinary de uma só vez!
                        streamEnvio.end(file.buffer);
                    });
                });

                // Espera que todos os ficheiros terminem o envio
                const urls = await Promise.all(promessasUpload);
                
                if (!res.headersSent) res.status(200).json({ success: true, anexos: urls });
                
            } catch (processError) {
                console.error('🚨 Erro no envio direto para o Cloudinary:', processError);
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
                mensagem: `comentou na publicação: "${texto.substring(0, 20)}..."`, origem: 'post', origemId: postId, lida: false, data: new Date().toISOString()
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

        if (autorNome && post.autorNome !== autorNome) { 
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(), escolaId: post.escolaId, destinatarioNome: post.autorNome, remetenteNome: autorNome,
                mensagem: `reagiu à sua publicação.`, origem: 'post', origemId: postId, lida: false, data: new Date().toISOString()
            });
            workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: [post.autorNome], escolaId: post.escolaId });
        }
        res.status(200).json({ success: true, likes, dislikes });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.delete('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_posts').deleteOne({ id: req.params.id });
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
// ⚙️ ROTA DE ALTERAÇÃO DE SENHA (PERFIL) - SUPORTE A SENHA PROVISÓRIA
// ============================================================================
router.put('/perfil', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, senhaAtual, novaSenha } = req.body;
        const database = await connectDB();
        
        const senhaLimpa = String(senhaAtual).trim();
        const novaSenhaLimpa = String(novaSenha).trim();

        // 1. A BUSCA CEGA: Encontramos o utilizador APENAS pelo ID (Não filtramos a senha aqui)
        let user = null;
        let nomeDaColecao = '';
        let idAlvo = null;

        // Tenta achar nos alunos primeiro (usando a referência do aluno)
        if (alunoRefId) {
            user = await database.collection('alunos').findOne({ id: alunoRefId });
            if (user) { nomeDaColecao = 'alunos'; idAlvo = alunoRefId; }
        }

        // Se não achou pelo alunoRefId, tenta pelo id normal na coleção alunos
        if (!user) {
            user = await database.collection('alunos').findOne({ id: id });
            if (user) { nomeDaColecao = 'alunos'; idAlvo = id; }
        }

        // Se não é aluno, tenta na coleção de usuarios (Professores/Gestores)
        if (!user) {
            user = await database.collection('usuarios').findOne({ id: id });
            if (user) { nomeDaColecao = 'usuarios'; idAlvo = id; }
        }

        // Se mesmo assim não achou ninguém, a conta não existe
        if (!user) {
            return res.status(404).json({ error: 'Conta não encontrada no sistema.' });
        }

        // 2. A VERIFICAÇÃO INTELIGENTE DA SENHA PROVISÓRIA (NO JAVASCRIPT)
        // Reunimos todos os campos onde o sistema possa ter gerado a senha inicial
        const senhasValidas = [
            String(user.senha).trim(),
            String(user.senha_provisoria).trim(),
            String(user.senhaProvisoria).trim(),
            String(user.password).trim()
        ];

        // Comparamos a senha digitada com a base de dados (permitindo match como texto ou número)
        const senhaCorreta = senhasValidas.includes(senhaLimpa) || senhasValidas.includes(String(Number(senhaLimpa)));

        // Se a senha não bater certo com nenhum dos campos provisórios ou oficiais...
        if (!senhaCorreta) {
            return res.status(400).json({ error: 'A senha atual está incorreta. Verifique e tente novamente.' });
        }

        // 3. ATUALIZAÇÃO DA SENHA E LIMPEZA
        // Guardamos a senha oficial e removemos as provisórias para ativar a conta definitivamente
        const updateDoc = {
            $set: { senha: novaSenhaLimpa },
            $unset: { senha_provisoria: "", senhaProvisoria: "" } 
        };

        await database.collection(nomeDaColecao).updateOne({ id: idAlvo }, updateDoc);

        // Sincronização dupla (Mantém ambas as gavetas iguais)
        if (nomeDaColecao === 'alunos') {
            await database.collection('usuarios').updateOne({ id: id }, updateDoc);
        } else if (alunoRefId) {
            await database.collection('alunos').updateOne({ id: alunoRefId }, updateDoc);
        }

        res.status(200).json({ success: true });
        
    } catch (error) { 
        console.error("🚨 Erro ao atualizar senha:", error);
        res.status(500).json({ error: 'Erro interno ao tentar atualizar a senha.' }); 
    }
});

router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, avatarUrl } = req.body;
        const database = await connectDB();
        await database.collection('usuarios').updateOne({ id: id }, { $set: { avatar: avatarUrl } });
        if (alunoRefId) await database.collection('alunos').updateOne({ id: alunoRefId }, { $set: { avatar: avatarUrl } });
        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.post('/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novaEntrega = { ...req.body, id: crypto.randomUUID(), dataEntrega: new Date().toISOString() };
        await database.collection('workspace_entregas').insertOne(novaEntrega);
        res.status(201).json({ success: true, entrega: novaEntrega });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
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

router.put('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('eventos').updateOne({ id: req.params.id }, { $set: { descricao: req.body.descricao } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

router.delete('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('eventos').deleteOne({ id: req.params.id });
        await database.collection('entregas').deleteMany({ eventoId: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
});

// ============================================================================
// 🧹 ROTAS DE DESTRUIÇÃO E REATIVAÇÃO (DELETE)
// ============================================================================

// 1. Limpar todo o Chat de uma turma
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

// 2. Reativar Acesso de 1 Aluno na Sala Online (Apaga uma presença específica)
router.delete('/entregas/:entregaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteOne({ id: req.params.entregaId });
        res.status(200).json({ success: true, message: "Acesso reativado!" });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao reativar aluno.' }); 
    }
});

// 3. Reativar Sala para Todos os Alunos (Apaga todas as presenças daquela sala)
router.delete('/avaliacoes/:id/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_entregas').deleteMany({ avaliacaoId: req.params.id });
        res.status(200).json({ success: true, message: "Sala reativada para todos!" });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao limpar presenças.' }); 
    }
});

module.exports = router;