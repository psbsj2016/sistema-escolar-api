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
global.workspaceStream = workspaceStream; // 🚀 MAGIA: Torna o motor acessível a todos os ficheiros!

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

const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    
    // 🚀 REGISTO AUTOMÁTICO DE ATIVIDADE: Atualiza o último acesso em background
    try {
        // Tentamos extrair o ID do utilizador através do token ou de cookies se decodificado, 
        // ou atualizamos com base nas rotas subsequentes. Para garantir leveza, 
        // fazemos um registo genérico se houver identificação na sessão.
        if (req.body && req.body.id) {
            const db = await connectDB();
            await db.collection('usuarios').updateOne(
                { id: req.body.id },
                { $set: { ultimoAcesso: new Date().toISOString() } }
            );
        }
    } catch (e) {
        // Silencioso para não atrapalhar o fluxo principal
    }

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

router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, avatarUrl } = req.body;
        const database = await connectDB();
        await database.collection('usuarios').updateOne({ id: id }, { $set: { avatar: avatarUrl } });
        if (alunoRefId) await database.collection('alunos').updateOne({ id: alunoRefId }, { $set: { avatar: avatarUrl } });
        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) { res.status(500).json({ error: 'Erro.' }); }
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
                        mensagem: `submeteu a resolução de "${tituloTarefa}" em ${turmaNome}.`,
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
            if (destino === 'global') {
                alunosAlvo = alunos; // Todos recebem
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    // Verifica se o aluno pertence à turma do material
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(destino).toLowerCase() || String(t).toLowerCase() === String(novoMaterial.destinoNome).toLowerCase());
                });
            }

            // 3. Se encontrou alunos, fabrica os bilhetes de notificação
            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    
                    return {
                        id: crypto.randomUUID(),
                        escolaId: escolaId,
                        destinatarioNome: nomeAluno,
                        remetenteNome: autor,
                        mensagem: `partilhou um novo material: "${tituloMat}"`,
                        origem: 'material', // O nosso Roteador no alertas.js procura por esta palavra exata!
                        origemId: novoMaterial.id,
                        destinoNome: novoMaterial.destinoNome || 'Geral',
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome); // Remove nulos por segurança

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
                // Mostra o que é Global + O que é da turma exata dele
                filtro = { 
                    escolaId: escolaId,
                    $or: [
                        { destino: 'global' }, 
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

// ============================================================================
// 📡 ROTA DE MONITORAMENTO EM TEMPO REAL DO WORKSPACE
// ============================================================================
router.get('/monitoramento/status', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        
        const alunos = await db.collection('alunos').find({}).toArray();
        const usuarios = await db.collection('usuarios').find({}).toArray();
        
        const agora = new Date();
        // 🚀 Janela reduzida para 35 segundos (perfeito para o ping de 30s)
        const JANELA_ONLINE = 35 * 1000; 

        const relatorio = alunos.map(aluno => {
            const contaUser = usuarios.find(u => u.alunoRefId === aluno.id || (u.tipo === 'Aluno' && u.nome === aluno.nome));
            
            const ultimoAcessoStr = contaUser ? contaUser.ultimoAcesso : null;
            let isOnline = false;

            if (ultimoAcessoStr) {
                const tempoUltimoAcesso = new Date(ultimoAcessoStr).getTime();
                if ((agora.getTime() - tempoUltimoAcesso) <= JANELA_ONLINE) {
                    isOnline = true;
                }
            }

            return {
                id: aluno.id,
                nome: aluno.nome || 'Aluno Sem Nome',
                login: contaUser ? contaUser.login : 'Sem Acesso Criado',
                isOnline: isOnline,
                ultimoAcesso: ultimoAcessoStr || (contaUser ? contaUser.dataCriacao : null)
            };
        });

        res.status(200).json(relatorio);
    } catch (error) {
        console.error("🚨 Erro ao gerar relatório de monitoramento:", error);
        res.status(500).json({ error: 'Erro interno ao carregar o radar de status.' });
    }
});

// 🚀 ROTA DE "HEARTBEAT" (Recebe o sinal periódico de que o aluno está ativo)
router.post('/monitoramento/ping', verificarToken, async (req, res) => {
    try {
        const { usuarioId } = req.body;
        if (!usuarioId) return res.status(400).json({ error: 'ID em falta.' });

        const db = await connectDB();
        await db.collection('usuarios').updateOne(
            { id: usuarioId },
            { $set: { ultimoAcesso: new Date().toISOString() } }
        );

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro no ping.' });
    }
});

// 🚀 ROTA DE SAÍDA INSTANTÂNEA (Força o aluno a ficar offline imediatamente)
router.post('/monitoramento/offline', verificarToken, async (req, res) => {
    try {
        const { usuarioId } = req.body;
        if (!usuarioId) return res.status(200).json({ success: true });

        const db = await connectDB();
        // Atualiza o último acesso e envelhece o timestamp para além da janela de 35 segundos
        const tempoExpirado = new Date(Date.now() - 60000).toISOString();
        
        await db.collection('usuarios').updateOne(
            { id: usuarioId },
            { $set: { ultimoAcesso: tempoExpirado } }
        );

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ success: true });
    }
});

module.exports = router;