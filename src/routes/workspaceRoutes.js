const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const multerCloudinary = require('multer-storage-cloudinary');
const CloudinaryStorage = multerCloudinary.CloudinaryStorage || multerCloudinary;

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const ehDocumento = file.originalname.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|zip)$/i);
        if (ehDocumento) {
            return {
                folder: 'workspace_escola',
                resource_type: 'raw',
                public_id: `${Date.now()}_${file.originalname}`
            };
        }
        return {
            folder: 'workspace_escola',
            resource_type: 'auto',
            public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
        };
    },
});

const upload = multer({ storage: storage });

const verificarToken = (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    next();
};

// 1. UPLOAD
router.post('/upload', verificarToken, upload.array('anexos', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Nenhum ficheiro.' });
        const urls = req.files.map(file => ({ url: file.path, nome: file.originalname, tipo: file.mimetype }));
        res.status(200).json({ success: true, anexos: urls });
    } catch (error) {
        res.status(500).json({ error: 'Erro no envio para a Nuvem.' });
    }
});

// 2. CRIAR POST
router.post('/posts', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome, autorTipo, escolaId, anexos, destino, destinoNome } = req.body;
        if (!texto && (!anexos || anexos.length === 0)) return res.status(400).json({ error: 'Publicação vazia.' });

        const database = await connectDB();
        const novoPost = {
            id: crypto.randomUUID(),
            escolaId: escolaId || 'DEFAULT',
            autorNome: autorNome || 'Desconhecido',
            autorTipo: autorTipo || 'Professor',
            destino: destino || 'global',
            destinoNome: destinoNome || 'Público Geral',
            texto: texto,
            anexos: anexos || [],
            dataCriacao: new Date().toISOString(),
            comentarios: [],
            likes: [],
            dislikes: []
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        res.status(201).json({ success: true, post: novoPost });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao publicar.' });
    }
});

// 3. BUSCAR TODOS OS POSTS (Feed)
router.get('/posts', verificarToken, async (req, res) => {
    try {
        const alunoRefId = req.query.alunoRefId;
        const database = await connectDB();
        let filtro = {}; 

        if (alunoRefId && alunoRefId !== 'undefined') {
            const aluno = await database.collection('alunos').findOne({ id: alunoRefId });
            if (aluno) {
                let minhasTurmas = [];
                if (aluno.turmas) minhasTurmas = Array.isArray(aluno.turmas) ? aluno.turmas : [aluno.turmas];
                else if (aluno.turma) minhasTurmas = [aluno.turma];
                
                filtro = {
                    $or: [
                        { destino: 'global' },
                        { destino: { $in: minhasTurmas } },
                        { destinoNome: { $in: minhasTurmas } }
                    ]
                };
            }
        }

        const posts = await database.collection('workspace_posts')
            .find(filtro)
            .sort({ dataCriacao: -1 })
            .limit(50)
            .toArray();
            
        res.status(200).json(posts);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar o feed.' });
    }
});

// 🚀 3.1 BUSCAR UM ÚNICO POST (O Motor da Sincronização em Tempo Real)
router.get('/posts/:id', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const database = await connectDB();
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        
        if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });
        res.status(200).json(post);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao sincronizar publicação.' });
    }
});

// 4. COMENTAR E GERAR NOTIFICAÇÃO 🔔
router.post('/posts/:id/comentarios', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto, autorNome } = req.body;

        const database = await connectDB();
        const novoComentario = { id: crypto.randomUUID(), autorNome: autorNome, texto: texto, dataCriacao: new Date().toISOString() };

        const postOriginal = await database.collection('workspace_posts').findOne({ id: postId });
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $push: { comentarios: novoComentario } }
        );

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });

        if (postOriginal) {
            const usuariosNotificar = new Set();
            if (postOriginal.autorNome !== autorNome) usuariosNotificar.add(postOriginal.autorNome);
            if (postOriginal.comentarios) {
                postOriginal.comentarios.forEach(c => {
                    if (c.autorNome !== autorNome) usuariosNotificar.add(c.autorNome);
                });
            }
            
            const notificacoesArray = Array.from(usuariosNotificar).map(destinatario => ({
                id: crypto.randomUUID(),
                escolaId: postOriginal.escolaId,
                destinatarioNome: destinatario,
                remetenteNome: autorNome,
                mensagem: `comentou na publicação: "${texto.substring(0, 20)}..."`,
                origem: 'post',
                origemId: postId,
                lida: false,
                data: new Date().toISOString()
            }));

            if (notificacoesArray.length > 0) {
                await database.collection('workspace_notificacoes').insertMany(notificacoesArray);
            }
        }

        res.status(201).json({ success: true, comentario: novoComentario });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao comentar.' });
    }
});

// 5. BUSCAR NOTIFICAÇÕES NÃO LIDAS 🔔
router.get('/notificacoes/:nomeDono', verificarToken, async (req, res) => {
    try {
        const nomeDono = req.params.nomeDono;
        const database = await connectDB();
        const notificacoes = await database.collection('workspace_notificacoes')
            .find({ destinatarioNome: nomeDono, lida: false })
            .sort({ data: -1 })
            .toArray();
            
        res.status(200).json(notificacoes);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar notificações.' });
    }
});

// MARCAR COMO LIDA
router.put('/notificacoes/:id/ler', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('workspace_notificacoes').updateOne({ id: req.params.id }, { $set: { lida: true } });
        res.status(200).json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao dispensar notificação.' }); 
    }
});

// 4.1 APAGAR COMENTÁRIO 🗑️
router.delete('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const { postId, comentarioId } = req.params;
        const database = await connectDB();
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId }, { $pull: { comentarios: { id: comentarioId } } }
        );
        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Comentário não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar comentário.' }); }
});

// 4.2 EDITAR COMENTÁRIO ✏️
router.put('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const { postId, comentarioId } = req.params;
        const { texto } = req.body;
        if (!texto) return res.status(400).json({ error: 'Vazio.' });

        const database = await connectDB();
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId, "comentarios.id": comentarioId }, { $set: { "comentarios.$.texto": texto } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao editar comentário.' }); }
});

// 7. REAGIR A UMA PUBLICAÇÃO (LIKE / DISLIKE) 👍👎
router.put('/posts/:id/reagir', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { userId, tipo, autorNome } = req.body; 
        if (!userId) return res.status(400).json({ error: 'ID do utilizador é obrigatório.' });

        const database = await connectDB();
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        if (!post) return res.status(404).json({ error: 'Publicação não encontrada.' });

        if (autorNome && post.autorNome !== autorNome) { 
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(),
                escolaId: post.escolaId,
                destinatarioNome: post.autorNome,
                remetenteNome: autorNome,
                mensagem: `reagiu à sua publicação.`,
                origem: 'post',
                origemId: postId,
                lida: false,
                data: new Date().toISOString()
            });
        }

        let likes = Array.isArray(post.likes) ? post.likes : [];
        let dislikes = Array.isArray(post.dislikes) ? post.dislikes : [];

        likes = likes.filter(id => id !== userId);
        dislikes = dislikes.filter(id => id !== userId);

        if (tipo === 'like') likes.push(userId);
        if (tipo === 'dislike') dislikes.push(userId);

        await database.collection('workspace_posts').updateOne(
            { id: postId }, { $set: { likes: likes, dislikes: dislikes } }
        );

        res.status(200).json({ success: true, likes, dislikes });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar reação.' }); }
});

// 8. APAGAR E EDITAR UMA PUBLICAÇÃO
router.delete('/posts/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const result = await database.collection('workspace_posts').deleteOne({ id: req.params.id });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar publicação.' }); }
});

router.put('/posts/:id', verificarToken, async (req, res) => {
    try {
        const { texto } = req.body;
        const database = await connectDB();
        const result = await database.collection('workspace_posts').updateOne(
            { id: req.params.id }, { $set: { texto: texto } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Publicação não encontrada.' });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao editar publicação.' }); }
});

// 9. CHAT DA TURMA E DEMAIS ROTAS ...
router.get('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mensagens = await database.collection('workspace_chats').find({ turmaId: req.params.turmaId }).sort({ data: 1 }).toArray();
        res.status(200).json(mensagens);
    } catch (error) { res.status(500).json({ error: 'Erro ao carregar o chat.' }); }
});

router.post('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome } = req.body;
        const database = await connectDB();
        const novaMensagem = { id: crypto.randomUUID(), turmaId: req.params.turmaId, autorNome: autorNome || 'Desconhecido', texto: texto, data: new Date().toISOString() };
        await database.collection('workspace_chats').insertOne(novaMensagem);
        
        const alunosDaTurma = await database.collection('alunos').find({ $or: [{ turma: req.params.turmaId }, { turmas: req.params.turmaId }] }).toArray();
        const notificacoesChat = [];
        alunosDaTurma.forEach(aluno => {
            if (aluno.nome !== autorNome) {
                notificacoesChat.push({
                    id: crypto.randomUUID(), escolaId: aluno.escolaId || 'DEFAULT', destinatarioNome: aluno.nome, remetenteNome: autorNome,
                    mensagem: `enviou uma mensagem no fórum da turma.`, origem: 'chat', origemId: req.params.turmaId, destinoNome: 'Fórum da Turma', lida: false, data: new Date().toISOString()
                });
            }
        });
        if (notificacoesChat.length > 0) await database.collection('workspace_notificacoes').insertMany(notificacoesChat);
        res.status(201).json({ success: true, mensagem: novaMensagem });
    } catch (error) { res.status(500).json({ error: 'Erro ao enviar mensagem.' }); }
});

router.put('/perfil', verificarToken, async (req, res) => {
    try {
        const { id, senhaAtual, novaSenha } = req.body;
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ id: id, senha: senhaAtual });
        if (!user) return res.status(401).json({ error: 'A senha atual está incorreta.' });
        await database.collection('usuarios').updateOne({ id: id }, { $set: { senha: novaSenha } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar a senha.' }); }
});

router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, avatarUrl } = req.body;
        const database = await connectDB();
        await database.collection('usuarios').updateOne({ id: id }, { $set: { avatar: avatarUrl } });
        if (alunoRefId) await database.collection('alunos').updateOne({ id: alunoRefId }, { $set: { avatar: avatarUrl } });
        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar a foto de perfil.' }); }
});

router.post('/entregas', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const novaEntrega = { ...req.body, id: crypto.randomUUID(), dataEntrega: new Date().toISOString() };
        await database.collection('workspace_entregas').insertOne(novaEntrega);
        res.status(201).json({ success: true, entrega: novaEntrega });
    } catch (error) { res.status(500).json({ error: 'Erro ao registar a entrega.' }); }
});

router.get('/entregas/verificar/:eventoId/:alunoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entrega = await database.collection('workspace_entregas').findOne({ eventoId: req.params.eventoId, alunoId: req.params.alunoId });
        res.status(200).json(entrega ? { entregue: true, detalhes: entrega } : { entregue: false });
    } catch (error) { res.status(500).json({ error: 'Erro ao verificar entrega.' }); }
});

router.get('/entregas/tarefa/:eventoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entregas = await database.collection('workspace_entregas').find({ eventoId: req.params.eventoId }).sort({ dataEntrega: -1 }).toArray();
        res.status(200).json(entregas);
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar trabalhos entregues.' }); }
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
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar dicionário de avatares.' }); }
});

router.put('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('eventos').updateOne({ id: req.params.id }, { $set: { descricao: req.body.descricao } });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao editar tarefa.' }); }
});

router.delete('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('eventos').deleteOne({ id: req.params.id });
        await database.collection('entregas').deleteMany({ eventoId: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao apagar tarefa.' }); }
});

module.exports = router;