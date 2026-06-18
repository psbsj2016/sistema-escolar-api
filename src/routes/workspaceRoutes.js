const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
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
    
    // Simplificação: num cenário real, o ID do utilizador é extraído do token aqui.
    // req.usuario = jwt.verify(token, process.env.JWT_SECRET);
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

// 2. CRIAR POST (Agora com seleção de público)
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
            destino: destino || 'global', // ID da turma ou 'global'
            destinoNome: destinoNome || 'Público Geral', // Nome da turma ou 'Geral'
            texto: texto,
            anexos: anexos || [],
            dataCriacao: new Date().toISOString(),
            comentarios: [],
            likes: 0
        };

        await database.collection('workspace_posts').insertOne(novoPost);
        res.status(201).json({ success: true, post: novoPost });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao publicar.' });
    }
});

// 3. BUSCAR POSTS (Agora com Fechadura de Privacidade)
router.get('/posts', verificarToken, async (req, res) => {
    try {
        const alunoRefId = req.query.alunoRefId;
        const database = await connectDB();
        let filtro = {}; // Por defeito, puxa tudo (para Gestores e Professores)

        // Se quem está a pedir for um Aluno (tem um alunoRefId)
        if (alunoRefId && alunoRefId !== 'undefined') {
            const aluno = await database.collection('alunos').findOne({ id: alunoRefId });
            
            if (aluno) {
                // Descobre as turmas do aluno
                let minhasTurmas = [];
                if (aluno.turmas) minhasTurmas = Array.isArray(aluno.turmas) ? aluno.turmas : [aluno.turmas];
                else if (aluno.turma) minhasTurmas = [aluno.turma];
                
                // O Aluno só vê os posts que são "Globais" OU que pertencem às suas turmas
                filtro = {
                    $or: [
                        { destino: 'global' },
                        { destino: { $in: minhasTurmas } },
                        { destinoNome: { $in: minhasTurmas } } // Segurança extra caso o filtro seja por nome
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

// 4. COMENTAR E GERAR NOTIFICAÇÃO 🔔
router.post('/posts/:id/comentarios', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto, autorNome } = req.body;

        const database = await connectDB();
        const novoComentario = { id: crypto.randomUUID(), autorNome: autorNome, texto: texto, data: new Date().toISOString() };

        // Procura o post para saber quem é o dono dele
        const postOriginal = await database.collection('workspace_posts').findOne({ id: postId });

        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $push: { comentarios: novoComentario } }
        );

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });

        // 🔔 Cria a notificação se o autor do comentário for diferente do dono do post
        if (postOriginal && postOriginal.autorNome !== autorNome) {
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(),
                escolaId: postOriginal.escolaId,
                destinatarioNome: postOriginal.autorNome, // A quem se destina a notificação
                remetenteNome: autorNome,
                mensagem: `comentou na sua publicação: "${texto.substring(0, 20)}..."`,
                lida: false,
                data: new Date().toISOString()
            });
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

// 6. MARCAR NOTIFICAÇÕES COMO LIDAS 🔔
router.put('/notificacoes/ler/:nomeDono', verificarToken, async (req, res) => {
    try {
        const nomeDono = req.params.nomeDono;
        const database = await connectDB();
        await database.collection('workspace_notificacoes').updateMany(
            { destinatarioNome: nomeDono, lida: false },
            { $set: { lida: true } }
        );
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar.' });
    }
});

// 7. DAR GOSTO (LIKE) NUMA PUBLICAÇÃO
router.put('/posts/:id/like', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const database = await connectDB();
        
        // Soma +1 aos likes da publicação
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $inc: { likes: 1 } }
        );

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar gosto.' });
    }
});

// 8. APAGAR UMA PUBLICAÇÃO
router.delete('/posts/:id', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const database = await connectDB();
        
        // Remove a publicação inteira da base de dados
        const result = await database.collection('workspace_posts').deleteOne({ id: postId });
        
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Post não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao apagar publicação.' });
    }
});

// 9. BUSCAR MENSAGENS DO FÓRUM DA TURMA
router.get('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mensagens = await database.collection('workspace_chats')
            .find({ turmaId: req.params.turmaId })
            .sort({ data: 1 }) // Mais antigas no topo, mais novas em baixo
            .toArray();
        res.status(200).json(mensagens);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar o chat.' });
    }
});

// 10. ENVIAR MENSAGEM PARA O FÓRUM DA TURMA
router.post('/chat/:turmaId', verificarToken, async (req, res) => {
    try {
        const { texto, autorNome } = req.body;
        if (!texto) return res.status(400).json({ error: 'A mensagem não pode estar vazia.' });

        const database = await connectDB();
        const novaMensagem = {
            id: crypto.randomUUID(),
            turmaId: req.params.turmaId,
            autorNome: autorNome || 'Desconhecido',
            texto: texto,
            data: new Date().toISOString()
        };

        await database.collection('workspace_chats').insertOne(novaMensagem);
        res.status(201).json({ success: true, mensagem: novaMensagem });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao enviar mensagem.' });
    }
});

// 11. ATUALIZAR PERFIL DO ALUNO (MUDAR SENHA) COM SEGURANÇA
router.put('/perfil', verificarToken, async (req, res) => {
    try {
        const { id, senhaAtual, novaSenha } = req.body;
        
        if (!id || !senhaAtual || !novaSenha || novaSenha.length < 6) {
            return res.status(400).json({ error: 'Dados inválidos ou senha nova muito curta.' });
        }

        const database = await connectDB();
        
        // 🛡️ Segurança: Primeiro verifica se a senha atual está correta!
        const user = await database.collection('usuarios').findOne({ id: id, senha: senhaAtual });
        
        if (!user) {
            return res.status(401).json({ error: 'A senha atual está incorreta.' });
        }

        // Se estiver certa, guarda a nova senha
        await database.collection('usuarios').updateOne(
            { id: id },
            { $set: { senha: novaSenha } }
        );

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar a senha.' });
    }
});

// 12. ENTREGAR TRABALHO / TAREFA
router.post('/entregas', verificarToken, async (req, res) => {
    try {
        const { eventoId, alunoId, alunoNome, arquivoUrl, arquivoNome, observacao } = req.body;
        if (!eventoId || !arquivoUrl) return res.status(400).json({ error: 'O ficheiro é obrigatório.' });

        const database = await connectDB();
        const novaEntrega = {
            id: crypto.randomUUID(),
            eventoId: eventoId,
            alunoId: alunoId,
            alunoNome: alunoNome,
            arquivoUrl: arquivoUrl,
            arquivoNome: arquivoNome,
            observacao: observacao || '',
            dataEntrega: new Date().toISOString()
        };

        await database.collection('workspace_entregas').insertOne(novaEntrega);
        res.status(201).json({ success: true, entrega: novaEntrega });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registar a entrega.' });
    }
});

// 13. VERIFICAR SE O ALUNO JÁ ENTREGOU UMA TAREFA ESPECÍFICA
router.get('/entregas/verificar/:eventoId/:alunoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entrega = await database.collection('workspace_entregas').findOne({
            eventoId: req.params.eventoId,
            alunoId: req.params.alunoId
        });
        
        if (entrega) {
            res.status(200).json({ entregue: true, detalhes: entrega });
        } else {
            res.status(200).json({ entregue: false });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erro ao verificar entrega.' });
    }
});

// 14. LISTAR ENTREGAS DE UMA TAREFA (PARA PROFESSORES/GESTORES)
router.get('/entregas/tarefa/:eventoId', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const entregas = await database.collection('workspace_entregas')
            .find({ eventoId: req.params.eventoId })
            .sort({ dataEntrega: -1 }) // As entregas mais recentes aparecem primeiro
            .toArray();
            
        res.status(200).json(entregas);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar trabalhos entregues.' });
    }
});

module.exports = router;