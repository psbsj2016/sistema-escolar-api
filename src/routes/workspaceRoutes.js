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
        // 1. Descobre se é um documento ou uma imagem/vídeo
        const ehDocumento = file.originalname.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|zip)$/i);
        
        // 2. Se for documento, tem de ser 'raw' e TEM DE MANTER a extensão no nome!
        if (ehDocumento) {
            return {
                folder: 'workspace_escola',
                resource_type: 'raw',
                public_id: `${Date.now()}_${file.originalname}` // Mantém a extensão intacta!
            };
        }
        
        // 3. Se for imagem/vídeo, deixa no 'auto' e tira a extensão (o Cloudinary põe depois)
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

        // 🔔 Gatilho: Notificar quem interagiu com o post
        if (postOriginal) {
            const usuariosNotificar = new Set();
            
            // Adiciona o dono do post
            if (postOriginal.autorNome !== autorNome) usuariosNotificar.add(postOriginal.autorNome);
            
            // Adiciona quem já comentou
            if (postOriginal.comentarios) {
                postOriginal.comentarios.forEach(c => {
                    if (c.autorNome !== autorNome) usuariosNotificar.add(c.autorNome);
                });
            }
            
            // Adiciona quem já curtiu/descurtiu (se houver IDs mapeados para nomes ou se os nomes forem usados)
            // Nota: Se usarmos IDs, o ideal é buscar o nome. Para simplificar e manter compatível com o seu sistema atual baseado em nomes:
            const notificacoesArray = Array.from(usuariosNotificar).map(destinatario => ({
                id: crypto.randomUUID(),
                escolaId: postOriginal.escolaId,
                destinatarioNome: destinatario,
                remetenteNome: autorNome,
                mensagem: `interagiu no post: "${texto.substring(0, 20)}..."`,
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

// 4.1 APAGAR COMENTÁRIO 🗑️
router.delete('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const { postId, comentarioId } = req.params;
        const database = await connectDB();
        
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $pull: { comentarios: { id: comentarioId } } } // Remove da array o comentário com este ID
        );

        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Comentário não encontrado.' });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao apagar comentário.' });
    }
});

// 4.2 EDITAR COMENTÁRIO ✏️
router.put('/posts/:postId/comentarios/:comentarioId', verificarToken, async (req, res) => {
    try {
        const { postId, comentarioId } = req.params;
        const { texto } = req.body;

        if (!texto) {
            return res.status(400).json({ error: 'O texto do comentário não pode estar vazio.' });
        }

        const database = await connectDB();
        
        // Atualiza o texto do comentário específico dentro da array 'comentarios'
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId, "comentarios.id": comentarioId },
            { $set: { "comentarios.$.texto": texto } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Comentário ou post não encontrado.' });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao editar comentário.' });
    }
});

// 7. REAGIR A UMA PUBLICAÇÃO (LIKE / DISLIKE) 👍👎
router.put('/posts/:id/reacao', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { userId, tipo } = req.body; // 'like', 'dislike', ou 'none'
        const database = await connectDB();
        
        const post = await database.collection('workspace_posts').findOne({ id: postId });
        // Código existente de update executado com sucesso...
        // 🔔 Gatilho: Notificar o dono do post sobre a reação
        if (post && post.autorNome !== req.body.autorNome) { // Certifique-se de enviar autorNome no body do frontend
            await database.collection('workspace_notificacoes').insertOne({
                id: crypto.randomUUID(),
                escolaId: post.escolaId,
                destinatarioNome: post.autorNome,
                remetenteNome: req.body.autorNome,
                mensagem: `reagiu à sua publicação.`,
                origem: 'post',
                origemId: postId,
                lida: false,
                data: new Date().toISOString()
            });
        }

        // Garante que são arrays (proteção para posts antigos que tinham o like como número)
        let likes = Array.isArray(post.likes) ? post.likes : [];
        let dislikes = Array.isArray(post.dislikes) ? post.dislikes : [];

        // Remove a pessoa das duas listas (limpa o estado dela)
        likes = likes.filter(id => id !== userId);
        dislikes = dislikes.filter(id => id !== userId);

        // Adiciona na lista certa
        if (tipo === 'like') likes.push(userId);
        if (tipo === 'dislike') dislikes.push(userId);

        await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $set: { likes: likes, dislikes: dislikes } }
        );

        res.status(200).json({ success: true, likes, dislikes });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar reação.' });
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

// 8.1 EDITAR UMA PUBLICAÇÃO ✏️
router.put('/posts/:id', verificarToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { texto } = req.body;

        if (!texto) {
            return res.status(400).json({ error: 'O texto não pode estar vazio.' });
        }

        const database = await connectDB();
        
        // Atualiza apenas o campo 'texto' do post com o ID correspondente
        const result = await database.collection('workspace_posts').updateOne(
            { id: postId },
            { $set: { texto: texto } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Publicação não encontrada.' });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao editar publicação.' });
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
        
        // 🔔 Gatilho: Notificar todos os membros da turma (exceto quem enviou)
        const alunosDaTurma = await database.collection('alunos').find({ 
            $or: [{ turma: req.params.turmaId }, { turmas: req.params.turmaId }] 
        }).toArray();

        const notificacoesChat = [];
        alunosDaTurma.forEach(aluno => {
            if (aluno.nome !== autorNome) {
                notificacoesChat.push({
                    id: crypto.randomUUID(),
                    escolaId: aluno.escolaId || 'DEFAULT',
                    destinatarioNome: aluno.nome,
                    remetenteNome: autorNome,
                    mensagem: `enviou uma mensagem no fórum da turma.`,
                    origem: 'chat',
                    origemId: req.params.turmaId,
                    destinoNome: 'Fórum da Turma', // 🛡️ CORRIGIDO: Removida a variável fantasma
                    lida: false,
                    data: new Date().toISOString()
                });
            }
        });

        if (notificacoesChat.length > 0) {
            await database.collection('workspace_notificacoes').insertMany(notificacoesChat);
        }
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

// 11.1 ATUALIZAR AVATAR DO PERFIL 📸
router.put('/perfil/avatar', verificarToken, async (req, res) => {
    try {
        const { id, alunoRefId, avatarUrl } = req.body;
        if (!id || !avatarUrl) return res.status(400).json({ error: 'Dados inválidos.' });

        const database = await connectDB();
        
        // Atualiza a foto no login do utilizador
        await database.collection('usuarios').updateOne(
            { id: id }, 
            { $set: { avatar: avatarUrl } }
        );

        // Se for um aluno, atualiza a foto também na ficha de matrícula (para a secretaria ver)
        if (alunoRefId) {
            await database.collection('alunos').updateOne(
                { id: alunoRefId }, 
                { $set: { avatar: avatarUrl } }
            );
        }

        res.status(200).json({ success: true, avatar: avatarUrl });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar a foto de perfil.' });
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

// 15. BUSCAR DICIONÁRIO DE AVATARES DA ESCOLA (Para o Feed, Chat e Alertas)
router.get('/avatars', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        const mapaAvatars = {};
        
        // Puxa apenas as fotos para poupar internet
        const alunos = await database.collection('alunos').find({ avatar: { $exists: true, $ne: null } }).toArray();
        const usuarios = await database.collection('usuarios').find({ avatar: { $exists: true, $ne: null } }).toArray();

        alunos.forEach(a => { if(a.nome) mapaAvatars[a.nome] = a.avatar; });
        usuarios.forEach(u => {
            const nome = u.nome || u.login;
            if(nome) mapaAvatars[nome] = u.avatar;
        });

        res.status(200).json(mapaAvatars);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar dicionário de avatares.' });
    }
});

// 16. EDITAR INSTRUÇÕES DA TAREFA ✏️
router.put('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const { descricao } = req.body;
        const database = await connectDB();
        await database.collection('eventos').updateOne(
            { id: req.params.id },
            { $set: { descricao: descricao } }
        );
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao editar tarefa.' });
    }
});

// 17. APAGAR TAREFA 🗑️
router.delete('/eventos/:id', verificarToken, async (req, res) => {
    try {
        const database = await connectDB();
        // 1. Apaga a tarefa
        await database.collection('eventos').deleteOne({ id: req.params.id });
        // 2. Apaga também todos os trabalhos (entregas) que os alunos já tinham feito para esta tarefa
        await database.collection('entregas').deleteMany({ eventoId: req.params.id });
        
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao apagar tarefa.' });
    }
});

module.exports = router;