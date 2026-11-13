// backend/routes/videoAulasRoutes.js - Motor Exclusivo de Vídeo-Aulas, Playlists e Lives (Estilo YouTube + Meet)
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const fs = require('fs');
const os = require('os');

// ⚙️ PARÂMETROS AJUSTÁVEIS
const LIMITE_MB_VIDEO = 800;
const PASTA_NUVEM_VIDEOS = 'workspace_video_aulas';

// 🛡️ Filtro de Alunos Ativos (Mesmo padrão de segurança do WorkSpace)
const ehAlunoAtivo = (aluno) => {
    if (!aluno) return false;
    const st = String(aluno.status || 'Ativo').trim().toLowerCase();
    if (st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist')) {
        return false;
    }
    return st === 'ativo' || st === '';
};

// ⏱️ Proteção contra Timeout em Uploads Grandes (15 minutos)
router.use((req, res, next) => {
    req.setTimeout(900000, () => {
        if (!res.headersSent) {
            res.status(408).json({ error: 'Tempo limite esgotado durante o envio do vídeo.' });
        }
        req.destroy();
    });
    next();
});

// ☁️ Configuração Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// 💾 Armazenamento Temporário em Disco para não esgotar a memória RAM do servidor
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, os.tmpdir());
    },
    filename: function (req, file, cb) {
        const nomeSeguro = String(file.originalname || 'video.webm')
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-zA-Z0-9.\-_]/g, '_');
        cb(null, `vid_${Date.now()}_${nomeSeguro}`);
    }
});

const uploadVideo = multer({
    storage: storage,
    limits: { fileSize: LIMITE_MB_VIDEO * 1024 * 1024, files: 2 }
});

// 🔒 Middleware de Autenticação
const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login.' });
    next();
};

// Helper para criar código identificador (Slug) de cada Assunto/Playlist para os links extraídos
const gerarSlugAssunto = (texto) => {
    return String(texto || 'geral')
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'geral';
};

// 🛡️ Verifica no banco de dados se o utilizador logado é Professor, Gestor ou Secretaria (NUNCA Aluno!)
async function verificarSeEhProfessorOuGestor(db, req) {
    try {
        const idToken = req.userId || req.query.userId || req.body?.autorId || '';
        if (idToken) {
            const u = await db.collection('usuarios').findOne({ id: String(idToken) });
            if (u) {
                const tipoLimpo = String(u.tipo || 'Gestor').trim().toLowerCase();
                if (tipoLimpo === 'aluno' || u.alunoRefId) return false;
                return true; // É Gestor, Professor, Secretaria ou Dono
            }
            // Se o ID estiver apenas na coleção de alunos, é Aluno
            const al = await db.collection('alunos').findOne({ id: String(idToken) });
            if (al) return false;
        }
        const roleParam = String(req.query.role || req.body?.role || '').trim().toLowerCase();
        return roleParam === 'professor' || roleParam === 'gestor' || roleParam === 'secretaria';
    } catch (e) {
        return false;
    }
}

// ============================================================================
// 1. ASSINATURA DIRETA CLOUDINARY + UPLOAD DE VÍDEO-AULAS SEM TRAVAMENTO
// ============================================================================

// 🚀 Rota A: Gera assinatura segura para o navegador enviar o vídeo DIRETO ao Cloudinary (Sem limite de MB da Vercel!)
router.get('/assinatura-upload', verificarToken, (req, res) => {
    try {
        const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
        const apiKey = process.env.CLOUDINARY_API_KEY;
        const apiSecret = process.env.CLOUDINARY_API_SECRET;

        if (!cloudName || !apiKey || !apiSecret) {
            return res.status(500).json({ success: false, error: 'Credenciais do Cloudinary não configuradas no servidor.' });
        }

        const timestamp = Math.round(new Date().getTime() / 1000);
        const paramsToSign = {
             timestamp: timestamp,
             folder: PASTA_NUVEM_VIDEOS
        };

        const signature = cloudinary.utils.api_sign_request(paramsToSign, apiSecret);

        res.status(200).json({
            success: true,
            cloudName,
            apiKey,
            timestamp,
            signature,
            folder: PASTA_NUVEM_VIDEOS
        });
    } catch (error) {
        console.error('🚨 Erro ao gerar assinatura Cloudinary:', error);
        res.status(500).json({ success: false, error: 'Falha ao autorizar upload na nuvem.' });
    }
});

// 🚀 Rota B: Fallback de upload pelo servidor (usando uploader.upload padrão que não trava)
router.post('/upload-video', verificarToken, (req, res) => {
    const processador = uploadVideo.single('video');

    processador(req, res, async (err) => {
        if (res.headersSent) return;
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: `O vídeo excede o limite de ${LIMITE_MB_VIDEO}MB.` });
            }
            return res.status(500).json({ error: 'Falha ao receber o ficheiro de vídeo no servidor.' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Nenhum ficheiro de vídeo recebido.' });
        }

        const caminhoTemp = req.file.path;

        try {
            const nomeOriginal = req.file.originalname || `aula_${Date.now()}.mp4`;
            const nomeSeguro = String(nomeOriginal)
                .normalize("NFD")
                .replace(/[\u0300-\u036f]/g, "")
                .replace(/[^a-zA-Z0-9.\-_]/g, '_');
            const publicId = `aula_${Date.now()}_${nomeSeguro.split('.')[0]}`;

            const resultado = await cloudinary.uploader.upload(caminhoTemp, {
                folder: PASTA_NUVEM_VIDEOS,
                resource_type: 'video',
                public_id: publicId
            });

            let miniaturaAuto = null;
            if (resultado.secure_url && resultado.secure_url.includes('/video/upload/')) {
                miniaturaAuto = resultado.secure_url.replace(/\.(mp4|webm|mov|mkv|ogg)$/i, '.jpg');
            }

            res.status(200).json({
                success: true,
                url: resultado.secure_url,
                miniatura: miniaturaAuto,
                duracaoSegundos: resultado.duration ? Math.round(resultado.duration) : 0,
                nomeOriginal: req.file.originalname
            });
        } catch (erroUpload) {
            console.error('🚨 Erro ao enviar vídeo para o Cloudinary:', erroUpload);
            res.status(500).json({ error: 'Erro ao guardar o vídeo na nuvem: ' + (erroUpload.message || 'Falha desconhecida') });
        } finally {
            if (caminhoTemp && fs.existsSync(caminhoTemp)) {
                try { fs.unlinkSync(caminhoTemp); } catch (e) {}
            }
        }
    });
});

// ============================================================================
// 2. LISTAR CATÁLOGO COMPLETO (VÍDEOS, SEQUÊNCIAS POR ASSUNTO E LIVE ATIVA)
// ============================================================================
router.get('/catalogo', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        const userId = req.query.userId || '';
        const alunoRefId = req.query.alunoRefId || '';
        const isGestorOuProf = await verificarSeEhProfessorOuGestor(db, req);
        const role = isGestorOuProf ? 'professor' : 'aluno';

        // ⏱️ Limpeza automática: Encerra lives que já ultrapassaram o limite máximo de 4 horas (240 min)
        const limiteQuatroHorasAtras = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
        await db.collection('workspace_video_lives').updateMany(
            { ativa: true, iniciadaEm: { $lt: limiteQuatroHorasAtras } },
            { $set: { ativa: false, encerradaEm: new Date().toISOString(), motivoEncerramento: 'Limite de 4h atingido' } }
        );

        const filtroEscola = (escolaId && escolaId !== 'DEFAULT')
            ? { $in: [escolaId, 'DEFAULT', null] }
            : { $exists: true };

        let filtroTurma = { escolaId: filtroEscola };

        // Se for Aluno, filtra apenas os vídeos e lives destinados às turmas dele ou 'global'
        let minhasTurmas = [];
        if (role === 'aluno' && (userId || alunoRefId)) {
            const idsBusca = [userId, alunoRefId].filter(x => x && x !== 'undefined');
            const contaUser = idsBusca.length
                ? await db.collection('usuarios').findOne({ $or: [{ id: { $in: idsBusca } }, { alunoRefId: { $in: idsBusca } }] })
                : null;
            const fichaAluno = idsBusca.length
                ? await db.collection('alunos').findOne({
                    $or: [
                        { id: { $in: idsBusca } },
                        ...(contaUser?.alunoRefId ? [{ id: String(contaUser.alunoRefId) }] : [])
                    ]
                })
                : null;

            const extrair = (v) => {
                if (!v) return;
                if (Array.isArray(v)) v.forEach(extrair);
                else if (typeof v === 'object') {
                    if (v.id) minhasTurmas.push(String(v.id).trim());
                    if (v.nome) minhasTurmas.push(String(v.nome).trim());
                } else {
                    minhasTurmas.push(String(v).trim());
                }
            };

            if (contaUser) { extrair(contaUser.turma); extrair(contaUser.turmas); }
            if (fichaAluno) { extrair(fichaAluno.turma); extrair(fichaAluno.turmaId); extrair(fichaAluno.turmas); }
            minhasTurmas = Array.from(new Set(minhasTurmas.filter(Boolean)));

            if (minhasTurmas.length > 0) {
                filtroTurma = {
                    escolaId: filtroEscola,
                    $or: [
                        { destino: 'global' },
                        { destino: { $in: ['global', ...minhasTurmas] } },
                        { destinoNome: { $in: ['Todas as Turmas', 'Público Geral', 'Global', ...minhasTurmas] } }
                    ]
                };
            }
        }

        const videos = await db.collection('workspace_video_aulas')
            .find(filtroTurma)
            .sort({ assuntoSlug: 1, ordem: 1, dataCriacao: -1 })
            .toArray();

        // Agrupa automaticamente os vídeos em Sequências / Playlists por Assunto
        const mapaAssuntos = {};
        videos.forEach(v => {
            const nomeAssunto = String(v.assunto || 'Aulas Gerais').trim();
            const slug = v.assuntoSlug || gerarSlugAssunto(nomeAssunto);
            if (!mapaAssuntos[slug]) {
                mapaAssuntos[slug] = {
                    slug: slug,
                    assunto: nomeAssunto,
                    capa: v.miniatura || null,
                    totalVideos: 0,
                    videos: []
                };
            }
            if (!mapaAssuntos[slug].capa && v.miniatura) {
                mapaAssuntos[slug].capa = v.miniatura;
            }
            mapaAssuntos[slug].videos.push(v);
            mapaAssuntos[slug].totalVideos = mapaAssuntos[slug].videos.length;
        });

        // Ordena cada sequência pela ordem numérica da aula (Aula 1, Aula 2, Aula 3...)
        Object.values(mapaAssuntos).forEach(pl => {
            pl.videos.sort((a, b) => (Number(a.ordem) || 999) - (Number(b.ordem) || 999));
        });

        // Verifica se há uma Transmissão Ao Vivo (Live) ativa para esta escola/turma
        const livesAtivas = await db.collection('workspace_video_lives')
            .find({ ativa: true, escolaId: filtroEscola })
            .sort({ iniciadaEm: -1 })
            .toArray();

        const liveAtivaParaUsuario = livesAtivas.find(lv => {
            if (role !== 'aluno') return true;
            if (!lv.destino || lv.destino === 'global') return true;
            return minhasTurmas.some(t =>
                t.toLowerCase() === String(lv.destino).toLowerCase() ||
                t.toLowerCase() === String(lv.destinoNome || '').toLowerCase()
            );
        }) || null;

        // Lista as turmas da escola para o seletor do Professor
        const turmasEscola = role !== 'aluno'
            ? await db.collection('turmas').find({}).project({ id: 1, nome: 1 }).toArray()
            : [];

       res.status(200).json({
            success: true,
            permissaoGestao: isGestorOuProf,
            videos: videos,
            sequencias: Object.values(mapaAssuntos),
            liveAtiva: liveAtivaParaUsuario,
            turmas: turmasEscola
        });
    } catch (error) {
        console.error('🚨 Erro ao carregar catálogo de vídeo-aulas:', error);
        res.status(500).json({ success: false, error: 'Erro ao carregar catálogo de vídeo-aulas.' });
    }
});

// ============================================================================
// 3. PUBLICAR NOVA VÍDEO-AULA OU GRAVAÇÃO DE LIVE
// ============================================================================
router.post('/videos', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const b = req.body || {};

        if (!b.titulo || !b.urlVideo) {
            return res.status(400).json({ error: 'O título e o vídeo são obrigatórios.' });
        }

        const assuntoLimpo = String(b.assunto || 'Aulas Gerais').trim();
        const assuntoSlug = gerarSlugAssunto(assuntoLimpo);
        const escolaId = b.escolaId || 'DEFAULT';

        // Se não enviou número de ordem na sequência, calcula automaticamente o próximo número dentro daquele assunto
        let ordemSequencia = parseInt(b.ordem, 10);
        if (!ordemSequencia || isNaN(ordemSequencia)) {
            const qtdNoAssunto = await db.collection('workspace_video_aulas').countDocuments({ assuntoSlug });
            ordemSequencia = qtdNoAssunto + 1;
        }

        const novoVideo = {
            id: 'vid_' + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: String(b.titulo).trim(),
            descricao: String(b.descricao || '').trim(),
            assunto: assuntoLimpo,
            assuntoSlug: assuntoSlug,
            ordem: ordemSequencia,
            urlVideo: String(b.urlVideo).trim(),
            miniatura: b.miniatura || null,
            duracaoSegundos: Number(b.duracaoSegundos) || 0,
            destino: b.destino || 'global',
            destinoNome: b.destinoNome || 'Todas as Turmas',
            autorId: b.autorId || '',
            autorNome: b.autorNome || 'Professor',
            isGravacaoLive: Boolean(b.isGravacaoLive),
            visualizacoes: 0,
            likes: [],
            concluidosPor: [],
            comentarios: [],
            dataCriacao: new Date().toISOString()
        };

        await db.collection('workspace_video_aulas').insertOne(novoVideo);

        // Dispara evento em tempo real e notificação para os alunos da turma
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_AULA_NOVA',
                video: novoVideo,
                escolaId: 'DEFAULT'
            });
        }

        try {
            const alunosAtivos = (await db.collection('alunos').find({}).toArray()).filter(ehAlunoAtivo);
            const destinoLower = String(novoVideo.destino).toLowerCase();
            const destinoNomeLower = String(novoVideo.destinoNome).toLowerCase();

            const alunosAlvo = destinoLower === 'global'
                ? alunosAtivos
                : alunosAtivos.filter(a => {
                    const turmasA = Array.isArray(a.turmas) ? a.turmas : [a.turma, a.turmaId];
                    return turmasA.some(t => t && (String(t).toLowerCase() === destinoLower || String(t).toLowerCase() === destinoNomeLower));
                });

            if (alunosAlvo.length > 0) {
                const nomesDest = [];
                const prefixoMsg = novoVideo.isGravacaoLive
                    ? `disponibilizou a gravação da aula ao vivo: "${novoVideo.titulo}"`
                    : `publicou uma nova vídeo-aula em [${novoVideo.assunto}]: "${novoVideo.titulo}"`;

                const notifs = alunosAlvo.map(al => {
                    const nomeAl = al.nome || al.login;
                    if (nomeAl) nomesDest.push(nomeAl);
                    return {
                        id: crypto.randomUUID(),
                        escolaId: escolaId,
                        destinatarioTipo: 'Aluno',
                        destinatarioNome: nomeAl,
                        remetenteNome: novoVideo.autorNome,
                        mensagem: prefixoMsg,
                        origem: 'video_aula',
                        origemId: novoVideo.id,
                        destinoNome: novoVideo.assunto,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notifs.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notifs);
                    if (global.workspaceStream) {
                        global.workspaceStream.emit('evento_realtime', {
                            type: 'NOVA_NOTIFICACAO',
                            destinatarios: nomesDest,
                            destinatariosTipo: 'Aluno',
                            escolaId: escolaId
                        });
                    }
                }
            }
        } catch (errNoti) {}

        res.status(201).json({ success: true, video: novoVideo });
    } catch (error) {
        console.error('🚨 Erro ao publicar vídeo-aula:', error);
        res.status(500).json({ error: 'Erro ao guardar a vídeo-aula.' });
    }
});

// ============================================================================
// 4. EDITAR E APAGAR VÍDEO-AULA
// ============================================================================
router.put('/videos/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const b = req.body || {};
        const assuntoLimpo = String(b.assunto || 'Aulas Gerais').trim();

        const camposAtualizar = {
            titulo: String(b.titulo || '').trim(),
            descricao: String(b.descricao || '').trim(),
            assunto: assuntoLimpo,
            assuntoSlug: gerarSlugAssunto(assuntoLimpo),
            ordem: parseInt(b.ordem, 10) || 1,
            destino: b.destino || 'global',
            destinoNome: b.destinoNome || 'Todas as Turmas'
        };
        if (b.urlVideo) camposAtualizar.urlVideo = String(b.urlVideo).trim();

        await db.collection('workspace_video_aulas').updateOne(
            { id: req.params.id },
            { $set: camposAtualizar }
        );

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar vídeo-aula.' });
    }
});

router.delete('/videos/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_video_aulas').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao remover vídeo-aula.' });
    }
});

// ============================================================================
// 5. RESOLVER LINK EXTRAÍDO (VÍDEO INDIVIDUAL OU SEQUÊNCIA POR ASSUNTO)
// ============================================================================
router.get('/compartilhado/:tipo/:alvo', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { tipo, alvo } = req.params;

        if (tipo === 'video') {
            const video = await db.collection('workspace_video_aulas').findOne({ id: alvo });
            if (!video) return res.status(404).json({ error: 'Vídeo-aula não encontrada.' });

            // Busca também toda a sequência do mesmo assunto para montar a fila lateral
            const sequencia = await db.collection('workspace_video_aulas')
                .find({ assuntoSlug: video.assuntoSlug })
                .sort({ ordem: 1, dataCriacao: 1 })
                .toArray();

            return res.status(200).json({ success: true, tipo: 'video', videoPrincipal: video, sequencia });
        }

        // Quando o link é de uma sequência completa de determinado assunto (Playlist)
        const slugBusca = gerarSlugAssunto(alvo);
        const sequencia = await db.collection('workspace_video_aulas')
            .find({ $or: [{ assuntoSlug: slugBusca }, { assunto: new RegExp(`^\\s*${alvo}\\s*$`, 'i') }] })
            .sort({ ordem: 1, dataCriacao: 1 })
            .toArray();

        if (!sequencia.length) {
            return res.status(404).json({ error: 'Sequência de aulas não encontrada.' });
        }

        res.status(200).json({
            success: true,
            tipo: 'sequencia',
            assunto: sequencia[0].assunto,
            assuntoSlug: sequencia[0].assuntoSlug,
            videoPrincipal: sequencia[0],
            sequencia: sequencia
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao abrir link de vídeo-aula.' });
    }
});

// ============================================================================
// 6. INTERATIVIDADE (COMENTÁRIOS / DÚVIDAS, LIKES E AULA CONCLUÍDA)
// ============================================================================
router.post('/videos/:id/interagir', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const videoId = req.params.id;
        const { acao, userId, autorNome, textoComentario } = req.body || {};

        const video = await db.collection('workspace_video_aulas').findOne({ id: videoId });
        if (!video) return res.status(404).json({ error: 'Vídeo não encontrado.' });

        if (acao === 'view') {
            await db.collection('workspace_video_aulas').updateOne({ id: videoId }, { $inc: { visualizacoes: 1 } });
            return res.status(200).json({ success: true });
        }

        if (acao === 'like' && userId) {
            let likes = Array.isArray(video.likes) ? [...video.likes] : [];
            if (likes.includes(userId)) likes = likes.filter(id => id !== userId);
            else likes.push(userId);
            await db.collection('workspace_video_aulas').updateOne({ id: videoId }, { $set: { likes } });
            return res.status(200).json({ success: true, likes });
        }

        if (acao === 'concluir' && userId) {
            let concluidos = Array.isArray(video.concluidosPor) ? [...video.concluidosPor] : [];
            if (concluidos.includes(userId)) concluidos = concluidos.filter(id => id !== userId);
            else concluidos.push(userId);
            await db.collection('workspace_video_aulas').updateOne({ id: videoId }, { $set: { concluidosPor: concluidos } });
            return res.status(200).json({ success: true, concluidosPor: concluidos });
        }

        if (acao === 'comentar' && textoComentario) {
            const novoCom = {
                id: 'com_' + crypto.randomUUID(),
                autorId: userId || '',
                autorNome: autorNome || 'Aluno',
                texto: String(textoComentario).trim(),
                data: new Date().toISOString()
            };
            await db.collection('workspace_video_aulas').updateOne(
                { id: videoId },
                { $push: { comentarios: novoCom } }
            );
            return res.status(201).json({ success: true, comentario: novoCom });
        }

        res.status(400).json({ error: 'Ação inválida.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registar interação.' });
    }
});

// ============================================================================
// 7. SALA AO VIVO (EXCLUSIVA PARA PROFESSOR/GESTOR CRIAR • ATÉ 4H SEGUIDAS)
// ============================================================================
router.post('/live/iniciar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeCriarLive = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeCriarLive) {
            return res.status(403).json({ error: 'Apenas Professores e Gestores podem iniciar uma transmissão ao vivo.' });
        }

        const b = req.body || {};
        const escolaId = b.escolaId || 'DEFAULT';

        // Encerra lives antigas que tenham ficado abertas
        await db.collection('workspace_video_lives').updateMany(
            { escolaId: escolaId, ativa: true },
            { $set: { ativa: false, encerradaEm: new Date().toISOString() } }
        );

        const codigoSalaMeet = `PlayClass_${escolaId}_${Date.now().toString(36)}`.replace(/[^a-zA-Z0-9_]/g, '');
        const expiraEm = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(); // Até 4 horas seguidas

        const novaLive = {
            id: 'live_' + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: String(b.titulo || 'Aula Ao Vivo').trim(),
            assunto: String(b.assunto || 'Aulas Ao Vivo Gravadas').trim(),
            destino: b.destino || 'global',
            destinoNome: b.destinoNome || 'Todas as Turmas',
            professorNome: b.professorNome || 'Professor',
            codigoSala: codigoSalaMeet,
            linkExternoOpcional: b.linkExterno ? String(b.linkExterno).trim() : null,
            ativa: true,
            duracaoMaximaHoras: 4,
            iniciadaEm: new Date().toISOString(),
            expiraEm: expiraEm
        };

        await db.collection('workspace_video_lives').insertOne(novaLive);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_STATUS',
                ativa: true,
                live: novaLive,
                escolaId: 'DEFAULT'
            });
        }

        res.status(201).json({ success: true, live: novaLive });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao iniciar sala ao vivo.' });
    }
});

router.post('/live/encerrar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeEncerrar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeEncerrar) {
            return res.status(403).json({ error: 'Apenas o Professor ou Gestor pode encerrar a transmissão.' });
        }

        const { liveId, escolaId } = req.body || {};

        if (liveId) {
            await db.collection('workspace_video_lives').updateOne(
                { id: liveId },
                { $set: { ativa: false, encerradaEm: new Date().toISOString() } }
            );
        } else {
            await db.collection('workspace_video_lives').updateMany(
                { ativa: true },
                { $set: { ativa: false, encerradaEm: new Date().toISOString() } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_STATUS',
                ativa: false,
                live: null,
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao encerrar transmissão.' });
    }
});

router.post('/live/encerrar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { liveId, escolaId } = req.body || {};

        if (liveId) {
            await db.collection('workspace_video_lives').updateOne(
                { id: liveId },
                { $set: { ativa: false, encerradaEm: new Date().toISOString() } }
            );
        } else {
            await db.collection('workspace_video_lives').updateMany(
                { ativa: true },
                { $set: { ativa: false, encerradaEm: new Date().toISOString() } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_STATUS',
                ativa: false,
                live: null,
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao encerrar transmissão.' });
    }
});

// ============================================================================
// 8. CANAL EM TEMPO REAL DO MINI CHAT E PROJEÇÃO DE LOUSA NA CHAMADA
// ============================================================================
router.post('/live/evento', verificarToken, async (req, res) => {
    try {
        const { salaCodigo, escolaId, subtipo, autorNome, autorRole, texto, lousaAtiva } = req.body || {};
        const db = await connectDB();

        // Se o professor ativou ou desativou a Projeção da Lousa, guarda no estado da live ativa
        if (subtipo === 'PROJETAR_LOUSA') {
            await db.collection('workspace_video_lives').updateMany(
                { ativa: true },
                { $set: { lousaProjetada: Boolean(lousaAtiva) } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_EVENTO',
                salaCodigo: salaCodigo || '',
                subtipo: subtipo || 'CHAT',
                autorNome: autorNome || 'Participante',
                autorRole: autorRole || 'aluno',
                texto: texto || '',
                lousaAtiva: Boolean(lousaAtiva),
                horario: new Date().toISOString(),
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao transmitir evento na live.' });
    }
});

module.exports = router;