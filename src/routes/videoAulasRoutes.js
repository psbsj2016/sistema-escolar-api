// src/routes/videoAulasRoutes.js - Motor Exclusivo de Vídeo-Aulas, Playlists, Links Criptografados e Histórico de Lives
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
const SEGREDO_LINK_LIVE = process.env.JWT_SECRET || 'playclass_meet_crypto_key_2026';

// 🛡️ Filtro de Alunos Ativos
const ehAlunoAtivo = (aluno) => {
    if (!aluno) return false;
    const st = String(aluno.status || 'Ativo').trim().toLowerCase();
    if (st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist')) {
        return false;
    }
    return st === 'ativo' || st === '';
};

const normalizarTexto = (str) => String(str || '').normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

// 🔐 Gerador de Token Único Criptografado para Links Diretos de Live
const gerarTokenLiveCriptografado = (escolaId, destino) => {
    const semente = `${escolaId}_${destino}_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const hash = crypto.createHmac('sha256', SEGREDO_LINK_LIVE).update(semente).digest('hex').slice(0, 22);
    return `lvk_${hash}`;
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

const gerarSlugAssunto = (texto) => {
    return String(texto || 'geral')
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'geral';
};

// 🛡️ Verifica no banco de dados se o utilizador logado é Professor, Gestor ou Secretaria
async function verificarSeEhProfessorOuGestor(db, req) {
    try {
        const idToken = req.userId || req.query.userId || req.body?.autorId || '';
        if (idToken) {
            const u = await db.collection('usuarios').findOne({ id: String(idToken) });
            if (u) {
                const tipoLimpo = String(u.tipo || 'Gestor').trim().toLowerCase();
                if (tipoLimpo === 'aluno' || u.alunoRefId) return false;
                return true;
            }
            const al = await db.collection('alunos').findOne({ id: String(idToken) });
            if (al) return false;
        }
        const roleParam = String(req.query.role || req.body?.role || '').trim().toLowerCase();
        return roleParam === 'professor' || roleParam === 'gestor' || roleParam === 'secretaria';
    } catch (e) {
        return false;
    }
}

// 🎯 Descobre com precisão todas as Turmas (IDs e Nomes) às quais o Aluno pertence
async function obterTurmasDoAluno(db, userId, alunoRefId) {
    const chavesTurma = new Set();
    try {
        const idsBusca = [userId, alunoRefId].filter(x => x && x !== 'undefined' && x !== 'null').map(String);
        if (idsBusca.length === 0) return [];

        const contaUser = await db.collection('usuarios').findOne({
            $or: [{ id: { $in: idsBusca } }, { alunoRefId: { $in: idsBusca } }]
        });

        const idsFicha = [...idsBusca];
        if (contaUser?.alunoRefId) idsFicha.push(String(contaUser.alunoRefId));
        if (contaUser?.id) idsFicha.push(String(contaUser.id));

        let fichaAluno = await db.collection('alunos').findOne({ id: { $in: idsFicha } });
        if (!fichaAluno && contaUser && (contaUser.nome || contaUser.login)) {
            const nomeAlvo = String(contaUser.nome || contaUser.login).trim();
            fichaAluno = await db.collection('alunos').findOne({
                nome: new RegExp(`^\\s*${nomeAlvo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'i')
            });
        }

        const extrairValor = (v) => {
            if (!v) return;
            if (Array.isArray(v)) v.forEach(extrairValor);
            else if (typeof v === 'object') {
                if (v.id) chavesTurma.add(normalizarTexto(v.id));
                if (v.nome) chavesTurma.add(normalizarTexto(v.nome));
            } else {
                chavesTurma.add(normalizarTexto(v));
            }
        };

        if (contaUser) {
            extrairValor(contaUser.turma);
            extrairValor(contaUser.turmaId);
            extrairValor(contaUser.turmas);
        }
        if (fichaAluno) {
            extrairValor(fichaAluno.turma);
            extrairValor(fichaAluno.turmaId);
            extrairValor(fichaAluno.turmas);
        }

        if (chavesTurma.size > 0) {
            const todasTurmas = await db.collection('turmas').find({}).project({ id: 1, nome: 1 }).toArray();
            todasTurmas.forEach(t => {
                const idNorm = normalizarTexto(t.id);
                const nomeNorm = normalizarTexto(t.nome);
                if (chavesTurma.has(idNorm) || chavesTurma.has(nomeNorm)) {
                    if (idNorm) chavesTurma.add(idNorm);
                    if (nomeNorm) chavesTurma.add(nomeNorm);
                }
            });
        }
    } catch (e) {}
    return Array.from(chavesTurma).filter(Boolean);
}

// 🔒 Verifica se um vídeo ou Live está liberado para o aluno com base na turma escolhida
function itemLiberadoParaTurmasDoAluno(item, turmasDoAlunoNorm) {
    if (!item) return false;
    const destNorm = normalizarTexto(item.destino || '');
    const destNomeNorm = normalizarTexto(item.destinoNome || '');

    if (destNorm === 'global' || destNorm === 'todas as turmas' || destNorm === 'publico geral') {
        return true;
    }
    if (!Array.isArray(turmasDoAlunoNorm) || turmasDoAlunoNorm.length === 0) {
        return false;
    }
    return (destNorm && turmasDoAlunoNorm.includes(destNorm)) || (destNomeNorm && turmasDoAlunoNorm.includes(destNomeNorm));
}

// ============================================================================
// 1. ASSINATURA DIRETA CLOUDINARY + UPLOAD DE VÍDEO-AULAS
// ============================================================================
router.get('/assinatura-upload', verificarToken, (req, res) => {
    try {
        const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
        const apiKey = process.env.CLOUDINARY_API_KEY;
        const apiSecret = process.env.CLOUDINARY_API_SECRET;

        if (!cloudName || !apiKey || !apiSecret) {
            return res.status(500).json({ success: false, error: 'Credenciais do Cloudinary não configuradas no servidor.' });
        }

        const timestamp = Math.round(new Date().getTime() / 1000);
        const paramsToSign = { timestamp, folder: PASTA_NUVEM_VIDEOS };
        const signature = cloudinary.utils.api_sign_request(paramsToSign, apiSecret);

        res.status(200).json({ success: true, cloudName, apiKey, timestamp, signature, folder: PASTA_NUVEM_VIDEOS });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Falha ao autorizar upload na nuvem.' });
    }
});

router.post('/upload-video', verificarToken, (req, res) => {
    const processador = uploadVideo.single('video');
    processador(req, res, async (err) => {
        if (res.headersSent) return;
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: `O vídeo excede o limite de ${LIMITE_MB_VIDEO}MB.` });
            return res.status(500).json({ error: 'Falha ao receber o ficheiro de vídeo no servidor.' });
        }
        if (!req.file) return res.status(400).json({ error: 'Nenhum ficheiro de vídeo recebido.' });

        const caminhoTemp = req.file.path;
        try {
            const nomeOriginal = req.file.originalname || `aula_${Date.now()}.mp4`;
            const nomeSeguro = String(nomeOriginal).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, '_');
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
            res.status(500).json({ error: 'Erro ao guardar o vídeo na nuvem: ' + (erroUpload.message || 'Falha desconhecida') });
        } finally {
            if (caminhoTemp && fs.existsSync(caminhoTemp)) {
                try { fs.unlinkSync(caminhoTemp); } catch (e) {}
            }
        }
    });
});

// ============================================================================
// 2. LISTAR CATÁLOGO COMPLETO (COM FILTRO ESTRITO DE TURMA + HISTÓRICO)
// ============================================================================
router.get('/catalogo', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = req.query.escolaId || 'DEFAULT';
        const userId = req.query.userId || req.userId || '';
        const alunoRefId = req.query.alunoRefId || '';

        const isGestorOuProf = await verificarSeEhProfessorOuGestor(db, req);

        // Encerra automaticamente lives que já ultrapassaram 4 horas (240 min)
        const limiteQuatroHorasAtras = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
        await db.collection('workspace_video_lives').updateMany(
            { ativa: true, inicioUsoEm: { $lt: limiteQuatroHorasAtras } },
            { $set: { ativa: false, encerradaEm: new Date().toISOString(), motivoEncerramento: 'Limite de 4h atingido' } }
        );

        const filtroEscola = (escolaId && escolaId !== 'DEFAULT')
            ? { $in: [escolaId, 'DEFAULT', null] }
            : { $exists: true };

        const todosVideosEscola = await db.collection('workspace_video_aulas')
            .find({ escolaId: filtroEscola })
            .sort({ assuntoSlug: 1, ordem: 1, dataCriacao: -1 })
            .toArray();

        let minhasTurmasNorm = [];
        let videos = todosVideosEscola;

        if (!isGestorOuProf) {
            minhasTurmasNorm = await obterTurmasDoAluno(db, userId, alunoRefId);
            videos = todosVideosEscola.filter(v => itemLiberadoParaTurmasDoAluno(v, minhasTurmasNorm));
        }

        const mapaAssuntos = {};
        videos.forEach(v => {
            const nomeAssunto = String(v.assunto || 'Aulas Gerais').trim();
            const slug = v.assuntoSlug || gerarSlugAssunto(nomeAssunto);
            if (!mapaAssuntos[slug]) {
                mapaAssuntos[slug] = { slug, assunto: nomeAssunto, capa: v.miniatura || null, totalVideos: 0, videos: [] };
            }
            if (!mapaAssuntos[slug].capa && v.miniatura) mapaAssuntos[slug].capa = v.miniatura;
            mapaAssuntos[slug].videos.push(v);
            mapaAssuntos[slug].totalVideos = mapaAssuntos[slug].videos.length;
        });

        Object.values(mapaAssuntos).forEach(pl => {
            pl.videos.sort((a, b) => (Number(a.ordem) || 999) - (Number(b.ordem) || 999));
        });

        const livesAtivas = await db.collection('workspace_video_lives')
            .find({ ativa: true, escolaId: filtroEscola })
            .sort({ inicioUsoEm: -1, criadaEm: -1 })
            .toArray();

        const liveAtivaParaUsuario = livesAtivas.find(lv => {
            if (isGestorOuProf) return true;
            return itemLiberadoParaTurmasDoAluno(lv, minhasTurmasNorm);
        }) || null;

        const turmasEscola = isGestorOuProf
            ? await db.collection('turmas').find({}).project({ id: 1, nome: 1 }).toArray()
            : [];

        const historicoLives = isGestorOuProf
            ? await db.collection('workspace_video_lives').find({ escolaId: filtroEscola }).sort({ criadaEm: -1 }).limit(60).toArray()
            : [];

        res.status(200).json({
            success: true,
            permissaoGestao: isGestorOuProf,
            minhasTurmas: minhasTurmasNorm,
            videos: videos,
            sequencias: Object.values(mapaAssuntos),
            liveAtiva: liveAtivaParaUsuario,
            turmas: turmasEscola,
            historicoLives: historicoLives
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao carregar catálogo de vídeo-aulas.' });
    }
});

// ============================================================================
// 3. PUBLICAR, EDITAR E APAGAR VÍDEO-AULAS
// ============================================================================
router.post('/videos', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podePublicar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podePublicar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem publicar vídeo-aulas.' });

        const b = req.body || {};
        if (!b.titulo || !b.urlVideo) return res.status(400).json({ error: 'O título e o vídeo são obrigatórios.' });

        const assuntoLimpo = String(b.assunto || 'Aulas Gerais').trim();
        const assuntoSlug = gerarSlugAssunto(assuntoLimpo);
        const escolaId = b.escolaId || 'DEFAULT';

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

      if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_AULA_NOVA',
                video: {
                    id: novoVideo.id,
                    titulo: novoVideo.titulo,
                    assunto: novoVideo.assunto,
                    destino: novoVideo.destino,
                    destinoNome: novoVideo.destinoNome,
                    autorId: novoVideo.autorId,
                    autorNome: novoVideo.autorNome
                },
                escolaId: 'DEFAULT'
            });
        }

        res.status(201).json({ success: true, video: novoVideo });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao guardar a vídeo-aula.' });
    }
});

router.delete('/videos/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeApagar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeApagar) return res.status(403).json({ error: 'Sem permissão.' });

        await db.collection('workspace_video_aulas').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao remover vídeo-aula.' });
    }
});

// ============================================================================
// 4. INTERATIVIDADE (COMENTÁRIOS, LIKES E CONCLUSÃO)
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
            await db.collection('workspace_video_aulas').updateOne({ id: videoId }, { $push: { comentarios: novoCom } });
            return res.status(201).json({ success: true, comentario: novoCom });
        }
        res.status(400).json({ error: 'Ação inválida.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registar interação.' });
    }
});

// ============================================================================
// 5. GERAR LINK CRIPTOGRAFADO, INICIAR LIVE, ENCERRAR E HISTÓRICO COMPLETO
// ============================================================================

// 🔐 Gera e guarda a Live + Link Criptografado ANTES de iniciar (Regista Horário de Criação)
router.post('/live/gerar-link', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeCriar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeCriar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem gerar links de live.' });

        const b = req.body || {};
        const escolaId = b.escolaId || 'DEFAULT';
        const destino = b.destino || 'global';
        const destinoNome = b.destinoNome || 'Todas as Turmas';
        const tokenCriptografado = gerarTokenLiveCriptografado(escolaId, destino);
        const codigoSalaMeet = `PlayClass_${escolaId}_${tokenCriptografado}`.replace(/[^a-zA-Z0-9_]/g, '');
        const agoraIso = new Date().toISOString();

        const registoLive = {
            id: 'live_' + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: String(b.titulo || 'Aula Ao Vivo').trim(),
            assunto: String(b.assunto || 'Aulas Ao Vivo Gravadas').trim(),
            destino: destino,
            destinoNome: destinoNome,
            professorNome: b.professorNome || 'Professor',
            codigoSala: codigoSalaMeet,
            tokenCriptografado: tokenCriptografado,
            ativa: false,
            duracaoMaximaHoras: 4,
            criadaEm: agoraIso,
            inicioUsoEm: null,
            encerradaEm: null
        };

        await db.collection('workspace_video_lives').insertOne(registoLive);
        res.status(201).json({ success: true, live: registoLive });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao gerar link criptografado da live.' });
    }
});

// 🔴 Inicia efetivamente a Sala Ao Vivo (Regista Horário de Início de Uso)
router.post('/live/iniciar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeCriarLive = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeCriarLive) return res.status(403).json({ error: 'Apenas Professores e Gestores podem iniciar uma transmissão.' });

        const b = req.body || {};
        const escolaId = b.escolaId || 'DEFAULT';
        const agoraIso = new Date().toISOString();
        const expiraEm = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();

        // Fecha outras lives que estivessem ativas anteriormente
        await db.collection('workspace_video_lives').updateMany(
            { escolaId: escolaId, ativa: true },
            { $set: { ativa: false, encerradaEm: agoraIso } }
        );

        let liveAtivada = null;

        // Se o professor já tinha gerado o link criptografado antes, ativa esse mesmo registo e grava o inicioUsoEm!
        if (b.liveId || b.tokenCriptografado) {
            const filtroPrevia = b.liveId ? { id: b.liveId } : { tokenCriptografado: b.tokenCriptografado };
            const previa = await db.collection('workspace_video_lives').findOne(filtroPrevia);
            if (previa) {
                const camposUpdate = {
                    titulo: String(b.titulo || previa.titulo || 'Aula Ao Vivo').trim(),
                    assunto: String(b.assunto || previa.assunto || 'Aulas Ao Vivo Gravadas').trim(),
                    destino: b.destino || previa.destino || 'global',
                    destinoNome: b.destinoNome || previa.destinoNome || 'Todas as Turmas',
                    ativa: true,
                    inicioUsoEm: previa.inicioUsoEm || agoraIso,
                    iniciadaEm: agoraIso,
                    encerradaEm: null,
                    expiraEm: expiraEm
                };
                await db.collection('workspace_video_lives').updateOne({ id: previa.id }, { $set: camposUpdate });
                liveAtivada = { ...previa, ...camposUpdate };
            }
        }

        // Caso tenha clicado diretamente em Iniciar Transmissão sem gerar link antes, cria tudo na hora
        if (!liveAtivada) {
            const destino = b.destino || 'global';
            const tokenCriptografado = gerarTokenLiveCriptografado(escolaId, destino);
            const codigoSalaMeet = `PlayClass_${escolaId}_${tokenCriptografado}`.replace(/[^a-zA-Z0-9_]/g, '');

            liveAtivada = {
                id: 'live_' + crypto.randomUUID(),
                escolaId: escolaId,
                titulo: String(b.titulo || 'Aula Ao Vivo').trim(),
                assunto: String(b.assunto || 'Aulas Ao Vivo Gravadas').trim(),
                destino: destino,
                destinoNome: b.destinoNome || 'Todas as Turmas',
                professorNome: b.professorNome || 'Professor',
                codigoSala: codigoSalaMeet,
                tokenCriptografado: tokenCriptografado,
                ativa: true,
                duracaoMaximaHoras: 4,
                criadaEm: agoraIso,
                inicioUsoEm: agoraIso,
                iniciadaEm: agoraIso,
                encerradaEm: null,
                expiraEm: expiraEm
            };
            await db.collection('workspace_video_lives').insertOne(liveAtivada);
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_STATUS',
                ativa: true,
                live: liveAtivada,
                escolaId: 'DEFAULT'
            });
        }

        res.status(201).json({ success: true, live: liveAtivada });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao iniciar sala ao vivo.' });
    }
});

// ⏹️ Encerra a Sala Ao Vivo (Regista Horário de Término)
router.post('/live/encerrar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeEncerrar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeEncerrar) return res.status(403).json({ error: 'Apenas o Professor ou Gestor pode encerrar a transmissão.' });

        const { liveId, escolaId } = req.body || {};
        const agoraIso = new Date().toISOString();

        if (liveId) {
            await db.collection('workspace_video_lives').updateOne(
                { id: liveId },
                { $set: { ativa: false, encerradaEm: agoraIso } }
            );
        } else {
            await db.collection('workspace_video_lives').updateMany(
                { ativa: true },
                { $set: { ativa: false, encerradaEm: agoraIso } }
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

        res.status(200).json({ success: true, encerradaEm: agoraIso });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao encerrar transmissão.' });
    }
});

// 📜 Consultar Histórico de Lives e Links Gerados (Criação, Início de Uso e Término)
router.get('/live/historico', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeVer = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeVer) return res.status(403).json({ error: 'Acesso restrito.' });

        const historico = await db.collection('workspace_video_lives')
            .find({})
            .sort({ criadaEm: -1, iniciadaEm: -1 })
            .limit(80)
            .toArray();

        res.status(200).json({ success: true, historico });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar histórico de lives.' });
    }
});

// 🗑️ Excluir registo do Histórico de Lives
router.delete('/live/historico/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeApagar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeApagar) return res.status(403).json({ error: 'Sem permissão.' });

        await db.collection('workspace_video_lives').deleteOne({ id: req.params.id });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao apagar item do histórico.' });
    }
});

// 🔐 Validar Acesso via Link Criptografado (#live-lvk_...) com Bloqueio Estrito de Turma
router.get('/live/acesso/:token', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const tokenLimpo = String(req.params.token || '').trim();
        const userId = req.query.userId || req.userId || '';
        const alunoRefId = req.query.alunoRefId || '';

        const live = await db.collection('workspace_video_lives').findOne({
            $or: [{ tokenCriptografado: tokenLimpo }, { id: tokenLimpo }, { codigoSala: tokenLimpo }]
        });

        if (!live) {
            return res.status(404).json({ success: false, error: 'Link de transmissão inválido ou não encontrado.' });
        }

        const isGestorOuProf = await verificarSeEhProfessorOuGestor(db, req);
        if (!isGestorOuProf) {
            const minhasTurmasNorm = await obterTurmasDoAluno(db, userId, alunoRefId);
            if (!itemLiberadoParaTurmasDoAluno(live, minhasTurmasNorm)) {
                return res.status(403).json({
                    success: false,
                    bloqueadoPorTurma: true,
                    error: `Acesso restrito: Esta transmissão é exclusiva para a turma "${live.destinoNome || 'selecionada'}".`
                });
            }
        }

        res.status(200).json({ success: true, live });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao validar link da live.' });
    }
});

// ============================================================================
// 6. CANAL EM TEMPO REAL (MINI CHAT, REAÇÕES, MICROFONE E PROJEÇÃO DE LOUSA)
// ============================================================================
router.post('/live/evento', verificarToken, async (req, res) => {
    try {
        const b = req.body || {};
        const db = await connectDB();

        if (b.subtipo === 'PROJETAR_LOUSA') {
            await db.collection('workspace_video_lives').updateMany(
                { ativa: true },
                { $set: { lousaProjetada: Boolean(b.lousaAtiva) } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_EVENTO',
                id: b.id || ('ev_' + crypto.randomUUID()),
                salaCodigo: b.salaCodigo || '',
                subtipo: b.subtipo || 'CHAT',
                autorId: b.autorId || '',
                autorNome: b.autorNome || 'Participante',
                autorRole: b.autorRole || 'aluno',
                peerId: b.peerId || '',
                texto: b.texto || '',
                emoji: b.emoji || '',
                lousaAtiva: Boolean(b.lousaAtiva),
                micAtivo: Boolean(b.micAtivo),
                horario: new Date().toISOString(),
                escolaId: b.escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao transmitir evento na live.' });
    }
});

module.exports = router;