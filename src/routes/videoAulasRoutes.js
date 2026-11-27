// src/routes/videoAulasRoutes.js - Motor Multi-Tenant Blindado de Vídeo-Aulas, Playlists, Lives, Portaria e ICE/TURN
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const { filtroTenant } = require('../middlewares/auth');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const fs = require('fs');
const os = require('os');

// ⚙️ PARÂMETROS AJUSTÁVEIS
const LIMITE_MB_VIDEO = 800;
const PASTA_NUVEM_VIDEOS = 'workspace_video_aulas';
const SEGREDO_LINK_LIVE = process.env.JWT_SECRET || 'playclass_meet_crypto_key_2026';
const JANELA_PRESENCA_LIVE_MS = 65 * 1000;

// 🧹 Remove participantes cujo último sinal de vida (heartbeat) já expirou
function limparParticipantesExpirados(lista, agoraMs = Date.now()) {
    if (!Array.isArray(lista)) return [];
    return lista.filter(p => {
        if (!p || !p.peerId) return false;
        const ultimo = Number(p.ultimoSinalMs || 0);
        return ultimo > 0 && (agoraMs - ultimo) <= JANELA_PRESENCA_LIVE_MS;
    });
}

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

// 🔒 Sempre lê o escolaId real do token JWT autenticado (nunca confia em query/body!)
function obterEscolaIdSeguro(req) {
    return String(req.escolaId || '').trim();
}

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

// 🔒 Middleware de Autenticação + Garantia de Escola no JWT
const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token || !req.escolaId) {
        return res.status(401).json({ error: 'Acesso negado. Faça login novamente.' });
    }
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

// 🛡️ Verifica estritamente pelo JWT + Banco de Dados se o utilizador é Professor, Gestor ou Secretaria
async function verificarSeEhProfessorOuGestor(db, req) {
    try {
        const tipoJwt = String(req.userTipo || '').trim().toLowerCase();
        if (tipoJwt === 'aluno') return false;

        const idToken = String(req.userId || '').trim();
        if (!idToken) return false;

        const u = await db.collection('usuarios').findOne({ id: idToken, ...filtroTenant(req) });
        if (u) {
            const tipoLimpo = String(u.tipo || 'Gestor').trim().toLowerCase();
            if (tipoLimpo === 'aluno' || u.alunoRefId) return false;
            return true;
        }
        return ['professor', 'gestor', 'secretaria'].includes(tipoJwt);
    } catch (e) {
        return false;
    }
}

// 🎯 Descobre com precisão todas as Turmas (IDs e Nomes) às quais o Aluno pertence DENTRO DA SUA ESCOLA
async function obterTurmasDoAluno(db, userId, alunoRefId, escolaId) {
    const chavesTurma = new Set();
    try {
        const idsBusca = [userId, alunoRefId].filter(x => x && x !== 'undefined' && x !== 'null').map(String);
        if (idsBusca.length === 0 || !escolaId) return [];

        const contaUser = await db.collection('usuarios').findOne({
            escolaId,
            $or: [{ id: { $in: idsBusca } }, { alunoRefId: { $in: idsBusca } }]
        });

        const idsFicha = [...idsBusca];
        if (contaUser?.alunoRefId) idsFicha.push(String(contaUser.alunoRefId));
        if (contaUser?.id) idsFicha.push(String(contaUser.id));

        let fichaAluno = await db.collection('alunos').findOne({ escolaId, id: { $in: idsFicha } });
        if (!fichaAluno && contaUser && (contaUser.nome || contaUser.login)) {
            const nomeAlvo = String(contaUser.nome || contaUser.login).trim();
            fichaAluno = await db.collection('alunos').findOne({
                escolaId,
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
            const todasTurmas = await db.collection('turmas').find({ escolaId }).project({ id: 1, nome: 1 }).toArray();
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

// 🔒 Verifica se um vídeo ou Live está liberado para o aluno (por Turma OU por Convite Direto do Professor!)
function itemLiberadoParaTurmasDoAluno(item, turmasDoAlunoNorm, userIdsAluno = []) {
    if (!item) return false;

    const convidados = Array.isArray(item.alunosConvidados) ? item.alunosConvidados.map(String) : [];
    const idsLimpos = (Array.isArray(userIdsAluno) ? userIdsAluno : []).filter(Boolean).map(String);
    if (convidados.length > 0 && idsLimpos.some(id => convidados.includes(id))) {
        return true;
    }

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
// 2. LISTAR CATÁLOGO COMPLETO (ISOLAMENTO ESTRITO POR ESCOLA + TURMA)
// ============================================================================
router.get('/catalogo', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = obterEscolaIdSeguro(req);
        const userId = String(req.userId || '').trim();
        const alunoRefId = String(req.query.alunoRefId || '').trim();

        const isGestorOuProf = await verificarSeEhProfessorOuGestor(db, req);

        // Encerra automaticamente lives desta escola que ultrapassaram 4 horas
        const limiteQuatroHorasAtras = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
        await db.collection('workspace_video_lives').updateMany(
            { escolaId, ativa: true, inicioUsoEm: { $lt: limiteQuatroHorasAtras } },
            { $set: { ativa: false, encerradaEm: new Date().toISOString(), motivoEncerramento: 'Limite de 4h atingido' } }
        );

        const todosVideosEscola = await db.collection('workspace_video_aulas')
            .find({ escolaId })
            .sort({ assuntoSlug: 1, ordem: 1, dataCriacao: -1 })
            .toArray();

        let minhasTurmasNorm = [];
        let videos = todosVideosEscola;

        if (!isGestorOuProf) {
            minhasTurmasNorm = await obterTurmasDoAluno(db, userId, alunoRefId, escolaId);
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
            .find({ ativa: true, escolaId })
            .sort({ inicioUsoEm: -1, criadaEm: -1 })
            .toArray();

        const liveAtivaParaUsuario = livesAtivas.find(lv => {
            if (isGestorOuProf) return true;
            return itemLiberadoParaTurmasDoAluno(lv, minhasTurmasNorm, [userId, alunoRefId]);
        }) || null;

        // 🔒 BLINDADO: Apenas turmas da própria escola do gestor/professor!
        const turmasEscola = isGestorOuProf
            ? await db.collection('turmas').find(filtroTenant(req)).project({ id: 1, nome: 1 }).toArray()
            : [];

        const historicoLives = isGestorOuProf
            ? await db.collection('workspace_video_lives').find({ escolaId }).sort({ criadaEm: -1 }).limit(60).toArray()
            : [];

        const livesAgendadas = isGestorOuProf
            ? historicoLives.filter(lv => !lv.ativa && !lv.encerradaEm)
            : [];

        res.status(200).json({
            success: true,
            permissaoGestao: isGestorOuProf,
            minhasTurmas: minhasTurmasNorm,
            videos: videos,
            sequencias: Object.values(mapaAssuntos),
            liveAtiva: liveAtivaParaUsuario,
            livesAgendadas: livesAgendadas,
            turmas: turmasEscola,
            historicoLives: historicoLives
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao carregar catálogo de vídeo-aulas.' });
    }
});

// ============================================================================
// 3. PUBLICAR E APAGAR VÍDEO-AULAS (ISOLADAS POR ESCOLA)
// ============================================================================
router.post('/videos', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podePublicar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podePublicar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem publicar vídeo-aulas.' });

        const b = req.body || {};
        if (!b.titulo || !b.urlVideo) return res.status(400).json({ error: 'O título e o vídeo são obrigatórios.' });

        const escolaId = obterEscolaIdSeguro(req);
        const assuntoLimpo = String(b.assunto || 'Aulas Gerais').trim();
        const assuntoSlug = gerarSlugAssunto(assuntoLimpo);

        let ordemSequencia = parseInt(b.ordem, 10);
        if (!ordemSequencia || isNaN(ordemSequencia)) {
            const qtdNoAssunto = await db.collection('workspace_video_aulas').countDocuments({ escolaId, assuntoSlug });
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
            autorId: String(req.userId || b.autorId || ''),
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
                escolaId: escolaId
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

        const escolaId = obterEscolaIdSeguro(req);
        await db.collection('workspace_video_aulas').deleteOne({ id: req.params.id, escolaId });
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
        const escolaId = obterEscolaIdSeguro(req);
        const videoId = req.params.id;
        const { acao, autorNome, textoComentario } = req.body || {};
        const userId = String(req.userId || req.body?.userId || '').trim();

        const video = await db.collection('workspace_video_aulas').findOne({ id: videoId, escolaId });
        if (!video) return res.status(404).json({ error: 'Vídeo não encontrado.' });

        if (acao === 'view') {
            await db.collection('workspace_video_aulas').updateOne({ id: videoId, escolaId }, { $inc: { visualizacoes: 1 } });
            return res.status(200).json({ success: true });
        }
        if (acao === 'like' && userId) {
            let likes = Array.isArray(video.likes) ? [...video.likes] : [];
            if (likes.includes(userId)) likes = likes.filter(id => id !== userId);
            else likes.push(userId);
            await db.collection('workspace_video_aulas').updateOne({ id: videoId, escolaId }, { $set: { likes } });
            return res.status(200).json({ success: true, likes });
        }
        if (acao === 'concluir' && userId) {
            let concluidos = Array.isArray(video.concluidosPor) ? [...video.concluidosPor] : [];
            if (concluidos.includes(userId)) concluidos = concluidos.filter(id => id !== userId);
            else concluidos.push(userId);
            await db.collection('workspace_video_aulas').updateOne({ id: videoId, escolaId }, { $set: { concluidosPor: concluidos } });
            return res.status(200).json({ success: true, concluidosPor: concluidos });
        }
        if (acao === 'comentar' && textoComentario) {
            const novoCom = {
                id: 'com_' + crypto.randomUUID(),
                autorId: userId,
                autorNome: autorNome || 'Aluno',
                texto: String(textoComentario).trim(),
                data: new Date().toISOString()
            };
            await db.collection('workspace_video_aulas').updateOne({ id: videoId, escolaId }, { $push: { comentarios: novoCom } });
            return res.status(201).json({ success: true, comentario: novoCom });
        }
        res.status(400).json({ error: 'Ação inválida.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registar interação.' });
    }
});

// ============================================================================
// 5. AGENDAMENTO DE LINK CRIPTOGRAFADO, PORTARIA COM ACEITE E HISTÓRICO DE LIVES
// ============================================================================
router.post('/live/gerar-link', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeCriar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeCriar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem gerar links de live.' });

        const b = req.body || {};
        const escolaId = obterEscolaIdSeguro(req);
        const destino = b.destino || 'global';
        const destinoNome = b.destinoNome || 'Todas as Turmas';
        const tituloLimpo = String(b.titulo || 'Aula Ao Vivo').trim();
        const dataAgendada = b.dataAgendada ? String(b.dataAgendada).trim() : null;
        const tokenCriptografado = gerarTokenLiveCriptografado(escolaId, destino);
        const codigoSalaMeet = `PlayClass_${escolaId}_${tokenCriptografado}`.replace(/[^a-zA-Z0-9_]/g, '');
        const agoraIso = new Date().toISOString();

        const registoLive = {
            id: 'live_' + crypto.randomUUID(),
            escolaId: escolaId,
            titulo: tituloLimpo,
            assunto: String(b.assunto || 'Aulas Ao Vivo Gravadas').trim(),
            destino: destino,
            destinoNome: destinoNome,
            professorNome: b.professorNome || 'Professor',
            autorId: String(req.userId || b.autorId || ''),
            codigoSala: codigoSalaMeet,
            tokenCriptografado: tokenCriptografado,
            dataAgendada: dataAgendada,
            ativa: false,
            alunosAutorizados: [],
            pedidosEntrada: [],
            duracaoMaximaHoras: 4,
            criadaEm: agoraIso,
            inicioUsoEm: null,
            encerradaEm: null
        };

        await db.collection('workspace_video_lives').insertOne(registoLive);

        let sessaoSalaAcessos = null;
        if (b.criarNaSalaAcessos && b.linkCompleto) {
            const dataParaSalaAcessos = dataAgendada || new Date(Date.now() + 3600000).toISOString().slice(0, 16);
            sessaoSalaAcessos = {
                id: 'av_' + crypto.randomUUID(),
                titulo: tituloLimpo,
                tipo: 'online',
                tempo: null,
                dataAgendada: dataParaSalaAcessos,
                linkSala: String(b.linkCompleto).trim(),
                questoes: [],
                instrucoes: '',
                escolaId: escolaId,
                autorNome: b.professorNome || 'Professor',
                destino: destino,
                destinoNome: destinoNome,
                tentativas: 1,
                liveTokenRef: tokenCriptografado,
                dataCriacao: agoraIso,
                ultimaAtualizacao: agoraIso,
                status: 'ativa'
            };
            await db.collection('workspace_avaliacoes').insertOne(sessaoSalaAcessos);

            try {
                const alunosBrutos = await db.collection('alunos').find({ escolaId }).toArray();
                const alunos = alunosBrutos.filter(ehAlunoAtivo);
                const alunosAlvo = destino === 'global'
                    ? alunos
                    : alunos.filter(a => {
                        const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turma, a.turmaId];
                        return minhasTurmas.some(t => normalizarTexto(t) === normalizarTexto(destino) || normalizarTexto(t) === normalizarTexto(destinoNome));
                    });

                if (alunosAlvo.length > 0) {
                    const nomesDestinatarios = [];
                    const notificacoesArray = alunosAlvo.map(aluno => {
                        const nomeAluno = aluno.nome || aluno.login;
                        if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                        return {
                            id: 'notif_' + crypto.randomUUID(),
                            escolaId: escolaId,
                            destinatarioNome: nomeAluno,
                            remetenteNome: b.professorNome || 'Professor',
                            mensagem: `agendou o link da aula online: "${tituloLimpo}"`,
                            origem: 'online',
                            origemId: sessaoSalaAcessos.id,
                            destinoNome: destinoNome,
                            dataEvento: dataParaSalaAcessos,
                            lida: false,
                            data: agoraIso
                        };
                    }).filter(n => n.destinatarioNome);

                    if (notificacoesArray.length > 0) {
                        await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                        if (global.workspaceStream) {
                            global.workspaceStream.emit('evento_realtime', {
                                type: 'NOVA_NOTIFICACAO',
                                destinatarios: nomesDestinatarios,
                                escolaId: escolaId
                            });
                            global.workspaceStream.emit('evento_realtime', {
                                type: 'SALA_UPDATE',
                                turmaId: sessaoSalaAcessos.id,
                                escolaId: escolaId
                            });
                        }
                    }
                }
            } catch (errNoti) {}
        }

        res.status(201).json({ success: true, live: registoLive, sessaoSalaAcessos });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao gerar link criptografado da live.' });
    }
});

// 🔴 Inicia efetivamente a Sala Ao Vivo (estritamente na escola do professor!)
router.post('/live/iniciar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeCriarLive = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeCriarLive) return res.status(403).json({ error: 'Apenas Professores e Gestores podem iniciar uma transmissão.' });

        const b = req.body || {};
        const escolaId = obterEscolaIdSeguro(req);
        const agoraIso = new Date().toISOString();
        const expiraEm = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();

        await db.collection('workspace_video_lives').updateMany(
            { escolaId, ativa: true },
            { $set: { ativa: false, encerradaEm: agoraIso } }
        );

        let liveAtivada = null;

        if (b.liveId || b.tokenCriptografado) {
            const filtroPrevia = b.liveId
                ? { id: b.liveId, escolaId }
                : { tokenCriptografado: b.tokenCriptografado, escolaId };
            const previa = await db.collection('workspace_video_lives').findOne(filtroPrevia);
            if (previa) {
                const camposUpdate = {
                    titulo: String(b.titulo || previa.titulo || 'Aula Ao Vivo').trim(),
                    assunto: String(b.assunto || previa.assunto || 'Aulas Ao Vivo Gravadas').trim(),
                    destino: b.destino || previa.destino || 'global',
                    destinoNome: b.destinoNome || previa.destinoNome || 'Todas as Turmas',
                    ativa: true,
                    alunosAutorizados: Array.isArray(previa.alunosAutorizados) ? previa.alunosAutorizados : [],
                    pedidosEntrada: Array.isArray(previa.pedidosEntrada) ? previa.pedidosEntrada : [],
                    participantesAtivos: [],
                    inicioUsoEm: previa.inicioUsoEm || agoraIso,
                    iniciadaEm: agoraIso,
                    encerradaEm: null,
                    expiraEm: expiraEm
                };
                await db.collection('workspace_video_lives').updateOne({ id: previa.id, escolaId }, { $set: camposUpdate });
                liveAtivada = { ...previa, ...camposUpdate };
            }
        }

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
                autorId: String(req.userId || b.autorId || ''),
                codigoSala: codigoSalaMeet,
                tokenCriptografado: tokenCriptografado,
                dataAgendada: b.dataAgendada || null,
                ativa: true,
                alunosAutorizados: [],
                pedidosEntrada: [],
                participantesAtivos: [],
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
                escolaId: escolaId
            });
        }

        res.status(201).json({ success: true, live: liveAtivada });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao iniciar sala ao vivo.' });
    }
});

// 🙋‍♂️ PORTARIA DA LIVE (PARTE A): Aluno pede permissão para entrar na chamada ao vivo da sua escola
router.post('/live/pedir-entrada', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = obterEscolaIdSeguro(req);
        const b = req.body || {};
        const userId = String(req.userId || b.userId || '').trim();
        const alunoRefId = String(b.alunoRefId || '').trim();
        const userName = String(b.userName || 'Aluno').trim();
        const liveId = b.liveId || '';
        const codigoSala = b.codigoSala || '';

        if (!userId) return res.status(400).json({ error: 'Utilizador não identificado.' });

        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [
                ...(liveId ? [{ id: liveId }] : []),
                ...(codigoSala ? [{ codigoSala: codigoSala }] : []),
                { ativa: true }
            ]
        });

        if (!live || !live.ativa) {
            return res.status(404).json({ success: false, error: 'Nenhuma transmissão ativa encontrada neste momento.' });
        }

        const minhasTurmasNorm = await obterTurmasDoAluno(db, userId, alunoRefId, escolaId);
        if (!itemLiberadoParaTurmasDoAluno(live, minhasTurmasNorm, [userId, alunoRefId])) {
            return res.status(403).json({
                success: false,
                error: `Esta transmissão pertence exclusivamente à turma "${live.destinoNome || 'selecionada'}".`
            });
        }

        const autorizados = Array.isArray(live.alunosAutorizados) ? live.alunosAutorizados.map(String) : [];

        if (autorizados.includes(userId) || (alunoRefId && autorizados.includes(alunoRefId))) {
            return res.status(200).json({ success: true, status: 'autorizado', live });
        }

        let avatarAluno = null;
        const contaUser = await db.collection('usuarios').findOne({
            escolaId,
            $or: [{ id: userId }, ...(alunoRefId ? [{ alunoRefId: alunoRefId }] : [])]
        });
        if (contaUser && contaUser.avatar) avatarAluno = contaUser.avatar;

        const pedidosAtuais = Array.isArray(live.pedidosEntrada) ? [...live.pedidosEntrada] : [];
        const jaPediu = pedidosAtuais.some(p => String(p.userId) === userId);

        const novoPedido = {
            userId: userId,
            alunoRefId: alunoRefId,
            userName: (contaUser && contaUser.nome) ? contaUser.nome : userName,
            avatar: avatarAluno,
            horario: new Date().toISOString()
        };

        if (!jaPediu) {
            pedidosAtuais.push(novoPedido);
            await db.collection('workspace_video_lives').updateOne(
                { id: live.id, escolaId },
                { $set: { pedidosEntrada: pedidosAtuais } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_EVENTO',
                subtipo: 'PEDIDO_ENTRADA',
                salaCodigo: live.codigoSala,
                liveId: live.id,
                pedido: novoPedido,
                pedidosEntrada: pedidosAtuais,
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, status: 'aguardando', pedido: novoPedido });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao solicitar entrada na aula.' });
    }
});

// 👨‍🏫 PORTARIA DA LIVE (PARTE B): Professor Aceita, Recusa ou Aceita Todos os alunos
router.post('/live/responder-entrada', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeGerir = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeGerir) return res.status(403).json({ error: 'Apenas o Professor pode autorizar a entrada.' });

        const escolaId = obterEscolaIdSeguro(req);
        const { liveId, codigoSala, alunoId, acao } = req.body || {};
        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [
                ...(liveId ? [{ id: liveId }] : []),
                ...(codigoSala ? [{ codigoSala: codigoSala }] : []),
                { ativa: true }
            ]
        });

        if (!live) return res.status(404).json({ error: 'Sala ao vivo não encontrada.' });

        let autorizados = Array.isArray(live.alunosAutorizados) ? [...live.alunosAutorizados.map(String)] : [];
        let pedidos = Array.isArray(live.pedidosEntrada) ? [...live.pedidosEntrada] : [];
        let alunosLiberadosAgora = [];

        if (acao === 'aceitar_todos') {
            pedidos.forEach(p => {
                if (p.userId && !autorizados.includes(String(p.userId))) autorizados.push(String(p.userId));
                if (p.alunoRefId && !autorizados.includes(String(p.alunoRefId))) autorizados.push(String(p.alunoRefId));
                if (p.userId) alunosLiberadosAgora.push(String(p.userId));
            });
            pedidos = [];
        } else if (acao === 'aceitar' && alunoId) {
            const alvoStr = String(alunoId);
            const pedidoAlvo = pedidos.find(p => String(p.userId) === alvoStr || String(p.alunoRefId) === alvoStr);
            if (!autorizados.includes(alvoStr)) autorizados.push(alvoStr);
            if (pedidoAlvo?.alunoRefId && !autorizados.includes(String(pedidoAlvo.alunoRefId))) {
                autorizados.push(String(pedidoAlvo.alunoRefId));
            }
            pedidos = pedidos.filter(p => String(p.userId) !== alvoStr && String(p.alunoRefId) !== alvoStr);
            alunosLiberadosAgora.push(alvoStr);
        } else if (acao === 'recusar' && alunoId) {
            const alvoStr = String(alunoId);
            pedidos = pedidos.filter(p => String(p.userId) !== alvoStr && String(p.alunoRefId) !== alvoStr);
        }

        await db.collection('workspace_video_lives').updateOne(
            { id: live.id, escolaId },
            { $set: { alunosAutorizados: autorizados, pedidosEntrada: pedidos } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_EVENTO',
                subtipo: 'RESPOSTA_ENTRADA',
                salaCodigo: live.codigoSala,
                liveId: live.id,
                acao: acao,
                alunoId: alunoId ? String(alunoId) : null,
                alunosLiberadosAgora: alunosLiberadosAgora,
                alunosAutorizados: autorizados,
                pedidosEntrada: pedidos,
                escolaId: escolaId
            });
        }

        res.status(200).json({
            success: true,
            alunosAutorizados: autorizados,
            pedidosEntrada: pedidos
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao responder solicitação de entrada.' });
    }
});

// ⏹️ Encerra a Sala Ao Vivo (estritamente desta escola!)
router.post('/live/encerrar', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeEncerrar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeEncerrar) return res.status(403).json({ error: 'Apenas o Professor ou Gestor pode encerrar a transmissão.' });

        const escolaId = obterEscolaIdSeguro(req);
        const { liveId } = req.body || {};
        const agoraIso = new Date().toISOString();

        if (liveId) {
            await db.collection('workspace_video_lives').updateOne(
                { id: liveId, escolaId },
                { $set: { ativa: false, encerradaEm: agoraIso, pedidosEntrada: [], participantesAtivos: [] } }
            );
        } else {
            await db.collection('workspace_video_lives').updateMany(
                { escolaId, ativa: true },
                { $set: { ativa: false, encerradaEm: agoraIso, pedidosEntrada: [], participantesAtivos: [] } }
            );
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_STATUS',
                ativa: false,
                live: null,
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, encerradaEm: agoraIso });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao encerrar transmissão.' });
    }
});

// 📜 Consultar Histórico de Lives (APENAS DA PRÓPRIA ESCOLA!)
router.get('/live/historico', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeVer = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeVer) return res.status(403).json({ error: 'Acesso restrito.' });

        const escolaId = obterEscolaIdSeguro(req);
        const historico = await db.collection('workspace_video_lives')
            .find({ escolaId })
            .sort({ criadaEm: -1, iniciadaEm: -1 })
            .limit(80)
            .toArray();

        res.status(200).json({ success: true, historico });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar histórico de lives.' });
    }
});

// 🗑️ Excluir registo do Histórico de Lives (APENAS DA PRÓPRIA ESCOLA!)
router.delete('/live/historico/:id', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeApagar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeApagar) return res.status(403).json({ error: 'Sem permissão.' });

        const escolaId = obterEscolaIdSeguro(req);
        await db.collection('workspace_video_lives').deleteOne({ id: req.params.id, escolaId });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao apagar item do histórico.' });
    }
});

// 🔐 Validar Acesso via Link Criptografado (#live-lvk_...) com Bloqueio Estrito de Escola e Turma
router.get('/live/acesso/:token', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = obterEscolaIdSeguro(req);
        const tokenLimpo = String(req.params.token || '').trim();
        const userId = String(req.userId || '').trim();
        const alunoRefId = String(req.query.alunoRefId || '').trim();

        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [{ tokenCriptografado: tokenLimpo }, { id: tokenLimpo }, { codigoSala: tokenLimpo }]
        });

        if (!live) {
            return res.status(404).json({ success: false, error: 'Link de transmissão inválido ou pertencente a outra instituição.' });
        }

        const isGestorOuProf = await verificarSeEhProfessorOuGestor(db, req);
        if (!isGestorOuProf) {
            const minhasTurmasNorm = await obterTurmasDoAluno(db, userId, alunoRefId, escolaId);
            if (!itemLiberadoParaTurmasDoAluno(live, minhasTurmasNorm, [userId, alunoRefId])) {
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
// 6. CANAL EM TEMPO REAL (CHAT, REAÇÕES, MIC, CÂMARA, MÃO, LOUSA E PRESENÇA)
// ============================================================================
router.post('/live/evento', verificarToken, async (req, res) => {
    try {
        const b = req.body || {};
        const escolaId = obterEscolaIdSeguro(req);
        const db = await connectDB();

        if (b.subtipo === 'PROJETAR_LOUSA') {
            await db.collection('workspace_video_lives').updateMany(
                { escolaId, ativa: true },
                { $set: { lousaProjetada: Boolean(b.lousaAtiva) } }
            );
        }

        if (b.salaCodigo && ['STATUS_MIC', 'STATUS_CAM', 'MAO_LEVANTADA', 'SAIU_ALUNO'].includes(b.subtipo)) {
            const live = await db.collection('workspace_video_lives').findOne({ codigoSala: b.salaCodigo, escolaId, ativa: true });
            if (live) {
                const agoraMs = Date.now();
                let lista = limparParticipantesExpirados(live.participantesAtivos, agoraMs);
                const autorIdStr = String(b.autorId || '').trim();
                const peerIdStr = String(b.peerId || '').trim();
                const nomeNorm = normalizarTexto(b.autorNome || b.nome || '');

                if (b.subtipo === 'SAIU_ALUNO') {
                    lista = lista.filter(p =>
                        !(autorIdStr && String(p.userId) === autorIdStr) &&
                        !(peerIdStr && String(p.peerId) === peerIdStr) &&
                        !(nomeNorm && !autorIdStr && !peerIdStr && normalizarTexto(p.nome) === nomeNorm)
                    );
                } else {
                    lista = lista.map(p => {
                        const mesmo = (autorIdStr && String(p.userId) === autorIdStr) ||
                                      (peerIdStr && String(p.peerId) === peerIdStr) ||
                                      (nomeNorm && !autorIdStr && !peerIdStr && normalizarTexto(p.nome) === nomeNorm);
                        if (!mesmo) return p;
                        return {
                            ...p,
                            micAtivo: b.subtipo === 'STATUS_MIC' ? (b.texto === 'ATIVO' || Boolean(b.micAtivo)) : Boolean(p.micAtivo),
                            camAtiva: b.subtipo === 'STATUS_CAM' ? (b.texto === 'ATIVA' || Boolean(b.camAtiva)) : Boolean(p.camAtiva),
                            maoLevantada: b.subtipo === 'MAO_LEVANTADA'
                                ? (b.maoLevantada !== undefined ? Boolean(b.maoLevantada) : b.texto !== 'ABAIXADA')
                                : Boolean(p.maoLevantada),
                            ultimoSinalMs: agoraMs
                        };
                    });
                }

                await db.collection('workspace_video_lives').updateOne(
                    { id: live.id, escolaId },
                    { $set: { participantesAtivos: lista } }
                );
            }
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
                camAtiva: Boolean(b.camAtiva),
                maoLevantada: b.maoLevantada !== undefined ? Boolean(b.maoLevantada) : (b.subtipo === 'MAO_LEVANTADA' && b.texto !== 'ABAIXADA'),
                horario: new Date().toISOString(),
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao transmitir evento na live.' });
    }
});

// 👥 REGISTO OFICIAL DE PRESENÇA NA SALA AO VIVO (ISOLADO POR ESCOLA)
router.post('/live/presenca', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = obterEscolaIdSeguro(req);
        const b = req.body || {};
        const acao = String(b.acao || 'entrar').toLowerCase();
        const userId = String(req.userId || b.userId || '').trim();
        const peerId = String(b.peerId || '').trim();
        const nome = String(b.nome || 'Participante').trim();
        const role = String(b.role || 'aluno').toLowerCase();

        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [
                ...(b.liveId ? [{ id: b.liveId }] : []),
                ...(b.codigoSala ? [{ codigoSala: b.codigoSala }] : []),
                { ativa: true }
            ]
        });

        if (!live || !live.ativa) {
            return res.status(200).json({ success: false, participantes: [] });
        }

        const agoraMs = Date.now();
        const listaAnterior = Array.isArray(live.participantesAtivos) ? live.participantesAtivos : [];
        let participantes = limparParticipantesExpirados(listaAnterior, agoraMs);
        const houveExpiracao = participantes.length !== listaAnterior.length;

        const mesmoParticipante = (p) => {
            if (userId && p.userId && String(p.userId) === userId) return true;
            if (peerId && p.peerId && String(p.peerId) === peerId) return true;
            return false;
        };

        if (acao === 'sair') {
            participantes = participantes.filter(p => !mesmoParticipante(p));
        } else if (peerId) {
            const existente = participantes.find(mesmoParticipante);
            const registroAtualizado = {
                userId: userId || peerId,
                peerId: peerId,
                nome: nome,
                role: role,
                micAtivo: b.micAtivo !== undefined ? Boolean(b.micAtivo) : Boolean(existente?.micAtivo),
                camAtiva: b.camAtiva !== undefined ? Boolean(b.camAtiva) : Boolean(existente?.camAtiva),
                maoLevantada: b.maoLevantada !== undefined ? Boolean(b.maoLevantada) : Boolean(existente?.maoLevantada),
                entrouEm: existente?.entrouEm || new Date(agoraMs).toISOString(),
                ultimoSinalMs: agoraMs
            };

            participantes = participantes.filter(p => !mesmoParticipante(p));
            participantes.push(registroAtualizado);
        }

        await db.collection('workspace_video_lives').updateOne(
            { id: live.id, escolaId },
            { $set: { participantesAtivos: participantes } }
        );

        const deveNotificarSala = (acao !== 'heartbeat') || houveExpiracao;
        if (deveNotificarSala && global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'VIDEO_LIVE_EVENTO',
                subtipo: 'LISTA_PARTICIPANTES',
                salaCodigo: live.codigoSala,
                liveId: live.id,
                acao: acao,
                atorUserId: userId,
                atorPeerId: peerId,
                participantes: participantes,
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, participantes });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao atualizar presença na live.' });
    }
});

// 📋 Consulta rápida da lista atual de participantes ativos na sala
router.get('/live/participantes', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const escolaId = obterEscolaIdSeguro(req);
        const { liveId, codigoSala } = req.query || {};
        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [
                ...(liveId ? [{ id: liveId }] : []),
                ...(codigoSala ? [{ codigoSala: codigoSala }] : []),
                { ativa: true }
            ]
        });

        if (!live || !live.ativa) {
            return res.status(200).json({ success: true, participantes: [] });
        }

        const participantes = limparParticipantesExpirados(live.participantesAtivos, Date.now());
        res.status(200).json({ success: true, participantes });
    } catch (error) {
        res.status(500).json({ success: false, participantes: [] });
    }
});

// ============================================================================
// 7. CONVITE DIRETO DE ALUNOS PARA A LIVE (ESTRITAMENTE DA PRÓPRIA ESCOLA!)
// ============================================================================
router.get('/live/alunos-convidaveis', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeConvidar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeConvidar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem convidar alunos.' });

        // 🔒 BLINDADO: Apenas alunos ativos da escola autenticada no JWT!
        const filtro = filtroTenant(req);
        const alunosBrutos = await db.collection('alunos').find(filtro).toArray();
        const alunosAtivos = alunosBrutos.filter(ehAlunoAtivo);
        const usuarios = await db.collection('usuarios').find(filtro).toArray();

        const agoraMs = Date.now();
        const JANELA_ONLINE_MS = 35 * 1000;
        const mapaUnicos = new Map();

        alunosAtivos.forEach(aluno => {
            const contaUser = usuarios.find(u =>
                (u.alunoRefId && String(u.alunoRefId) === String(aluno.id)) ||
                (u.id && String(u.id) === String(aluno.id))
            );
            const ultimoAcesso = contaUser?.ultimoAcesso || null;
            const isOnline = Boolean(ultimoAcesso && !isNaN(new Date(ultimoAcesso).getTime()) && (agoraMs - new Date(ultimoAcesso).getTime()) <= JANELA_ONLINE_MS);

            const idChave = String(contaUser?.id || aluno.id);
            const nomeFinal = String(contaUser?.nome || aluno.nome || contaUser?.login || 'Aluno').trim();
            const turmaFinal = Array.isArray(aluno.turmas) && aluno.turmas.length > 0
                ? aluno.turmas.join(', ')
                : (aluno.turma || contaUser?.turma || 'Sem turma');

            mapaUnicos.set(idChave, {
                userId: contaUser?.id ? String(contaUser.id) : String(aluno.id),
                alunoRefId: String(aluno.id),
                nome: nomeFinal,
                turma: turmaFinal,
                avatar: contaUser?.avatar || aluno.avatar || null,
                isOnline: isOnline,
                ultimoAcesso: ultimoAcesso
            });
        });

        usuarios.forEach(u => {
            if (String(u.tipo || '').toLowerCase() !== 'aluno') return;
            const idChave = String(u.id || '');
            if (!idChave || mapaUnicos.has(idChave)) return;
            if (u.alunoRefId && alunosBrutos.some(a => String(a.id) === String(u.alunoRefId) && !ehAlunoAtivo(a))) return;

            const ultimoAcesso = u.ultimoAcesso || null;
            const isOnline = Boolean(ultimoAcesso && !isNaN(new Date(ultimoAcesso).getTime()) && (agoraMs - new Date(ultimoAcesso).getTime()) <= JANELA_ONLINE_MS);

            mapaUnicos.set(idChave, {
                userId: idChave,
                alunoRefId: u.alunoRefId ? String(u.alunoRefId) : '',
                nome: String(u.nome || u.login || 'Aluno').trim(),
                turma: u.turma || 'Aluno',
                avatar: u.avatar || null,
                isOnline: isOnline,
                ultimoAcesso: ultimoAcesso
            });
        });

        const listaOrdenada = Array.from(mapaUnicos.values()).sort((a, b) => {
            if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;
            return a.nome.localeCompare(b.nome, 'pt-BR');
        });

        res.status(200).json({ success: true, alunos: listaOrdenada });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao listar alunos para convite.' });
    }
});

router.post('/live/convidar-aluno', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const podeConvidar = await verificarSeEhProfessorOuGestor(db, req);
        if (!podeConvidar) return res.status(403).json({ error: 'Apenas Professores e Gestores podem convidar alunos.' });

        const escolaId = obterEscolaIdSeguro(req);
        const { liveId, codigoSala, alunoUserId, alunoRefId, alunoNome, professorNome } = req.body || {};
        if (!alunoUserId && !alunoRefId) {
            return res.status(400).json({ error: 'Selecione um aluno válido para convidar.' });
        }

        const live = await db.collection('workspace_video_lives').findOne({
            escolaId,
            $or: [
                ...(liveId ? [{ id: liveId }] : []),
                ...(codigoSala ? [{ codigoSala: codigoSala }] : []),
                { ativa: true }
            ]
        });

        if (!live || !live.ativa) {
            return res.status(404).json({ error: 'Nenhuma aula ao vivo ativa encontrada neste momento.' });
        }

        const idsConvidado = [alunoUserId, alunoRefId].filter(Boolean).map(String);
        const convidadosAtuais = Array.isArray(live.alunosConvidados) ? live.alunosConvidados.map(String) : [];
        const autorizadosAtuais = Array.isArray(live.alunosAutorizados) ? live.alunosAutorizados.map(String) : [];

        const novosConvidados = Array.from(new Set([...convidadosAtuais, ...idsConvidado]));
        const novosAutorizados = Array.from(new Set([...autorizadosAtuais, ...idsConvidado]));

        await db.collection('workspace_video_lives').updateOne(
            { id: live.id, escolaId },
            { $set: { alunosConvidados: novosConvidados, alunosAutorizados: novosAutorizados } }
        );

        const payloadConvite = {
            type: 'CONVITE_LIVE_DIRETO',
            escolaId: escolaId,
            destinatarioIds: idsConvidado,
            destinatarioNome: String(alunoNome || '').trim(),
            liveId: live.id,
            tokenCriptografado: live.tokenCriptografado || live.codigoSala || live.id,
            tituloLive: live.titulo || 'Aula Ao Vivo',
            professorNome: professorNome || live.professorNome || 'Professor',
            destinoNome: live.destinoNome || 'Aula Ao Vivo',
            horario: new Date().toISOString()
        };

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', payloadConvite);
        }

        res.status(200).json({
            success: true,
            alunosConvidados: novosConvidados,
            alunosAutorizados: novosAutorizados
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao enviar convite direto ao aluno.' });
    }
});

// ============================================================================
// 🌐 SERVIDORES ICE / TURN (DESTRAVA CONEXÕES ALUNO ↔ ALUNO NO 4G/5G)
// ============================================================================
const STUN_PADRAO_LIVE = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    { urls: 'stun:stun4.l.google.com:19302' }
];
let cacheIceTurn = { servers: null, expiraEm: 0 };

router.get('/live/ice-servers', verificarToken, async (req, res) => {
    try {
        const agora = Date.now();
        if (cacheIceTurn.servers && agora < cacheIceTurn.expiraEm) {
            return res.status(200).json({ success: true, iceServers: cacheIceTurn.servers, turnAtivo: true });
        }

        let iceServers = [...STUN_PADRAO_LIVE];
        let turnAtivo = false;

        const meteredKey = String(process.env.METERED_API_KEY || '').trim();
        const meteredApp = String(process.env.METERED_APP_NAME || '').trim();
        if (meteredKey && meteredApp) {
            try {
                const urlMetered = `https://${encodeURIComponent(meteredApp)}.metered.live/api/v1/turn/credentials?apiKey=${encodeURIComponent(meteredKey)}`;
                const resp = await fetch(urlMetered, { signal: AbortSignal.timeout(3500) });
                if (resp.ok) {
                    const listaTurn = await resp.json();
                    if (Array.isArray(listaTurn) && listaTurn.length > 0) {
                        iceServers = [...STUN_PADRAO_LIVE, ...listaTurn];
                        turnAtivo = true;
                        cacheIceTurn = { servers: iceServers, expiraEm: agora + 10 * 60 * 1000 };
                    }
                }
            } catch (errMetered) {
                console.warn('⚠️ Aviso Metered TURN (usando fallback STUN):', errMetered.message);
            }
        }

        if (!turnAtivo && process.env.TURN_URL && process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
            const urlsTurn = String(process.env.TURN_URL).split(',').map(u => u.trim()).filter(Boolean);
            if (urlsTurn.length > 0) {
                iceServers.push({
                    urls: urlsTurn,
                    username: String(process.env.TURN_USERNAME).trim(),
                    credential: String(process.env.TURN_CREDENTIAL).trim()
                });
                turnAtivo = true;
                cacheIceTurn = { servers: iceServers, expiraEm: agora + 10 * 60 * 1000 };
            }
        }

        res.status(200).json({ success: true, iceServers, turnAtivo });
    } catch (error) {
        res.status(200).json({ success: true, iceServers: STUN_PADRAO_LIVE, turnAtivo: false });
    }
});

module.exports = router;