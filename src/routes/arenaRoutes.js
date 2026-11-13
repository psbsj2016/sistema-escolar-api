// backend/routes/arenaRoutes.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db'); 

const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado.' });
    next();
};

// 🚀 LISTA DE CENÁRIOS ÉPICOS DE ROLEPLAY (Classificados por Nível CEFR)
const CENARIOS_POR_NIVEL = {
    'A1_A2': [
        { id: 'a1_1', t: "No restaurante, a comida chegou fria e atrasada.", p1: "Unhappy Customer", p2: "Waiter" },
        { id: 'a1_2', t: "No aeroporto, você perdeu a sua bagagem.", p1: "Frustrated Traveler", p2: "Ground Staff" },
        { id: 'a1_3', t: "A comprar um bilhete de comboio para Londres.", p1: "Tourist", p2: "Ticket Agent" },
        { id: 'a1_4', t: "Perdido na cidade, a pedir direções para o hotel.", p1: "Lost Tourist", p2: "Helpful Local" },
        { id: 'a1_5', t: "A fazer o check-in num hotel, mas não encontram a reserva.", p1: "Tired Guest", p2: "Receptionist" }
    ],
    'B1_B2': [
        { id: 'b1_1', t: "Entrevista de emprego para uma vaga de tecnologia.", p1: "Nervous Candidate", p2: "Strict Boss" },
        { id: 'b1_2', t: "Devolução de um produto com defeito na loja.", p1: "Irritated Customer", p2: "Store Manager" },
        { id: 'b1_3', t: "A planear uma viagem: praia versus montanha.", p1: "Mountain Lover", p2: "Beach Lover" },
        { id: 'b1_4', t: "Discussão entre colegas de casa sobre as limpezas.", p1: "Tidy Flatmate", p2: "Messy Flatmate" },
        { id: 'b1_5', t: "A ligar para cancelar o contrato da internet.", p1: "Angry Customer", p2: "Call Center Agent" }
    ],
    'C1_C2': [
        { id: 'c1_1', t: "Debate sobre as implicações éticas da IA na sociedade.", p1: "Tech Optimist", p2: "Cautious Ethicist" },
        { id: 'c1_2', t: "Negociação empresarial de alto risco para uma fusão.", p1: "Aggressive CEO", p2: "Skeptical Investor" },
        { id: 'c1_3', t: "Cimeira global sobre políticas de alterações climáticas.", p1: "Environmental Activist", p2: "Industry Representative" },
        { id: 'c1_4', t: "Discussão filosófica sobre o impacto das redes sociais na mente.", p1: "Digital Minimalist", p2: "Social Media Influencer" },
        { id: 'c1_5', t: "A defender uma tese de mestrado controversa.", p1: "Confident Student", p2: "Critical Professor" }
    ]
};

// 🧠 Função Inteligente que filtra os cenários jogados nos últimos 7 dias
const sortearCenarioNivelado = (nivelProposto, jogadosIds = []) => {
    // Se não for passado um nível válido, escolhemos um nível aleatório para PvP
    const niveisValidos = ['A1_A2', 'B1_B2', 'C1_C2'];
    const nivel = niveisValidos.includes(nivelProposto) ? nivelProposto : niveisValidos[Math.floor(Math.random() * niveisValidos.length)];
    
    let pool = CENARIOS_POR_NIVEL[nivel];
    
    // Filtra os cenários que o aluno já jogou
    let disponiveis = pool.filter(c => !jogadosIds.includes(c.id));
    
    // Se o aluno foi tão dedicado que já jogou todos deste nível, recomeçamos a lista!
    if (disponiveis.length === 0) disponiveis = pool;
    
    return disponiveis[Math.floor(Math.random() * disponiveis.length)];
};

// ============================================================================
// ⚔️ ARENA: SISTEMA DE DESAFIO ALEATÓRIO RÁPIDO (SINALIZADOR)
// ============================================================================
// Memória RAM ultrarrápida do servidor para gerir quem clica primeiro
global.desafiosAtivos = global.desafiosAtivos || {};

// 🚀 CORREÇÃO 1: Rota ajustada para não ter '/arena' duplicado
router.post('/desafio-aleatorio', verificarToken, async (req, res) => {
    try {
        const { desafianteNome, escolaId, minutos } = req.body;
        const desafioId = 'rnd_' + Date.now();
        
        global.desafiosAtivos[desafioId] = { 
            status: 'pendente', 
            desafiante: desafianteNome,
            minutos: parseInt(minutos) || 10 // Guarda o tempo escolhido
        };

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'DESAFIO_ALEATORIO_BROADCAST',
                desafioId: desafioId,
                desafianteNome: desafianteNome,
                escolaId: escolaId || 'DEFAULT',
                minutos: minutos || 10
            });
        }

        res.json({ success: true, desafioId });
    } catch (e) {
        res.status(500).json({ error: 'Erro ao lançar o sinalizador.' });
    }
});

// 🚀 CORREÇÃO 2: Cria a Sala e emite o Raio Trator (ARENA_MATCH_ENCONTRADO)
router.post('/desafio-aleatorio/aceitar', verificarToken, async (req, res) => {
    try {
        const { desafioId, desafiadoNome, escolaId } = req.body;
        const db = await connectDB();
        
        const desafio = global.desafiosAtivos[desafioId];
        if (!desafio) return res.status(404).json({ error: 'Este desafio já expirou ou não existe.' });
        
        if (desafio.status === 'aceito') {
            return res.status(400).json({ error: 'Alguém foi mais rápido e já aceitou este desafio! 🏃💨' });
        }

        desafio.status = 'aceito';
        desafio.desafiado = desafiadoNome;

        const userDesafiado = await db.collection('usuarios').findOne({ $or: [{nome: desafiadoNome}, {login: desafiadoNome}] });
        const userDesafiante = await db.collection('usuarios').findOne({ $or: [{nome: desafio.desafiante}, {login: desafio.desafiante}] });

        const salaId = 'rnd-match-' + Date.now();
        // 🚀 O NOVO SORTEADOR (null significa nível aleatório para PvP)
        const cenarioSorteado = sortearCenarioNivelado(null);

        const novaSala = {
            id: salaId,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'desafio_aleatorio',
            status: 'em_curso',
            jogador1: { id: userDesafiante?.id || null, nome: desafio.desafiante },
            jogador2: { id: userDesafiado?.id || null, nome: desafiadoNome },
            limiteMinutos: desafio.minutos,
            iniciadoEm: new Date().toISOString(),
            cenario: "⚡ COMBATE ALEATÓRIO RÁPIDO ⚡\n" + cenarioSorteado.t, // Puxa o texto (.t)
            cenarioObj: cenarioSorteado, // 🚀 Guarda o objeto rico
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'DESAFIO_ALEATORIO_FECHADO',
                desafioId: desafioId,
                desafianteNome: desafio.desafiante,
                desafiadoNome: desafiadoNome,
                escolaId: escolaId || 'DEFAULT'
            });

            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                destinatarios: [desafio.desafiante, desafiadoNome],
                destinatariosIds: [userDesafiante?.id, userDesafiado?.id], 
                salaId: salaId,
                limiteMinutos: novaSala.limiteMinutos,
                cenario: novaSala.cenario,
                cenarioObj: cenarioSorteado, // 🚀 Envia o objeto rico para o Frontend
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.json({ success: true, desafianteNome: desafio.desafiante, salaId: salaId });
    } catch (e) {
        res.status(500).json({ error: 'Erro ao processar aceitação.' });
    }
});

// 🚀 DESAFIO DIRETO A PARTIR DO CARTÃO DO FEED (10 MINUTOS)
router.post('/desafio-direto', verificarToken, async (req, res) => {
    try {
        const { desafiadoNome, desafianteNome, escolaId, minutos, postId } = req.body;
        if (!desafiadoNome || !desafianteNome) {
            return res.status(400).json({ error: 'Dados do desafio incompletos.' });
        }

        const salaId = 'dir_' + Date.now() + '_' + Math.floor(Math.random() * 1000);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_DESAFIO_DIRETO',
                salaId: salaId,
                desafianteNome: desafianteNome,
                destinatarios: [desafiadoNome],
                minutos: parseInt(minutos, 10) || 10,
                postId: postId || null,
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true, salaId });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao enviar desafio direto.' });
    }
});

router.post('/desafio-direto/aceitar', verificarToken, async (req, res) => {
    try {
        const { salaId, desafiadoNome, desafianteNome, escolaId, minutos, postId } = req.body;
        const db = await connectDB();

        const userDesafiado = await db.collection('usuarios').findOne({ $or: [{ nome: desafiadoNome }, { login: desafiadoNome }] });
        const userDesafiante = await db.collection('usuarios').findOne({ $or: [{ nome: desafianteNome }, { login: desafianteNome }] });

        const salaIdFinal = salaId || ('dir_match_' + Date.now());
        const cenarioSorteado = sortearCenarioNivelado(null);

        const novaSala = {
            id: salaIdFinal,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'desafio_direto',
            status: 'em_curso',
            jogador1: { id: userDesafiante?.id || null, nome: desafianteNome },
            jogador2: { id: userDesafiado?.id || null, nome: desafiadoNome },
            limiteMinutos: parseInt(minutos, 10) || 10,
            iniciadoEm: new Date().toISOString(),
            cenario: "⚔️ DUELO DIRETO DO FEED ⚔️\n" + cenarioSorteado.t,
            cenarioObj: cenarioSorteado,
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        // Se veio de um post de desafio no Feed, remove o post antigo para ninguém mais clicar num duelo já iniciado
        if (postId) {
            await db.collection('workspace_posts').deleteOne({ id: String(postId) });
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'POST_APAGADO',
                    postId: String(postId),
                    escolaId: escolaId || 'DEFAULT'
                });
            }
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                destinatarios: [desafianteNome, desafiadoNome],
                destinatariosIds: [userDesafiante?.id, userDesafiado?.id].filter(Boolean),
                salaId: salaIdFinal,
                limiteMinutos: novaSala.limiteMinutos,
                cenario: novaSala.cenario,
                cenarioObj: cenarioSorteado,
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true, salaId: salaIdFinal });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao iniciar duelo direto.' });
    }
});

router.post('/desafio-direto/recusar', verificarToken, async (req, res) => {
    try {
        const { desafianteNome, escolaId } = req.body;
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_DESAFIO_RECUSADO',
                destinatarios: [desafianteNome],
                escolaId: escolaId || 'DEFAULT'
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao recusar desafio.' }); }
});

// ============================================================================
// 🗣️ NOVO AMBIENTE: SALA DE PRÁTICA LIVRE EM GRUPO (SEM CONTEXTO • ATÉ 5 PESSOAS)
// ============================================================================
router.post('/grupo-livre/criar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, colegasNomes = [], escolaId, limiteMinutos } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';
        const db = await connectDB();

        const listaNomesLimpa = Array.isArray(colegasNomes)
            ? Array.from(new Set(colegasNomes.map(n => String(n || '').trim()).filter(Boolean))).slice(0, 4)
            : [];

        if (listaNomesLimpa.length === 0) {
            return res.status(400).json({ error: 'Adicione pelo menos 1 colega (máximo 4 colegas + você = 5 pessoas).' });
        }

        const destinatariosNomes = new Set();
        const destinatariosIds = new Set();

        for (const nomeBusca of listaNomesLimpa) {
            const esc = nomeBusca.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regexExato = new RegExp(`^\\s*${esc}\\s*$`, 'i');
            const regexParcial = new RegExp(esc, 'i');

            let u = await db.collection('usuarios').findOne({ $or: [{ nome: regexExato }, { login: regexExato }] });
            let a = await db.collection('alunos').findOne({ $or: [{ nome: regexExato }, { login: regexExato }] });

            if (!u && !a) {
                u = await db.collection('usuarios').findOne({ $or: [{ nome: regexParcial }, { login: regexParcial }] });
                if (!u) a = await db.collection('alunos').findOne({ $or: [{ nome: regexParcial }, { login: regexParcial }] });
            }
            if (!u && a) {
                u = await db.collection('usuarios').findOne({ $or: [{ alunoRefId: String(a.id) }, { id: String(a.id) }] });
            }

            if (u || a) {
                if (u?.nome) destinatariosNomes.add(u.nome.trim());
                if (u?.login) destinatariosNomes.add(u.login.trim());
                if (a?.nome) destinatariosNomes.add(a.nome.trim());
                if (u?.id) destinatariosIds.add(String(u.id));
                if (u?.alunoRefId) destinatariosIds.add(String(u.alunoRefId));
                if (a?.id) destinatariosIds.add(String(a.id));
            } else {
                destinatariosNomes.add(nomeBusca);
            }
        }

        const salaId = 'livre-' + Date.now() + '-' + crypto.randomUUID().substring(0, 6);
        const cenarioLivreObj = {
            id: 'livre_aberto',
            t: 'Prática Livre em Grupo (Sem Contexto Fixo)',
            p1: 'Participante',
            p2: 'Participante',
            livre: true
        };

        const novaSala = {
            id: salaId,
            escolaId: escolaAlvo,
            tipo: 'grupo_livre',
            status: 'em_curso',
            maxParticipantes: 5,
            jogador1: { id: String(alunoId), nome: alunoNome, papel: 'Prática Livre' },
            jogador2: null,
            participantes: [
                { id: String(alunoId), nome: alunoNome, papel: 'Prática Livre' }
            ],
            convidados: listaNomesLimpa,
            papeisDefinidos: true,
            limiteMinutos: parseInt(limiteMinutos, 10) || 30,
            iniciadoEm: new Date().toISOString(),
            cenario: '🗣️ PRÁTICA LIVRE EM GRUPO (Sem Contexto Fixo)',
            cenarioObj: cenarioLivreObj,
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_GRUPO',
                salaId: salaId,
                remetenteNome: alunoNome,
                destinatarios: Array.from(destinatariosNomes),
                destinatariosIds: Array.from(destinatariosIds),
                limiteMinutos: novaSala.limiteMinutos,
                cenarioObj: cenarioLivreObj,
                escolaId: escolaAlvo
            });
        }

        res.status(201).json({
            success: true,
            salaId: salaId,
            limiteMinutos: novaSala.limiteMinutos,
            cenarioObj: cenarioLivreObj,
            participantes: novaSala.participantes
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar sala de prática livre.' });
    }
});

router.post('/grupo-livre/:salaId/entrar', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const { alunoId, alunoNome, escolaId } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';
        const db = await connectDB();

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala || sala.status === 'finalizado' || sala.status === 'cancelado') {
            return res.status(404).json({ error: 'Esta sala de treino já foi encerrada.' });
        }

        const participantesAtuais = Array.isArray(sala.participantes) && sala.participantes.length > 0
            ? [...sala.participantes]
            : [sala.jogador1, sala.jogador2].filter(Boolean);

        const jaEstaNaSala = participantesAtuais.some(p =>
            String(p.id) === String(alunoId) ||
            String(p.nome || '').trim().toLowerCase() === String(alunoNome || '').trim().toLowerCase()
        );

        if (!jaEstaNaSala) {
            if (participantesAtuais.length >= 5) {
                return res.status(400).json({ error: 'A sala já atingiu o limite máximo de 5 pessoas!' });
            }
            participantesAtuais.push({
                id: String(alunoId),
                nome: alunoNome,
                papel: 'Prática Livre'
            });
        }

        const updateFields = { participantes: participantesAtuais };
        if (!sala.jogador2 && String(sala.jogador1?.id) !== String(alunoId)) {
            updateFields.jogador2 = { id: String(alunoId), nome: alunoNome, papel: 'Prática Livre' };
        }

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: updateFields }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_GRUPO_ATUALIZADO',
                salaId: salaId,
                participantes: participantesAtuais,
                novoMembro: alunoNome,
                escolaId: escolaAlvo
            });
        }

        res.status(200).json({
            success: true,
            salaId: salaId,
            limiteMinutos: sala.limiteMinutos,
            cenarioObj: sala.cenarioObj || { id: 'livre_aberto', t: 'Prática Livre em Grupo', livre: true },
            participantes: participantesAtuais
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao entrar na sala de grupo.' });
    }
});

// ============================================================================
// 🤖 MODO SOLO: TREINO CONTRA A IA (PvE)
// ============================================================================
router.post('/solo', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId, limiteMinutos, nivel, jogados } = req.body;
        const db = await connectDB();
        
        const salaId = 'solo-' + Date.now() + '-' + crypto.randomUUID().substring(0, 8);
        
        // 🚀 O NOVO MOTOR: Escolhe o cenário baseado no nível e na memória do aluno
        const cenarioSorteado = sortearCenarioNivelado(nivel, jogados || []);

        const novaSala = {
            id: salaId,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'solo',
            status: 'em_curso', 
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: 'ia_groq', nome: 'Mestre da Guilda 🤖' },
            limiteMinutos: parseInt(limiteMinutos) || 15,
            iniciadoEm: new Date().toISOString(),
            cenario: "🤖 TREINO SOLO \n" + cenarioSorteado.t,
            cenarioObj: cenarioSorteado, // 🚀 Guardamos o objeto completo para o Frontend
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);
        
        res.status(200).json({ success: true, salaId: novaSala.id, cenarioObj: cenarioSorteado });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao invocar a IA para treino solo.' }); 
    }
});

// 0. Rota para Listar Todos os Guerreiros Ativos da Escola (Com ou Sem Foto de Perfil!)
router.get('/guerreiros', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const usuarios = await db.collection('usuarios').find({}).toArray();
        const alunos = await db.collection('alunos').find({}).toArray();

        const ehAlunoAtivo = (aluno) => {
            if (!aluno) return false;
            const st = String(aluno.status || 'Ativo').trim().toLowerCase();
            if (st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist')) {
                return false;
            }
            return st === 'ativo' || st === '';
        };

        const idsAlunosInativos = new Set(
            alunos.filter(a => !ehAlunoAtivo(a)).map(a => String(a.id))
        );

        const mapaGuerreiros = new Map();

        // 1. Adiciona utilizadores com conta ativa
        usuarios.forEach(u => {
            if (u.alunoRefId && idsAlunosInativos.has(String(u.alunoRefId))) return;
            const fichaAluno = alunos.find(a =>
                (u.alunoRefId && String(a.id) === String(u.alunoRefId)) ||
                (u.id && String(a.id) === String(u.id))
            );
            if (fichaAluno && !ehAlunoAtivo(fichaAluno)) return;

            const nomeExibicao = String(u.nome || (fichaAluno && fichaAluno.nome) || u.login || '').trim();
            if (!nomeExibicao) return;

            const chave = nomeExibicao.toLowerCase();
            mapaGuerreiros.set(chave, {
                id: String(u.id || ''),
                alunoRefId: u.alunoRefId ? String(u.alunoRefId) : (fichaAluno?.id ? String(fichaAluno.id) : null),
                nome: nomeExibicao,
                login: String(u.login || '').trim(),
                avatar: u.avatar || (fichaAluno && fichaAluno.avatar) || null,
                tipo: u.tipo || 'Aluno'
            });
        });

        // 2. Garante também alunos ativos da coleção 'alunos' caso ainda não estejam mapeados
        alunos.filter(ehAlunoAtivo).forEach(a => {
            const nomeAl = String(a.nome || a.login || '').trim();
            if (!nomeAl) return;
            const chave = nomeAl.toLowerCase();
            if (!mapaGuerreiros.has(chave)) {
                const jaMapeadoPorRef = Array.from(mapaGuerreiros.values()).some(g => g.alunoRefId === String(a.id) || g.id === String(a.id));
                if (!jaMapeadoPorRef) {
                    mapaGuerreiros.set(chave, {
                        id: String(a.id || ''),
                        alunoRefId: String(a.id || ''),
                        nome: nomeAl,
                        login: String(a.login || '').trim(),
                        avatar: a.avatar || null,
                        tipo: 'Aluno'
                    });
                }
            }
        });

        res.status(200).json({ success: true, guerreiros: Array.from(mapaGuerreiros.values()) });
    } catch (error) {
        res.status(500).json({ success: false, guerreiros: [] });
    }
});

// 1. Rota para Procurar Duelo Aleatório
router.post('/procurar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId, limiteMinutos } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';
        const db = await connectDB();
        
        const salaEspera = await db.collection('workspace_arenas').findOne({
            escolaId: { $in: [escolaAlvo, 'DEFAULT'] }, tipo: 'aleatorio', status: 'aguardando', 'jogador1.id': { $ne: alunoId }
        });

        if (salaEspera) {
            const cenarioSorteado = sortearCenarioNivelado(null);

            await db.collection('workspace_arenas').updateOne(
                { id: salaEspera.id },
                { $set: { 
                    status: 'em_curso', 
                    jogador2: { id: alunoId, nome: alunoNome },
                    iniciadoEm: new Date().toISOString(),
                    cenario: cenarioSorteado.t,
                    cenarioObj: cenarioSorteado
                }}
            );

            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_MATCH_ENCONTRADO',
                    salaId: salaEspera.id,
                    destinatarios: [salaEspera.jogador1.nome, alunoNome],
                    destinatariosIds: [salaEspera.jogador1.id, alunoId].filter(Boolean),
                    escolaId: escolaAlvo,
                    limiteMinutos: salaEspera.limiteMinutos,
                    cenario: cenarioSorteado.t,
                    cenarioObj: cenarioSorteado
                });
            }
            return res.status(200).json({ success: true, salaId: salaEspera.id, mensagem: 'Oponente encontrado!' });
        } else {
            const novaSala = {
                id: crypto.randomUUID(), escolaId: escolaAlvo, tipo: 'aleatorio', status: 'aguardando',
                jogador1: { id: alunoId, nome: alunoNome }, jogador2: null,
                limiteMinutos: parseInt(limiteMinutos) || 50, criadoEm: new Date().toISOString()
            };
            await db.collection('workspace_arenas').insertOne(novaSala);
            return res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'A aguardar oponente...' });
        }
    } catch (error) { res.status(500).json({ error: 'Erro ao aceder à Arena.' }); }
});

// 2. Rota para Convidar um Colega Específico (Blindada com Cruzamento Usuarios + Alunos e EscolaId Default)
router.post('/convidar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, colegaNome, escolaId, limiteMinutos } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';
        const db = await connectDB();

        const nomeBusca = String(colegaNome || '').trim();
        if (!nomeBusca) return res.status(400).json({ error: 'Informe o nome do colega.' });

        const nomeEscapado = nomeBusca.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regexExato = new RegExp(`^\\s*${nomeEscapado}\\s*$`, 'i');
        const regexParcial = new RegExp(nomeEscapado, 'i');

        // 1. Procura primeiro por correspondência exata em usuarios e alunos
        let userConta = await db.collection('usuarios').findOne({
            $or: [{ nome: regexExato }, { login: regexExato }, { id: nomeBusca }]
        });
        let fichaAluno = await db.collection('alunos').findOne({
            $or: [{ nome: regexExato }, { login: regexExato }, { id: nomeBusca }]
        });

        // 2. Se não achou exato, procura por correspondência parcial
        if (!userConta && !fichaAluno) {
            userConta = await db.collection('usuarios').findOne({
                $or: [{ nome: regexParcial }, { login: regexParcial }]
            });
            if (!userConta) {
                fichaAluno = await db.collection('alunos').findOne({
                    $or: [{ nome: regexParcial }, { login: regexParcial }]
                });
            }
        }

        // 3. Se achou apenas a ficha do aluno, localiza a conta de login correspondente em 'usuarios'
        if (!userConta && fichaAluno) {
            userConta = await db.collection('usuarios').findOne({
                $or: [
                    { alunoRefId: String(fichaAluno.id) },
                    { id: String(fichaAluno.id) },
                    ...(fichaAluno.login ? [{ login: new RegExp(`^\\s*${String(fichaAluno.login).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'i') }] : [])
                ]
            });
        } else if (userConta && !fichaAluno && userConta.alunoRefId) {
            fichaAluno = await db.collection('alunos').findOne({ id: String(userConta.alunoRefId) });
        }

        const userAlvo = userConta || fichaAluno;
        if (!userAlvo) return res.status(404).json({ error: 'Guerreiro não encontrado! Selecione um nome sugerido na lista.' });

        const nomeColegaReal = (userConta && userConta.nome) ? userConta.nome : (userAlvo.nome || userAlvo.login);
        const idPrincipalAlvo = userConta ? String(userConta.id) : String(userAlvo.id);

        const destinatariosNomes = Array.from(new Set([
            nomeColegaReal,
            userConta?.nome,
            userConta?.login,
            fichaAluno?.nome,
            fichaAluno?.login
        ].filter(Boolean)));

        const destinatariosIds = Array.from(new Set([
            idPrincipalAlvo,
            userConta?.id ? String(userConta.id) : null,
            userConta?.alunoRefId ? String(userConta.alunoRefId) : null,
            fichaAluno?.id ? String(fichaAluno.id) : null
        ].filter(Boolean)));

        const novaSala = {
            id: crypto.randomUUID(),
            escolaId: escolaAlvo,
            tipo: 'convite',
            status: 'aguardando',
            jogador1: { id: String(alunoId), nome: alunoNome },
            jogador2: { id: idPrincipalAlvo, nome: nomeColegaReal },
            limiteMinutos: parseInt(limiteMinutos) || 50,
            criadoEm: new Date().toISOString()
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_RECEBIDO',
                salaId: novaSala.id,
                remetenteNome: alunoNome,
                destinatarios: destinatariosNomes,
                destinatariosIds: destinatariosIds,
                escolaId: escolaAlvo,
                limiteMinutos: novaSala.limiteMinutos
            });
        }
        res.status(201).json({ success: true, salaId: novaSala.id, nomeConvidado: nomeColegaReal, mensagem: 'Convite enviado!' });
    } catch (error) { res.status(500).json({ error: 'Erro ao enviar convite.' }); }
});

// Quando o convidado aceita
router.post('/:salaId/aceitar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId } = req.body;
        const escolaAlvo = escolaId || 'DEFAULT';
        const salaId = req.params.salaId;
        const db = await connectDB();

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        const cenarioSorteado = sortearCenarioNivelado(null);

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { 
                status: 'em_curso', 'jogador2.id': alunoId, 'jogador2.nome': alunoNome, 
                iniciadoEm: new Date().toISOString(), 
                cenario: cenarioSorteado.t,
                cenarioObj: cenarioSorteado
            } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                salaId: salaId,
                destinatarios: [sala.jogador1.nome, alunoNome].filter(Boolean),
                destinatariosIds: [String(sala.jogador1.id), String(alunoId)].filter(Boolean), 
                escolaId: escolaAlvo,
                limiteMinutos: sala.limiteMinutos,
                cenario: cenarioSorteado.t,
                cenarioObj: cenarioSorteado
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao aceitar convite.' }); }
});

// ============================================================================
// 🆘 LIFELINE: BOTÃO DE SOCORRO (IDEIAS DA IA)
// ============================================================================
router.post('/:salaId/ajuda', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const db = await connectDB();
        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });

        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        let dialogo = '';
        if (sala.historico && sala.historico.length > 0) {
            // Puxamos apenas as últimas 8 mensagens para a IA não se distrair
            sala.historico.slice(-8).forEach(fala => {
                dialogo += `[${fala.autorNome}]: ${fala.texto}\n`;
            });
        } else {
            dialogo = "(O debate acabou de começar. Ninguém falou ainda.)";
        }

        const promptIA = `
        Você é um professor de inglês ajudando um aluno que "deu branco" no meio de um Roleplay.
        Cenário atual: "${sala.cenario || 'Conversa livre'}"
        Diálogo até o momento:
        ${dialogo}

        A sua missão: O aluno precisa de falar agora e não sabe o que dizer. Forneça EXATAMENTE 3 opções de frases curtas (máximo 7 palavras cada), naturais e em inglês, que ele possa usar para continuar a conversa de forma lógica.
        Retorne APENAS um JSON válido nesta estrutura exata: {"sugestoes": ["Frase 1", "Frase 2", "Frase 3"]}
        `;

        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.6, // Equilíbrio perfeito entre criatividade e precisão
            response_format: { type: 'json_object' }
        });

        const resposta = JSON.parse(completion.choices[0].message.content);
        res.status(200).json({ success: true, sugestoes: resposta.sugestoes });
    } catch (error) {
        console.error("Erro no Socorro da IA:", error);
        res.status(500).json({ error: 'O Mestre não pôde formular as dicas a tempo.' });
    }
});

// ============================================================================
// 🧙‍♂️ O MESTRE DA GUILDA COMO NPC (INTERVENÇÃO NO CHAT)
// ============================================================================
async function intervirComoMestre(sala, escolaId) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const db = await connectDB();
        let dialogo = '';
        
        // Aumentámos um pouco o histórico lido para o Mestre ter ainda mais contexto
        sala.historico.slice(-10).forEach(fala => { 
            dialogo += `[${fala.autorNome}]: ${fala.texto}\n`; 
        });

        // 🚀 PROMPT AFINADO: Foco 100% no contexto da conversa atual!
        const promptIA = `
        Aja como o "Mestre da Guilda" (um NPC sábio que observa a cena) interagindo DIRETAMENTE no Roleplay de inglês entre os alunos.
        Cenário atual: "${sala.cenario || 'Conversa livre'}".
        
        Diálogo recente:
        ${dialogo}
        
        Sua missão: Leia o diálogo acima e faça um comentário ou adicione uma ação PERFEITAMENTE alinhada com o que eles estão a debater neste exato momento. Não mude de assunto nem crie eventos aleatórios descontextualizados. Acompanhe a "vibe" e o ritmo da conversa.
        Regras:
        1. O seu idioma DEVE ser INGLÊS.
        2. Escreva APENAS a sua fala (sem o seu nome, sem aspas e sem JSON).
        3. Seja um personagem imersivo na cena (ex: o gerente, um passante, uma voz no intercomunicador, ou uma voz narrativa) que reage estritamente à ÚLTIMA coisa que aconteceu.
        4. Seja breve (máximo 2 frases curtas).
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.6 // Temperatura afinada para ser criativo, mas não perder o rumo
        });

        const falaDoMestre = completion.choices[0].message.content.trim();

        const novaFalaIA = { 
            id: crypto.randomUUID(), 
            autorId: 'mestre_guilda', 
            autorNome: '🧙‍♂️ Mestre da Guilda', 
            texto: falaDoMestre, 
            data: new Date().toISOString() 
        };

        await db.collection('workspace_arenas').updateOne({ id: sala.id }, { $push: { historico: novaFalaIA } });

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_NOVA_FALA', 
                salaId: sala.id, 
                fala: novaFalaIA, 
                escolaId: escolaId || 'DEFAULT'
            });
        }
    } catch (error) { console.error("Erro na Intervenção do Mestre:", error); }
}

// 3. Rota para Receber a Voz e Disparar a IA (Com o novo Ritmo)
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId, combo } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();
        
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, combo, data: new Date().toISOString() };
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        
        // 🚀 GATILHO DO MODO SOLO (Treino contra a IA)
        // O Mestre da Guilda agora foca-se APENAS em responder no modo Solo. O combate PvP fica 100% limpo!
        if (salaAtualizada && salaAtualizada.tipo === 'solo' && autorId !== 'ia_groq') {
            responderComoIA(salaAtualizada, escolaId);
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'ARENA_NOVA_FALA', salaId: salaId, fala: novaFala, escolaId: escolaId || 'DEFAULT' });
        }
        
        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar a fala.' }); }
});

// Faz a IA conversar com o aluno no Modo Solo
async function responderComoIA(sala, escolaId) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        let dialogo = '';
        
        // Pega no máximo nas últimas 15 mensagens para manter o contexto rápido e barato
        sala.historico.slice(-15).forEach(fala => { 
            dialogo += `[${fala.autorNome}]: ${fala.texto}\n`; 
        });

        // 🚀 O SEGREDO DOS PAPÉIS NO MODO SOLO: A IA lê o que sobrou!
        const papelIA = sala.jogador2.papel || "a OUTRA pessoa na cena";
        const papelAluno = sala.jogador1.papel || "o protagonista";

        const promptIA = `
        Aja estritamente como um personagem num Roleplay em inglês com um aluno.
        Cenário da cena: "${sala.cenario || 'Conversa livre'}".
        Você é: ${papelIA}.
        O aluno (${sala.jogador1.nome}) é: ${papelAluno}.
        
        Diálogo até ao momento:
        ${dialogo}
        
        Como VOCÊ (${papelIA}) responde agora à última mensagem?
        Regras de ouro:
        1. Escreva apenas a sua fala, sem o seu nome, sem aspas e sem explicações.
        2. Seja muito natural, direto e conversacional. Use vocabulário nativo.
        3. Termine quase sempre com uma pergunta ou um gatilho para o aluno ter de responder.
        4. O idioma da sua resposta DEVE ser estritamente Inglês.
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b', // 🚀 MODELO OFICIAL DA SUA PLATAFORMA ALINHADO!
            temperature: 0.6 // Temperatura equilibrada para respostas naturais
        });

        const respostaDaIA = completion.choices[0].message.content.trim();
        
        // Constrói o objeto de fala da IA
        const novaFalaIA = { 
            id: crypto.randomUUID(), 
            autorId: 'ia_groq', 
            autorNome: 'Mestre da Guilda 🤖', 
            texto: respostaDaIA, 
            data: new Date().toISOString() 
        };

        const db = await connectDB();
        await db.collection('workspace_arenas').updateOne({ id: sala.id }, { $push: { historico: novaFalaIA } });

        // Dispara a fala da IA pelo túnel para desenhar no ecrã do aluno
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_NOVA_FALA', salaId: sala.id, fala: novaFalaIA, escolaId: escolaId || 'DEFAULT'
            });
        }
    } catch (error) { 
        console.error("Erro na resposta Solo da IA:", error); 
    }
}

// ============================================================================
// 🚑 SALVA-VIDAS DA IA E ROTAS FINAIS MANTIDAS INTACTAS
// ============================================================================
async function gerarFeedbackEmergencia(dialogo, nomeJogador) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const prompt = `Atue como um professor de inglês. Leia este diálogo:\n\n${dialogo}\n\nO aluno "${nomeJogador}" participou. Escreva UMA ÚNICA FRASE curta em português dando uma dica gramatical útil ou corrigindo um erro que ele cometeu no diálogo. Não use aspas. Seja motivador.`;
        const completion = await groq.chat.completions.create({ messages: [{ role: 'user', content: prompt }], model: 'openai/gpt-oss-120b', temperature: 0.4 });
        return completion.choices[0].message.content.trim();
    } catch (e) { return "O seu esforço foi notável! Continue a praticar para aprimorar a sua fluência."; }
}

router.post('/:salaId/avaliar', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const db = await connectDB();
        const escolaId = req.body.escolaId || 'DEFAULT';

        // 🚀 TRAVA ATÓMICA (Anti-Colisão Dupla): Apenas 1 jogador aciona a IA
        const updateResult = await db.collection('workspace_arenas').updateOne(
            { id: salaId, status: 'em_curso' },
            { $set: { status: 'avaliando' } }
        );

        // Se não modificou, é porque a sala já está em avaliação pelo outro jogador ou já acabou!
        if (updateResult.modifiedCount === 0) {
            return res.status(200).json({ success: true, mensagem: 'Avaliação já em andamento. Aguarde o Mestre.' });
        }

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        const isSolo = sala.tipo === 'solo'; // 🚀 Deteta se é modo Treino

        let dialogo = '';
        if (sala.historico && sala.historico.length > 0) {
            sala.historico.forEach(fala => { 
                let comboStr = (fala.combo && fala.combo > 0) ? ` (Speed Combo 🔥x${fala.combo})` : '';
                dialogo += `[${fala.autorNome}]${comboStr}: ${fala.texto}\n`; 
            });
        } else {
            dialogo = "(Os alunos permaneceram em silêncio.)";
        }

        const promptIA = `
        Aja como um professor nativo de inglês avaliando um "Roleplay" (duelo de fluência).
        Cenário encenado: "${sala.cenario || 'Conversa livre'}"
        Níveis de Evolução: 1. "Safira", 2. "Ametista", 3. "Rubi", 4. "Diamante Estelar".
        Jogadores: - ${sala.jogador1.nome} | - ${sala.jogador2 ? sala.jogador2.nome : 'Nenhum'}
        Diálogo: ${dialogo}
        Retorne APENAS um JSON: {"vencedor": "Nome ou Empate", "feedbackGeral": "Comentário", "jogadores": [{"nome": "Nome Aluno", "cristal": "Safira", "titulo": "Orador Audaz", "feedback": "Correção curta"}]}
        `;

        let resultadoAvaliacao = {};
        
        // 🚀 PROTEÇÃO SALVA-VIDAS CONTRA QUEDAS DA IA
        try {
            const Groq = require('groq-sdk');
            const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
            const completion = await groq.chat.completions.create({
                messages: [{ role: 'user', content: promptIA }], 
                model: 'openai/gpt-oss-120b', // 🚀 Unificado para evitar erros de limite de taxa 
                temperature: 0.2, 
                response_format: { type: 'json_object' }
            });
            resultadoAvaliacao = JSON.parse(completion.choices[0].message.content); 
        } catch (iaError) {
            console.error("🚨 Erro na Groq durante a avaliação:", iaError);
            // Fallback elegante para destravar os alunos em caso de falha da IA!
            resultadoAvaliacao = { 
                vencedor: "Empate", 
                feedbackGeral: "A conexão com os Deuses da Arena oscilou, mas a vossa coragem foi registada! Excelente treino.", 
                jogadores: [] 
            };
        }

        const jogadoresReais = (Array.isArray(sala.participantes) && sala.participantes.length > 0)
            ? sala.participantes.filter(j => j && j.id)
            : [sala.jogador1, sala.jogador2].filter(j => j && j.id);
        const jogadoresCorrigidosParaFrontend = [];

        for (const jogadorReal of jogadoresReais) {
            let avaliacaoIA = resultadoAvaliacao.jogadores?.find(j => 
                String(j.nome).toLowerCase().trim().includes(String(jogadorReal.nome).toLowerCase().trim()) ||
                String(jogadorReal.nome).toLowerCase().trim().includes(String(j.nome).toLowerCase().trim())
            );

            if (!avaliacaoIA) {
                const dicaSalvadora = await gerarFeedbackEmergencia(dialogo, jogadorReal.nome);
                avaliacaoIA = { nome: jogadorReal.nome, feedback: dicaSalvadora };
            }

            const userRecord = await db.collection('usuarios').findOne({ id: jogadorReal.id });
            const alunoRef = userRecord ? userRecord.alunoRefId : null;

            const duelosAtuais = (userRecord && userRecord.arenaStats && userRecord.arenaStats.duelosConcluidos) ? userRecord.arenaStats.duelosConcluidos : 0;
            const novosDuelos = duelosAtuais + 1; 

            let cristalCalculado = 'Safira', tituloCalculado = 'Iniciante da Arena';
            if (novosDuelos >= 30) { cristalCalculado = 'Diamante'; tituloCalculado = 'Lenda Nativa'; } 
            else if (novosDuelos >= 15) { cristalCalculado = 'Rubi'; tituloCalculado = 'Mestre do Diálogo'; } 
            else if (novosDuelos >= 5) { cristalCalculado = 'Ametista'; tituloCalculado = 'Orador Audaz'; }

            avaliacaoIA.cristal = cristalCalculado;
            avaliacaoIA.titulo = tituloCalculado;
            avaliacaoIA.id = jogadorReal.id;
            jogadoresCorrigidosParaFrontend.push(avaliacaoIA);

            // 🚀 PROTEÇÃO DE CRISTAIS: Se for um treino Solo ou se for a IA, NÃO atualiza a Base de Dados!
            if (!isSolo && jogadorReal.id !== 'ia_groq') {
                const idsParaAtualizar = [jogadorReal.id];
                if (alunoRef) idsParaAtualizar.push(alunoRef);

                const updateQuery = { $inc: { 'arenaStats.duelosConcluidos': 1 },$set: { 'arenaStats.cristalAtual': cristalCalculado, 'arenaStats.tituloAtual': tituloCalculado } };
                
                await db.collection('usuarios').updateMany({ $or: [ { id: { $in: idsParaAtualizar } }, { alunoRefId: {$in: idsParaAtualizar } } ] }, updateQuery);
                await db.collection('alunos').updateMany({ id: { $in: idsParaAtualizar } }, updateQuery);
            }
        } // <--- 🚨 A CHAVETA MÁGICA QUE SALVA O SERVIDOR ESTÁ AQUI! Fecha o loop "for (const jogadorReal of jogadoresReais)"

        resultadoAvaliacao.jogadores = jogadoresCorrigidosParaFrontend;
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } });

     if (global.workspaceStream) {
            const nomesTodos = jogadoresReais.map(j => j.nome).filter(Boolean);
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_RESULTADO_FINAL', salaId: salaId, resultado: resultadoAvaliacao,
                destinatarios: nomesTodos, escolaId: escolaId || 'DEFAULT'
            });
        }
        res.status(200).json({ success: true, resultado: resultadoAvaliacao });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao avaliar a Arena.' }); 
    }
});

router.get('/historico/:alunoId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const historico = await db.collection('workspace_arenas').find({
            status: 'finalizado', $or: [{ 'jogador1.id': req.params.alunoId }, { 'jogador2.id': req.params.alunoId }]
        }).sort({ dataFim: -1 }).limit(20).toArray();
        res.status(200).json({ success: true, historico });
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar histórico de batalhas.' }); }
});

// ============================================================================
// 🎭 FASE 4: ÁRBITRO DE PERSONAGENS (APERTO DE MÃO DUPLO E INTELIGÊNCIA ARTIFICIAL)
// ============================================================================
router.post('/:salaId/escolher-papel', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const { alunoId, papelEscolhido, papelRestante } = req.body;
        const db = await connectDB();
        
        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        const isJogador1 = sala.jogador1.id === alunoId;

        // 1. Grava a escolha do aluno APENAS para ele próprio
        let updateDoc = { $set: { papeisDefinidos: true } }; 
        updateDoc.$set[isJogador1 ? 'jogador1.papel' : 'jogador2.papel'] = papelEscolhido;

        // 🚀 MODO SOLO: Apenas se for contra a IA é que o servidor atribui o papel restante imediatamente
        if (sala.tipo === 'solo') {
            updateDoc.$set[isJogador1 ? 'jogador2.papel' : 'jogador1.papel'] = papelRestante;
        }

        await db.collection('workspace_arenas').updateOne({ id: salaId }, updateDoc);

        // 2. Verifica se agora AMBOS os jogadores já têm papel
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        const j1Pronto = !!salaAtualizada.jogador1.papel;
        const j2Pronto = !!salaAtualizada.jogador2.papel;

        if (j1Pronto && j2Pronto) {
            // 🎯 TIRO DE PARTIDA! Ambos escolheram. O Servidor liberta a Arena.
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_TODOS_PRONTOS',
                    salaId: salaId,
                    escolaId: req.usuario?.escolaId || 'DEFAULT'
                });
            }
        } else {
            // 🛑 APENAS UM ESCOLHEU! Avisa a rede para pintar de cinzento esse botão no ecrã do oponente
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_PAPEL_BLOQUEADO',
                    salaId: salaId,
                    papelBloqueado: papelEscolhido,
                    escolaId: req.usuario?.escolaId || 'DEFAULT'
                });
            }
        }

        res.status(200).json({ success: true, papel: papelEscolhido });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar escolha de papel.' });
    }
});

// ============================================================================
// 🌍 O TRADUTOR MÁGICO DA ARENA (SMART TOUCH)
// ============================================================================
router.post('/traduzir', verificarToken, async (req, res) => {
    try {
        const { texto } = req.body;
        if (!texto) return res.status(400).json({ error: 'Texto não fornecido.' });

        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });

        const promptIA = `
        Aja como um dicionário e guia de pronúncia de inglês para falantes de português (Portugal e Brasil).
        Analise o seguinte texto selecionado pelo aluno na Arena (pode ser uma palavra ou uma frase inteira): "${texto}"
        
        Sua missão:
        1. "traducao": Forneça a melhor tradução direta para o português, considerando o contexto.
        2. "pronuncia": Escreva como o aluno deve LER essa palavra/frase em português para soar como um nativo de inglês (exemplo: para "apple", escreva "é-pôl").

        Retorne APENAS um objeto JSON estrito com esta estrutura, sem aspas adicionais ou formatação extra:
        {
            "traducao": "Sua tradução aqui",
            "pronuncia": "A pronúncia figurada aqui"
        }
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.1, // Temperatura baixa porque queremos fatos exatos, não criatividade
            response_format: { type: 'json_object' }
        });

        const resposta = JSON.parse(completion.choices[0].message.content.trim());
        res.status(200).json({ success: true, ...resposta });

    } catch (error) {
        console.error("Erro no Tradutor da Arena:", error);
        res.status(500).json({ error: 'Falha ao comunicar com a IA de tradução.' });
    }
});

// ============================================================================
// 🏃💨 SISTEMA DE FUGA (DESISTÊNCIA)
// ============================================================================
router.post('/:salaId/abandonar', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const { alunoNome, escolaId } = req.body;
        const db = await connectDB();

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        
        // Se a sala já não existir ou já estiver terminada, não fazemos nada
        if (!sala || sala.status === 'finalizado' || sala.status === 'cancelado') {
            return res.status(200).json({ success: true });
        }

        // 1. Marca a sala como cancelada na base de dados
        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { status: 'cancelado', motivoFinalizacao: `Fuga de ${alunoNome}` } }
        );

        // 2. Avisa o jogador que ficou na sala através do WebSocket
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_OPONENTE_FUGIU',
                salaId: salaId,
                fugitivoNome: alunoNome,
                escolaId: escolaId || 'DEFAULT'
            });
        }
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar abandono.' });
    }
});

// ============================================================================
// 🧰 CAIXA NEGRA: RECUPERAÇÃO DE ESTADO APÓS QUEDA DE REDE OU F5
// ============================================================================
router.get('/:salaId/estado', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        const sala = await db.collection('workspace_arenas').findOne({ id: req.params.salaId });
        
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });
        
        res.json({ success: true, sala });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar a Caixa Negra da Arena.' });
    }
});

// ============================================================================
// 🎙️ TRANSCRIÇÃO EM NUVEM (GROQ WHISPER) - FALLBACK ANTI-BLOQUEIO DE CHAMADA
// ============================================================================
router.post('/transcrever-audio', verificarToken, async (req, res) => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    let tempFilePath = null;

    try {
        const { audioBase64, mimeType } = req.body || {};
        if (!audioBase64) {
            return res.status(400).json({ success: false, error: 'Áudio vazio.' });
        }

        const chaveApi = process.env.GROQ_API_KEY;
        if (!chaveApi) {
            return res.status(500).json({ success: false, error: 'Chave API da Groq em falta.' });
        }

        // Remove o cabeçalho data:audio/...;base64, e grava num ficheiro temporário leve
        const base64Limpo = String(audioBase64).replace(/^data:[^;]+;base64,/, '');
        const buffer = Buffer.from(base64Limpo, 'base64');
        if (buffer.length < 200) {
            return res.status(400).json({ success: false, error: 'Áudio demasiado curto.' });
        }

        const extensao = (mimeType && mimeType.includes('mp4')) ? 'm4a' : (mimeType && mimeType.includes('ogg') ? 'ogg' : 'webm');
        tempFilePath = path.join(os.tmpdir(), `arena_voice_${Date.now()}_${Math.random().toString(36).substring(7)}.${extensao}`);
        fs.writeFileSync(tempFilePath, buffer);

        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: chaveApi.trim() });

        // 1. Transcreve o áudio em Inglês usando o motor ultrarrápido Whisper da Groq
        const transcricao = await groq.audio.transcriptions.create({
            file: fs.createReadStream(tempFilePath),
            model: 'whisper-large-v3-turbo',
            language: 'en',
            response_format: 'json',
            temperature: 0.0
        });

        const textoCru = (transcricao && transcricao.text) ? String(transcricao.text).trim() : '';
        if (!textoCru) {
            return res.status(200).json({ success: false, error: 'Não foi possível ouvir a fala.' });
        }

        res.status(200).json({ success: true, textoTranscrito: textoCru });
    } catch (error) {
        console.error('🚨 Erro na transcrição Whisper da Arena:', error);
        res.status(500).json({ success: false, error: 'Falha ao processar o áudio na nuvem.' });
    } finally {
        if (tempFilePath && fs.existsSync(tempFilePath)) {
            try { fs.unlinkSync(tempFilePath); } catch (e) {}
        }
    }
});

module.exports = router;