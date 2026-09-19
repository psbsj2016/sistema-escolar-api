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

// 🚀 LISTA DE CENÁRIOS ÉPICOS DE ROLEPLAY
const CENARIOS_ARENA = [
    "You are at a restaurant and the food is cold. One is the unhappy customer, the other is the waiter.",
    "You are at the airport and lost your luggage. One is the frustrated traveler, the other is the ground staff.",
    "You are roommates arguing about who should clean the apartment today.",
    "Job Interview: One is the strict boss, the other is the nervous candidate.",
    "Planning a trip: Two friends disagree on whether to go to the beach or the mountains."
];

const sortearCenario = () => CENARIOS_ARENA[Math.floor(Math.random() * CENARIOS_ARENA.length)];

// ============================================================================
// ⚔️ VIA RÁPIDA DA ARENA (MATCHMAKING DO FEED - 10 MINUTOS)
// ============================================================================

router.post('/desafio-direto', verificarToken, async (req, res) => {
    try {
        const { desafiadoNome, desafianteNome, escolaId, minutos, postId } = req.body;
        const desafianteId = req.usuario?.id || req.body.alunoId; 
        const db = await connectDB();

        // 🛡️ ESCUDO INTELIGENTE: Ignora batalhas fantasmas cujo tempo já expirou!
        const arenasAtivas = await db.collection('workspace_arenas').find({
            status: 'em_curso',
            $or: [
                { 'jogador1.nome': desafiadoNome },
                { 'jogador2.nome': desafiadoNome },
                { 'jogador1.nome': desafianteNome },
                { 'jogador2.nome': desafianteNome }
            ]
        }).toArray();

        const agora = new Date().getTime();
        const jogadorOcupado = arenasAtivas.some(arena => {
            if (!arena.iniciadoEm) return false;
            const inicio = new Date(arena.iniciadoEm).getTime();
            const limiteMs = (arena.limiteMinutos || 10) * 60000;
            return (agora - inicio) < (limiteMs + 60000); // 1 min de tolerância após o tempo oficial
        });

        if (jogadorOcupado) {
            return res.status(400).json({ error: 'Um dos guerreiros já está a travar uma batalha ao vivo. Aguarde!' });
        }

        const salaId = 'duelo-feed-' + Date.now();

        const novaSala = {
            id: salaId,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'desafio_feed',
            status: 'aguardando',
            jogador1: { id: desafianteId, nome: desafianteNome }, 
            jogador2: { id: null, nome: desafiadoNome },  
            limiteMinutos: parseInt(minutos) || 10,
            criadoEm: new Date().toISOString(),
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_DESAFIO_DIRETO',
                destinatarios: [desafiadoNome],
                desafianteNome: desafianteNome,
                salaId: salaId,
                minutos: minutos,
                postId: postId, 
                escolaId: escolaId || 'DEFAULT'
            });
        }
        res.status(200).json({ success: true, salaId });
    } catch (error) { res.status(500).json({ error: 'Erro ao enviar desafio direto.' }); }
});

router.post('/desafio-direto/aceitar', verificarToken, async (req, res) => {
    try {
        const { salaId, desafiadoNome, desafianteNome, escolaId, minutos } = req.body;
        const db = await connectDB();

        const userDesafiado = await db.collection('usuarios').findOne({ $or: [{nome: desafiadoNome}, {login: desafiadoNome}] });
        const userDesafiante = await db.collection('usuarios').findOne({ $or: [{nome: desafianteNome}, {login: desafianteNome}] });

        const cenarioSorteado = sortearCenario();

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { 
                status: 'em_curso', 
                jogador1: { id: userDesafiante?.id || null, nome: desafianteNome },
                jogador2: { id: userDesafiado?.id || null, nome: desafiadoNome },
                iniciadoEm: new Date().toISOString(),
                cenario: "🔥 DUELO RÁPIDO DO FEED 🔥\n" + cenarioSorteado
            }}
        );

        // 🚪 PORTA IMORTAL: O Post de desafio no Feed NÃO é apagado.

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                destinatarios: [desafiadoNome, desafianteNome],
                destinatariosIds: [userDesafiante?.id, userDesafiado?.id], // A BLINDAGEM INFALÍVEL
                salaId: salaId,
                limiteMinutos: minutos,
                cenario: "🔥 DUELO RÁPIDO DO FEED 🔥\n" + cenarioSorteado,
                escolaId: escolaId || 'DEFAULT'
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao aceitar desafio.' }); }
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

// 1. Rota para Procurar Duelo Aleatório
router.post('/procurar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId, limiteMinutos } = req.body;
        const db = await connectDB();
        
        const salaEspera = await db.collection('workspace_arenas').findOne({
            escolaId: escolaId, tipo: 'aleatorio', status: 'aguardando', 'jogador1.id': { $ne: alunoId }
        });

        if (salaEspera) {
            const cenarioSorteado = sortearCenario();

            await db.collection('workspace_arenas').updateOne(
                { id: salaEspera.id },
                { $set: { 
                    status: 'em_curso', 
                    jogador2: { id: alunoId, nome: alunoNome },
                    iniciadoEm: new Date().toISOString(),
                    cenario: cenarioSorteado
                }}
            );

            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_MATCH_ENCONTRADO',
                    salaId: salaEspera.id,
                    destinatarios: [salaEspera.jogador1.nome, alunoNome],
                    destinatariosIds: [salaEspera.jogador1.id, alunoId], // BLINDAGEM
                    escolaId: escolaId,
                    limiteMinutos: salaEspera.limiteMinutos,
                    cenario: cenarioSorteado 
                });
            }
            return res.status(200).json({ success: true, salaId: salaEspera.id, mensagem: 'Oponente encontrado!' });
        } else {
            const novaSala = {
                id: crypto.randomUUID(), escolaId: escolaId, tipo: 'aleatorio', status: 'aguardando',
                jogador1: { id: alunoId, nome: alunoNome }, jogador2: null,
                limiteMinutos: parseInt(limiteMinutos) || 50, criadoEm: new Date().toISOString()
            };
            await db.collection('workspace_arenas').insertOne(novaSala);
            return res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'A aguardar oponente...' });
        }
    } catch (error) { res.status(500).json({ error: 'Erro ao aceder à Arena.' }); }
});

// 2. Rota para Convidar um Colega Específico (Blindada)
router.post('/convidar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, colegaNome, escolaId, limiteMinutos } = req.body;
        const db = await connectDB();

        const userAlvo = await db.collection('usuarios').findOne({
            $or: [
                { nome: new RegExp(`^${colegaNome.trim()}$`, 'i') },
                { login: new RegExp(`^${colegaNome.trim()}$`, 'i') }
            ]
        });

        if (!userAlvo) return res.status(404).json({ error: 'Guerreiro não encontrado! Selecione o nome na lista.' });

        const nomeColegaReal = userAlvo.nome || userAlvo.login;

        const novaSala = {
            id: crypto.randomUUID(), escolaId: escolaId, tipo: 'convite', status: 'aguardando',
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: userAlvo.id, nome: nomeColegaReal },
            limiteMinutos: parseInt(limiteMinutos) || 50, criadoEm: new Date().toISOString()
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_RECEBIDO',
                salaId: novaSala.id,
                remetenteNome: alunoNome,
                destinatarios: [nomeColegaReal],
                destinatariosIds: [userAlvo.id], // BLINDAGEM
                escolaId: escolaId,
                limiteMinutos: novaSala.limiteMinutos
            });
        }
        res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'Convite enviado!' });
    } catch (error) { res.status(500).json({ error: 'Erro ao enviar convite.' }); }
});

// Quando o convidado aceita
router.post('/:salaId/aceitar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        const cenarioSorteado = sortearCenario();

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { 
                status: 'em_curso', 'jogador2.id': alunoId, 'jogador2.nome': alunoNome, 
                iniciadoEm: new Date().toISOString(), cenario: cenarioSorteado
            } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                salaId: salaId,
                destinatarios: [sala.jogador1.nome, alunoNome],
                destinatariosIds: [sala.jogador1.id, alunoId], // A CURA DOS EVENTOS FANTASMAS!
                escolaId: escolaId,
                limiteMinutos: sala.limiteMinutos,
                cenario: cenarioSorteado
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao aceitar convite.' }); }
});

// ============================================================================
// 🚀 O CÉREBRO DO MESTRE DA GUILDA E DOS PLOT TWISTS (CORRIGIDO PARA GROQ-SDK)
// ============================================================================
async function gerarDicaDoMestre(sala, escolaId) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        let dialogo = '';
        const ultimasMensagens = sala.historico.slice(-10);
        ultimasMensagens.forEach(fala => { dialogo += `[${fala.autorNome}]: ${fala.texto}\n`; });

        const promptIA = `
        Aja como o "Mestre da Guilda", um sábio professor nativo de inglês observando dois alunos a praticarem num Roleplay.
        Cenário atual deles: "${sala.cenario || 'Conversa livre'}".
        
        Aqui estão as últimas 10 mensagens:
        ${dialogo}
        
        Sua missão: Escreva UMA DICA RÁPIDA E AMIGÁVEL (máximo de 2 frases) para eles.
        IMPORTANTE: Responda APENAS com a frase da dica, sem aspas, sem introduções e sem JSON. Misture português com inglês.
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.5
        });

        const dica = completion.choices[0].message.content.trim();

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_DICA_MESTRE', salaId: sala.id, dica: dica, escolaId: escolaId || 'DEFAULT'
            });
        }
    } catch (error) { console.error("Erro na Dica do Mestre:", error); }
}

async function gerarPlotTwist(sala, escolaId) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const promptIA = `
        Atue como o Mestre da Guilda num jogo de Roleplay (simulação) em inglês.
        O cenário original dos alunos é: "${sala.cenario || 'Conversa livre'}".
        
        Sua missão: Inventar um "Plot Twist" (uma reviravolta inesperada, dramática ou engraçada) que acabou de acontecer neste cenário para forçar os alunos a mudarem o rumo da conversa.
        
        Regras:
        1. Escreva apenas UMA frase curta e impactante.
        2. Comece com um aviso em português e descreva o novo desafio em inglês.
        Exemplo: "🚨 Atenção! The restaurant just caught on fire! You need to escape immediately!"
        Não use aspas e vá direto ao assunto. Seja muito criativo!
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.8
        });

        const twist = completion.choices[0].message.content.trim();

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_PLOT_TWIST', salaId: sala.id, twist: twist, escolaId: escolaId || 'DEFAULT'
            });
        }
    } catch (error) { console.error("Erro no Plot Twist:", error); }
}

// 3. Rota para Receber a Voz e Disparar a IA (COM MATEMÁTICA PERFEITA)
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId, combo } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();
        
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, combo, data: new Date().toISOString() };
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        
        // 🚀 A MATEMÁTICA ESTRATÉGICA DOS PLOT TWISTS!
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        
        if (salaAtualizada && salaAtualizada.historico) {
            const hist = salaAtualizada.historico;
            const total = hist.length;
            
            // Conta quantas vezes cada jogador falou
            const falasJ1 = hist.filter(h => h.autorId === salaAtualizada.jogador1.id).length;
            const falasJ2 = hist.filter(h => h.autorId === salaAtualizada.jogador2?.id).length;

            // Condição infalível: Se AMBOS já falaram pelo menos 3 vezes e a soma total é um múltiplo de 3 (6, 9, 12, 15...)
            if (falasJ1 >= 3 && falasJ2 >= 3 && total % 3 === 0) {
                gerarPlotTwist(salaAtualizada, escolaId);
            } 
            else if (total > 0 && total % 10 === 0) {
                gerarDicaDoMestre(salaAtualizada, escolaId);
            }
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'ARENA_NOVA_FALA', salaId: salaId, fala: novaFala, escolaId: escolaId || 'DEFAULT' });
        }
        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar a fala.' }); }
});

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

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala || sala.status === 'finalizado') return res.status(400).json({ error: 'Sala inválida ou já avaliada.' });

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

        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }], model: 'llama3-70b-8192', temperature: 0.2, response_format: { type: 'json_object' }
        });

        let resultadoAvaliacao = {};
        try { resultadoAvaliacao = JSON.parse(completion.choices[0].message.content); } 
        catch (e) { resultadoAvaliacao = { vencedor: "Empate", feedbackGeral: "Ótimo treino!", jogadores: [] }; }

        const jogadoresReais = [sala.jogador1, sala.jogador2].filter(j => j && j.id);
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

            const idsParaAtualizar = [jogadorReal.id];
            if (alunoRef) idsParaAtualizar.push(alunoRef);

            const updateQuery = { $inc: { 'arenaStats.duelosConcluidos': 1 },$set: { 'arenaStats.cristalAtual': cristalCalculado, 'arenaStats.tituloAtual': tituloCalculado } };
            
            await db.collection('usuarios').updateMany({ $or: [ { id: { $in: idsParaAtualizar } }, { alunoRefId: {$in: idsParaAtualizar } } ] }, updateQuery);
            await db.collection('alunos').updateMany({ id: { $in: idsParaAtualizar } }, updateQuery);
        }

        resultadoAvaliacao.jogadores = jogadoresCorrigidosParaFrontend;
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } });

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_RESULTADO_FINAL', salaId: salaId, resultado: resultadoAvaliacao,
                destinatarios: [sala.jogador1.nome, sala.jogador2?.nome].filter(Boolean), escolaId: escolaId
            });
        }
        res.status(200).json({ success: true, resultado: resultadoAvaliacao });
    } catch (error) { res.status(500).json({ error: 'Erro ao avaliar a Arena.' }); }
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

module.exports = router;