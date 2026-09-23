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

// ============================================================================
// 🤖 MODO SOLO: TREINO CONTRA A IA (PvE)
// ============================================================================
router.post('/solo', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId, limiteMinutos } = req.body;
        const db = await connectDB();
        
        const salaId = 'solo-' + Date.now() + '-' + crypto.randomUUID().substring(0, 8);
        const cenarioSorteado = sortearCenario();

        const novaSala = {
            id: salaId,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'solo',
            status: 'em_curso', // Começa imediatamente!
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: 'ia_groq', nome: 'Mestre da Guilda 🤖' },
            limiteMinutos: parseInt(limiteMinutos) || 15,
            iniciadoEm: new Date().toISOString(),
            cenario: "🤖 TREINO SOLO \n" + cenarioSorteado,
            historico: []
        };

        await db.collection('workspace_arenas').insertOne(novaSala);
        
        // Devolve o sucesso imediatamente para o frontend abrir a tela
        res.status(200).json({ success: true, salaId: novaSala.id, cenario: novaSala.cenario });
    } catch (error) { 
        res.status(500).json({ error: 'Erro ao invocar a IA para treino solo.' }); 
    }
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

        // 🚀 CORREÇÃO 1: Procura de forma mais abrangente na coleção de Utilizadores
        let userAlvo = await db.collection('usuarios').findOne({
            $or: [
                { nome: new RegExp(`^${colegaNome.trim()}$`, 'i') },
                { login: new RegExp(`^${colegaNome.trim()}$`, 'i') }
            ]
        });

        // 🚀 CORREÇÃO 2: Se não achar, procura na coleção de Alunos (cobre alunos sem login ativo)
        if (!userAlvo) {
            userAlvo = await db.collection('alunos').findOne({
                $or: [
                    { nome: new RegExp(`^${colegaNome.trim()}$`, 'i') },
                    { login: new RegExp(`^${colegaNome.trim()}$`, 'i') }
                ]
            });
        }

        if (!userAlvo) return res.status(404).json({ error: 'Guerreiro não encontrado! Selecione um nome sugerido na lista.' });

        const nomeColegaReal = userAlvo.nome || userAlvo.login;

        const novaSala = {
            id: crypto.randomUUID(), escolaId: escolaId, tipo: 'convite', status: 'aguardando',
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: String(userAlvo.id), nome: nomeColegaReal },
            limiteMinutos: parseInt(limiteMinutos) || 50, criadoEm: new Date().toISOString()
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_RECEBIDO',
                salaId: novaSala.id,
                remetenteNome: alunoNome,
                destinatarios: [nomeColegaReal],
                destinatariosIds: [String(userAlvo.id)], // BLINDAGEM
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
        
        // Pega nas últimas mensagens para o Mestre entender o contexto
        sala.historico.slice(-8).forEach(fala => { 
            dialogo += `[${fala.autorNome}]: ${fala.texto}\n`; 
        });

        const promptIA = `
        Aja como o "Mestre da Guilda" (um sábio, divertido e às vezes intrometido NPC) interagindo DIRETAMENTE num Roleplay em inglês com dois alunos.
        Cenário atual deles: "${sala.cenario || 'Conversa livre'}".
        
        Diálogo até agora:
        ${dialogo}
        
        Sua missão: Entre na história como um personagem da cena ou comente a situação interagindo com eles em INGLÊS.
        Regras:
        1. Escreva APENAS a sua fala (sem o seu nome, sem aspas, sem introdução).
        2. Seja criativo! Pode ser o gerente do restaurante, um cliente chateado na mesa ao lado, um polícia, ou apenas um narrador astuto.
        3. Faça uma pergunta ou crie um pequeno obstáculo para eles resolverem.
        4. Máximo de 2 frases curtas.
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: promptIA }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.7
        });

        const falaDoMestre = completion.choices[0].message.content.trim();

        // 🚀 O SEGREDO: Salva a fala na base de dados para o Avaliador final poder ler!
        const novaFalaIA = { 
            id: crypto.randomUUID(), 
            autorId: 'mestre_guilda', 
            autorNome: '🧙‍♂️ Mestre da Guilda', 
            texto: falaDoMestre, 
            data: new Date().toISOString() 
        };

        await db.collection('workspace_arenas').updateOne({ id: sala.id }, { $push: { historico: novaFalaIA } });

        // Dispara como uma NOVA FALA normal para aparecer nos balões de chat de ambos!
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

// 3. Rota para Receber a Voz e Disparar a IA (Sem Plot Twist)
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId, combo } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();
        
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, combo, data: new Date().toISOString() };
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        
        if (salaAtualizada && salaAtualizada.historico) {
            const hist = salaAtualizada.historico;
            const total = hist.length;
            
            // 🚀 O Mestre entra na conversa a cada 6 mensagens enviadas no modo Humano vs Humano!
            if (total > 0 && total % 6 === 0 && salaAtualizada.tipo !== 'solo') {
                intervirComoMestre(salaAtualizada, escolaId);
            }
        }
        
        // GATILHO DO MODO SOLO: Se o aluno falou, a IA tem de lhe responder!
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

        const promptIA = `
        Aja estritamente como um personagem num Roleplay em inglês com um aluno.
        Cenário da cena: "${sala.cenario}".
        Você é a OUTRA pessoa na cena (ex: o empregado de mesa, o amigo, o chefe, etc).
        O aluno (${sala.jogador1.nome}) é o protagonista com quem você está a falar.
        
        Diálogo até ao momento:
        ${dialogo}
        
        Como VOCÊ (o personagem da cena) responde agora à última mensagem?
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
// 🎭 FASE 4: ÁRBITRO DE PERSONAGENS (APERTO DE MÃO DUPLO)
// ============================================================================
router.post('/:salaId/escolher-papel', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const { alunoId, papelEscolhido } = req.body;
        const db = await connectDB();
        
        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        const isJogador1 = sala.jogador1.id === alunoId;

        // 1. Grava a escolha na base de dados para o jogador específico
        const updateField = isJogador1 ? 'jogador1.papel' : 'jogador2.papel';
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $set: { [updateField]: papelEscolhido } });

        // 2. Verifica se agora AMBOS os jogadores já têm papel
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        const j1Pronto = !!salaAtualizada.jogador1.papel;
        const j2Pronto = !!salaAtualizada.jogador2.papel;

        if (j1Pronto && j2Pronto) {
            // 🎯 TIRO DE PARTIDA! Ambos escolheram.
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_TODOS_PRONTOS',
                    salaId: salaId,
                    escolaId: req.usuario?.escolaId || 'DEFAULT'
                });
            }
        } else {
            // 🛑 APENAS UM ESCOLHEU! Avisa a rede para bloquear visualmente esse botão no oponente
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

module.exports = router;