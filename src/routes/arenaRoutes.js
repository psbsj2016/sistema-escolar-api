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

// Função utilitária para sortear um cenário
const sortearCenario = () => CENARIOS_ARENA[Math.floor(Math.random() * CENARIOS_ARENA.length)];

// ============================================================================
// ⚔️ VIA RÁPIDA DA ARENA (MATCHMAKING DO FEED - 10 MINUTOS)
// IMPORTANTE: Fica acima de /:salaId para que o servidor a leia primeiro!
// ============================================================================

router.post('/desafio-direto', verificarToken, async (req, res) => {
    try {
        const { desafiadoNome, desafianteNome, escolaId, minutos } = req.body;
        const salaId = 'duelo-feed-' + Date.now();
        const db = await connectDB();

        // 🚀 CRIA A SALA OFICIALMENTE NA BD (O Palco para a IA avaliar depois)
        const novaSala = {
            id: salaId,
            escolaId: escolaId || 'DEFAULT',
            tipo: 'desafio_feed',
            status: 'aguardando',
            jogador1: { id: null, nome: desafianteNome }, // O desafiante
            jogador2: { id: null, nome: desafiadoNome },  // O dono do post (desafiado)
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

        // 🚀 INTELIGÊNCIA: Busca os IDs verdadeiros pelo nome para o algoritmo dar os Cristais corretamente no final!
        const userDesafiado = await db.collection('usuarios').findOne({ $or: [{nome: desafiadoNome}, {login: desafiadoNome}] });
        const userDesafiante = await db.collection('usuarios').findOne({ $or: [{nome: desafianteNome}, {login: desafianteNome}] });

        const cenarioSorteado = sortearCenario();

        // Atualiza a sala como 'em_curso' e regista oficialmente a batalha
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

        // 🚀 O GRANDE PUXÃO: Este é o sinal que suga os dois alunos para a tela preta instantaneamente!
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                destinatarios: [desafiadoNome, desafianteNome],
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
            const cenarioSorteado = sortearCenario(); // 🚀 Sorteia a missão!

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
                    escolaId: escolaId,
                    limiteMinutos: salaEspera.limiteMinutos,
                    cenario: cenarioSorteado // 🚀 Envia a missão para a tela
                });
            }
            return res.status(200).json({ success: true, salaId: salaEspera.id, mensagem: 'Oponente encontrado!' });
        } else {
            const novaSala = {
                id: crypto.randomUUID(),
                escolaId: escolaId,
                tipo: 'aleatorio',
                status: 'aguardando',
                jogador1: { id: alunoId, nome: alunoNome },
                jogador2: null,
                limiteMinutos: parseInt(limiteMinutos) || 50,
                criadoEm: new Date().toISOString()
            };
            await db.collection('workspace_arenas').insertOne(novaSala);
            return res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'A aguardar oponente...' });
        }
    } catch (error) { res.status(500).json({ error: 'Erro ao aceder à Arena.' }); }
});

// 2. Rota para Convidar um Colega Específico
router.post('/convidar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, colegaNome, escolaId, limiteMinutos } = req.body;
        const db = await connectDB();

        const novaSala = {
            id: crypto.randomUUID(),
            escolaId: escolaId,
            tipo: 'convite',
            status: 'aguardando',
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: null, nome: colegaNome },
            limiteMinutos: parseInt(limiteMinutos) || 50,
            criadoEm: new Date().toISOString()
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_RECEBIDO',
                salaId: novaSala.id,
                remetenteNome: alunoNome,
                destinatarios: [colegaNome],
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

        const cenarioSorteado = sortearCenario(); // 🚀 Sorteia a missão também nos convites!

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { 
                status: 'em_curso', 
                'jogador2.id': alunoId, 
                'jogador2.nome': alunoNome, 
                iniciadoEm: new Date().toISOString(),
                cenario: cenarioSorteado
            } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                salaId: salaId,
                destinatarios: [sala.jogador1.nome, alunoNome],
                escolaId: escolaId,
                limiteMinutos: sala.limiteMinutos,
                cenario: cenarioSorteado
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao aceitar convite.' }); }
});

// ============================================================================
// 🚀 O CÉREBRO DO MESTRE DA GUILDA (IA em Tempo Real)
// ============================================================================
async function gerarDicaDoMestre(sala, escolaId) {
    try {
        let dialogo = '';
        // Pega apenas nas últimas 10 mensagens para dar contexto focado à IA
        const ultimasMensagens = sala.historico.slice(-10);
        ultimasMensagens.forEach(fala => {
            dialogo += `[${fala.autorNome}]: ${fala.texto}\n`;
        });

        const promptIA = `
        Aja como o "Mestre da Guilda", um sábio professor nativo de inglês observando dois alunos a praticarem num Roleplay.
        Cenário atual deles: "${sala.cenario || 'Conversa livre'}".
        
        Aqui estão as últimas 10 mensagens do diálogo:
        ${dialogo}
        
        Sua missão: Escreva UMA DICA RÁPIDA E AMIGÁVEL (máximo de 2 frases) para eles.
        Pode ser a correção de um erro gramatical comum que notou no diálogo, a sugestão de um vocabulário mais nativo, ou um elogio à fluência deles.
        Responda de forma direta e inspiradora. Seja o mentor.
        IMPORTANTE: Responda APENAS com a frase da dica, sem aspas, sem introduções e sem JSON. Misture português com inglês.
        `;

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ model: 'llama3-70b-8192', messages: [{ role: 'user', content: promptIA }], temperature: 0.5 })
        });

        const groqData = await groqRes.json();
        const dica = groqData.choices[0].message.content.trim();

        // Transmite a Dica Mágica para os alunos pelo túnel SSE em Tempo Real
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_DICA_MESTRE',
                salaId: sala.id,
                dica: dica,
                escolaId: escolaId || 'DEFAULT'
            });
        }
    } catch (error) {
        console.error("Erro na Intervenção Divina do Mestre:", error);
    }
}

// 3. Rota para Receber a Voz e Disparar a IA
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId, combo } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();
        
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, combo, data: new Date().toISOString() };
        
        // Grava a mensagem na base de dados
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        
        // 🚀 INTERVENÇÃO DIVINA: Verifica se chegamos a um múltiplo de 10 mensagens!
        const salaAtualizada = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (salaAtualizada && salaAtualizada.historico && salaAtualizada.historico.length % 10 === 0) {
            // Dispara a IA em segundo plano (não trava o chat dos alunos!)
            gerarDicaDoMestre(salaAtualizada, escolaId);
        }

        // Avisa imediatamente o colega que há uma nova mensagem
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'ARENA_NOVA_FALA', salaId: salaId, fala: novaFala, escolaId: escolaId || 'DEFAULT' });
        }
        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar a fala.' }); }
});

// ============================================================================
// 🚑 SALVA-VIDAS DA IA: Feedback de Emergência (Se a formatação do JSON falhar)
// ============================================================================
async function gerarFeedbackEmergencia(dialogo, nomeJogador) {
    try {
        const Groq = require('groq-sdk');
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY.trim() });
        const prompt = `Atue como um professor de inglês. Leia este diálogo:\n\n${dialogo}\n\nO aluno "${nomeJogador}" participou. Escreva UMA ÚNICA FRASE curta em português dando uma dica gramatical útil ou corrigindo um erro que ele cometeu no diálogo. Não use aspas. Seja motivador.`;
        const completion = await groq.chat.completions.create({
            messages: [{ role: 'user', content: prompt }],
            model: 'openai/gpt-oss-120b',
            temperature: 0.4
        });
        return completion.choices[0].message.content.trim();
    } catch (e) {
        return "O seu esforço foi notável! Continue a praticar para aprimorar a sua fluência.";
    }
}

// ============================================================================
// 4. Rota para Avaliar a Partida e Forjar Cristais (O ALGORITMO INFALÍVEL)
// ============================================================================
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

        // 🚀 PROMPT SIMPLIFICADO: A IA só precisa de focar-se nos Nomes e Cristais!
        const promptIA = `
        Aja como um professor nativo de inglês avaliando um "Roleplay" (duelo de fluência).
        Cenário encenado: "${sala.cenario || 'Conversa livre'}"
        
        Níveis de Evolução:
        1. "Safira" (Título: Orador Audaz)
        2. "Ametista" (Título: Mestre do Diálogo)
        3. "Rubi" (Título: Embaixador da Fluência)
        4. "Diamante Estelar" (Título: Lenda Nativa)

        Jogadores:
        - ${sala.jogador1.nome}
        - ${sala.jogador2 ? sala.jogador2.nome : 'Nenhum'}
        
        Diálogo:
        ${dialogo}

        Retorne APENAS um objeto JSON válido, avaliando APENAS os nomes listados acima.
        {
            "vencedor": "Nome do vencedor ou Empate",
            "feedbackGeral": "Comentário sobre o duelo",
            "jogadores": [
                { "nome": "Nome Aluno 1", "cristal": "Safira", "titulo": "Orador Audaz", "feedback": "Correção curta" }
            ]
        }
        `;

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                model: 'llama3-70b-8192', 
                messages: [{ role: 'user', content: promptIA }], 
                temperature: 0.2 // Mantém o rigor
            })
        });

        const groqData = await groqRes.json();
        let resultadoAvaliacao = {};
        
        try {
            let conteudoIA = groqData.choices[0].message.content;
            resultadoAvaliacao = JSON.parse(conteudoIA.replace(/```json/g, '').replace(/```/g, '').trim());
        } catch (e) {
            resultadoAvaliacao = { vencedor: "Empate", feedbackGeral: "Ótimo treino!", jogadores: [] };
        }

        // 🚀 O ALGORITMO INFALÍVEL DE RECOMPENSA COM PROGRESSÃO RPG
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

            // 🚀 MATEMÁTICA DE PROGRESSÃO: Busca o aluno no banco de dados para saber o nível dele
            const userRecord = await db.collection('usuarios').findOne({ id: jogadorReal.id });
            const alunoRef = userRecord ? userRecord.alunoRefId : null;

            // Calcula o total de duelos (os que já tinha + esta vitória)
            const duelosAtuais = (userRecord && userRecord.arenaStats && userRecord.arenaStats.duelosConcluidos) ? userRecord.arenaStats.duelosConcluidos : 0;
            const novosDuelos = duelosAtuais + 1; 

            // 🏆 O SISTEMA DE ELOS (RANKS)
            let cristalCalculado = 'Safira';
            let tituloCalculado = 'Iniciante da Arena';

            if (novosDuelos >= 30) {
                cristalCalculado = 'Diamante';
                tituloCalculado = 'Lenda Nativa';
            } else if (novosDuelos >= 15) {
                cristalCalculado = 'Rubi';
                tituloCalculado = 'Mestre do Diálogo';
            } else if (novosDuelos >= 5) {
                cristalCalculado = 'Ametista';
                tituloCalculado = 'Orador Audaz';
            }

            // Injeta o Cristal conquistado na avaliação visual do Frontend
            avaliacaoIA.cristal = cristalCalculado;
            avaliacaoIA.titulo = tituloCalculado;
            avaliacaoIA.id = jogadorReal.id;
            jogadoresCorrigidosParaFrontend.push(avaliacaoIA);

            // Prepara a atualização no Banco de Dados
            const idsParaAtualizar = [jogadorReal.id];
            if (alunoRef) idsParaAtualizar.push(alunoRef);

            const updateQuery = { 
                $inc: { 'arenaStats.duelosConcluidos': 1 },
                $set: { 'arenaStats.cristalAtual': cristalCalculado, 'arenaStats.tituloAtual': tituloCalculado }
            };
            
            // Aplica a evolução na conta do Aluno
            await db.collection('usuarios').updateMany({ $or: [ { id: { $in: idsParaAtualizar } }, { alunoRefId: { $in: idsParaAtualizar } } ] }, updateQuery);
            await db.collection('alunos').updateMany({ id: { $in: idsParaAtualizar } }, updateQuery);
        }

        // Substitui a lista de jogadores da IA pela nossa lista 100% precisa
        resultadoAvaliacao.jogadores = jogadoresCorrigidosParaFrontend;

        // Salva a sala finalizada
        await db.collection('workspace_arenas').updateOne(
            { id: salaId }, { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_RESULTADO_FINAL', salaId: salaId, resultado: resultadoAvaliacao,
                destinatarios: [sala.jogador1.nome, sala.jogador2?.nome].filter(Boolean), escolaId: escolaId
            });
        }
        res.status(200).json({ success: true, resultado: resultadoAvaliacao });
    } catch (error) { 
        console.error("Erro na Arena:", error);
        res.status(500).json({ error: 'Erro ao avaliar a Arena.' }); 
    }
});

// ============================================================================
// 5. Rota para buscar o Histórico Épico do Aluno (Fase 3)
// ============================================================================
router.get('/historico/:alunoId', verificarToken, async (req, res) => {
    try {
        const db = await connectDB();
        
        // Procura salas finalizadas onde o aluno jogou
        const historico = await db.collection('workspace_arenas')
            .find({
                status: 'finalizado',
                $or: [
                    { 'jogador1.id': req.params.alunoId },
                    { 'jogador2.id': req.params.alunoId }
                ]
            })
            .sort({ dataFim: -1 }) // Ordena do mais recente para o mais antigo
            .limit(20) // Mostra os últimos 20 duelos para não sobrecarregar
            .toArray();
        
        res.status(200).json({ success: true, historico });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar histórico de batalhas.' });
    }
});

module.exports = router;