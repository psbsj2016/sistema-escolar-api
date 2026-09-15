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

// 3. Rota para Receber a Voz 
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId, combo } = req.body; // 🚀 Recebe a informação do Combo
        const salaId = req.params.salaId;
        const db = await connectDB();
        
        // Guarda a informação de combo no histórico
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, combo, data: new Date().toISOString() };
        
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'ARENA_NOVA_FALA', salaId: salaId, fala: novaFala, escolaId: escolaId || 'DEFAULT' });
        }
        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar a fala.' }); }
});

// 4. Rota para Avaliar a Partida e Forjar Cristais
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
                // 🚀 Inclui a métrica do Combo para a IA ler!
                let comboStr = (fala.combo && fala.combo > 0) ? ` (Speed Combo 🔥x${fala.combo})` : '';
                dialogo += `[${fala.autorNome}]${comboStr}: ${fala.texto}\n`; 
            });
        } else {
            dialogo = "(Os alunos permaneceram em silêncio.)";
        }

        const promptIA = `
        Aja como um professor nativo de inglês. Dois alunos participaram num "Roleplay" (duelo de fluência).
        Cenário encenado: "${sala.cenario || 'Conversa livre'}"
        
        Avalie o diálogo e atribua um Cristal de Evolução a CADA aluno baseado no seu esforço e gramática.
        NOTA: Se um aluno tiver o aviso "(Speed Combo 🔥xN)" significa que ele respondeu em poucos segundos! Elogie muito a sua fluência de raciocínio.
        
        Níveis de Evolução (Do menor para o maior):
        1. "Safira" (Título: Orador Audaz) - Nível Básico/Bom.
        2. "Ametista" (Título: Mestre do Diálogo) - Nível Muito Bom.
        3. "Rubi" (Título: Embaixador da Fluência) - Nível Excelente.
        4. "Diamante Estelar" (Título: Lenda Nativa) - Nível Impecável.

        Identificação dos Alunos na Sala:
        - Aluno 1: ${sala.jogador1.nome} (ID_Secreto: ${sala.jogador1.id})
        - Aluno 2: ${sala.jogador2 ? sala.jogador2.nome : 'Nenhum'} (ID_Secreto: ${sala.jogador2 ? sala.jogador2.id : 'Nenhum'})
        
        Diálogo:
        ${dialogo}

        Retorne APENAS um objeto JSON válido, com esta estrutura exata:
        {
            "vencedor": "Nome do Aluno que se destacou (ou 'Empate')",
            "feedbackGeral": "Comentário vibrante sobre o duelo geral",
            "jogadores": [
                { "id": "ID_Secreto do Aluno 1", "nome": "Nome Aluno 1", "cristal": "Safira", "titulo": "Orador Audaz", "feedback": "Correção ou elogio direto" },
                { "id": "ID_Secreto do Aluno 2", "nome": "Nome Aluno 2", "cristal": "Ametista", "titulo": "Mestre do Diálogo", "feedback": "Correção ou elogio direto" }
            ]
        }
        Nunca retorne texto fora do JSON.
        `;

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ model: 'llama3-70b-8192', messages: [{ role: 'user', content: promptIA }], temperature: 0.3 })
        });

        const groqData = await groqRes.json();
        let resultadoAvaliacao = {};
        
        try {
            let conteudoIA = groqData.choices[0].message.content;
            resultadoAvaliacao = JSON.parse(conteudoIA.replace(/```json/g, '').replace(/```/g, '').trim());
        } catch (e) {
            resultadoAvaliacao = { vencedor: "Empate", feedbackGeral: "Ótimo treino!", jogadores: [] };
        }

        await db.collection('workspace_arenas').updateOne(
            { id: salaId }, { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } }
        );

        if (resultadoAvaliacao.jogadores && resultadoAvaliacao.jogadores.length > 0) {
            for (const jogador of resultadoAvaliacao.jogadores) {
                if (!jogador.id || jogador.id === 'Nenhum') continue;

                const updateQuery = { 
                    $inc: { 'arenaStats.duelosConcluidos': 1 },
                    $set: { 'arenaStats.cristalAtual': jogador.cristal, 'arenaStats.tituloAtual': jogador.titulo }
                };
                
                await db.collection('usuarios').updateOne({ id: jogador.id }, updateQuery);
                await db.collection('alunos').updateOne({ id: jogador.id }, updateQuery);
            }
        }

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_RESULTADO_FINAL', salaId: salaId, resultado: resultadoAvaliacao,
                destinatarios: [sala.jogador1.nome, sala.jogador2?.nome].filter(Boolean), escolaId: escolaId
            });
        }
        res.status(200).json({ success: true, resultado: resultadoAvaliacao });
    } catch (error) { res.status(500).json({ error: 'Erro ao avaliar a Arena.' }); }
});

module.exports = router;