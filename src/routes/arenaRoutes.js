// backend/routes/arenaRoutes.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db'); // Ajuste o caminho se a sua pasta config estiver noutro local

// Middleware de Autenticação (Reaproveitado do seu sistema)
const verificarToken = async (req, res, next) => {
    const token = req.cookies?.token_acesso || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado.' });
    next();
};

// 1. Rota para Procurar Duelo Aleatório
router.post('/procurar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId, limiteMinutos } = req.body; // 🚀 Recebe o tempo
        const db = await connectDB();
        
        const salaEspera = await db.collection('workspace_arenas').findOne({
            escolaId: escolaId, tipo: 'aleatorio', status: 'aguardando', 'jogador1.id': { $ne: alunoId }
        });

        if (salaEspera) {
            await db.collection('workspace_arenas').updateOne(
                { id: salaEspera.id },
                { $set: { 
                    status: 'em_curso', 
                    jogador2: { id: alunoId, nome: alunoNome },
                    iniciadoEm: new Date().toISOString()
                    // Mantém o limite de minutos de quem criou a sala
                }}
            );

            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_MATCH_ENCONTRADO',
                    salaId: salaEspera.id,
                    destinatarios: [salaEspera.jogador1.nome, alunoNome],
                    escolaId: escolaId,
                    limiteMinutos: salaEspera.limiteMinutos // 🚀 Envia o tempo para o relógio
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
                limiteMinutos: parseInt(limiteMinutos) || 50, // 🚀 Guarda o tempo escolhido
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
            limiteMinutos: parseInt(limiteMinutos) || 50, // 🚀 Guarda o tempo
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
                limiteMinutos: novaSala.limiteMinutos // 🚀 Informa ao convidado a duração
            });
        }
        res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'Convite enviado!' });
    } catch (error) { res.status(500).json({ error: 'Erro ao enviar convite.' }); }
});

// 🚀 NOVA ROTA: Quando o convidado aceita, puxa ambos para a Arena imediatamente
router.post('/:salaId/aceitar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, escolaId } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala) return res.status(404).json({ error: 'Sala não encontrada.' });

        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { status: 'em_curso', 'jogador2.id': alunoId, 'jogador2.nome': alunoNome, iniciadoEm: new Date().toISOString() } }
        );

        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_MATCH_ENCONTRADO',
                salaId: salaId,
                destinatarios: [sala.jogador1.nome, alunoNome],
                escolaId: escolaId,
                limiteMinutos: sala.limiteMinutos
            });
        }
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao aceitar convite.' }); }
});

// 3. Rota para Receber a Voz (Mantém igual ao que já tínhamos)
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();
        const novaFala = { id: crypto.randomUUID(), autorId, autorNome, texto, data: new Date().toISOString() };
        await db.collection('workspace_arenas').updateOne({ id: salaId }, { $push: { historico: novaFala } });
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'ARENA_NOVA_FALA', salaId: salaId, fala: novaFala, escolaId: escolaId || 'DEFAULT' });
        }
        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) { res.status(500).json({ error: 'Erro ao processar a fala.' }); }
});

// 4. Rota para Avaliar a Partida e Distribuir Medalhas (Fase 3 - GROQ IA)
router.post('/:salaId/avaliar', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const db = await connectDB();
        const escolaId = req.body.escolaId || 'DEFAULT';

        // 1. Busca a sala e verifica se já foi avaliada para evitar chamadas duplas à IA
        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala || sala.status === 'finalizado') {
            return res.status(400).json({ error: 'Sala inválida ou já avaliada.' });
        }

        // 2. Prepara o guião do que foi dito para a IA ler
        let dialogo = '';
        if (sala.historico && sala.historico.length > 0) {
            sala.historico.forEach(fala => {
                dialogo += `[${fala.autorNome}]: ${fala.texto}\n`;
            });
        } else {
            dialogo = "(Os alunos permaneceram em silêncio durante a partida inteira.)";
        }

        // 3. A Instrução de Comando Perfeita (Prompt)
        const promptIA = `
        Aja como um professor nativo de inglês de elite. Dois alunos participaram num "Roleplay" (duelo de fluência).
        Analise o diálogo abaixo e atribua uma medalha (Bronze, Prata, Ouro, Diamante) baseada no esforço, gramática e argumentação.
        
        Diálogo da Arena:
        ${dialogo}

        Retorne APENAS um objeto JSON válido, com a seguinte estrutura exata:
        {
            "vencedor": "Nome do Aluno que foi melhor (ou 'Empate')",
            "medalha": "Ouro",
            "feedbackGeral": "Comentário vibrante de 2 frases sobre o desempenho da dupla",
            "correcoes": [
                { "nome": "Nome Aluno 1", "feedback": "Correção gramatical ou elogio" },
                { "nome": "Nome Aluno 2", "feedback": "Correção gramatical ou elogio" }
            ]
        }
        Nunca retorne texto fora do JSON.
        `;

        // 4. Invoca o Groq usando o Fetch nativo do Node.js
        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'llama3-70b-8192', // Ou gemma2-9b-it, conforme o que estiver a usar
                messages: [{ role: 'user', content: promptIA }],
                temperature: 0.3 // Baixa temperatura para garantir JSON perfeito
            })
        });

        const groqData = await groqRes.json();
        let resultadoAvaliacao = {};
        
        try {
            // Limpeza de segurança (caso a IA responda com marcações de código markdown)
            let conteudoIA = groqData.choices[0].message.content;
            const jsonLimpo = conteudoIA.replace(/```json/g, '').replace(/```/g, '').trim();
            resultadoAvaliacao = JSON.parse(jsonLimpo);
        } catch (e) {
            // Em caso de falha de leitura, damos um prémio de consolação seguro
            resultadoAvaliacao = {
                vencedor: "Empate", medalha: "Prata", 
                feedbackGeral: "Foi um excelente treino! A Inteligência Artificial não conseguiu processar todos os detalhes, mas ambos merecem reconhecimento.",
                correcoes: []
            };
        }

        // 5. Salva as Medalhas no DB e Tranca a Sala
        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } }
        );

        // 6. Envia o troféu para o ecrã dos dois alunos instantaneamente (SSE)
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_RESULTADO_FINAL',
                salaId: salaId,
                resultado: resultadoAvaliacao,
                destinatarios: [sala.jogador1.nome, sala.jogador2?.nome].filter(Boolean),
                escolaId: escolaId
            });
        }

        res.status(200).json({ success: true, resultado: resultadoAvaliacao });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao avaliar a Arena.' });
    }
});

module.exports = router;