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

// 4. Rota para Avaliar a Partida e Forjar Cristais (Fase 3 - GROQ IA)
router.post('/:salaId/avaliar', verificarToken, async (req, res) => {
    try {
        const salaId = req.params.salaId;
        const db = await connectDB();
        const escolaId = req.body.escolaId || 'DEFAULT';

        const sala = await db.collection('workspace_arenas').findOne({ id: salaId });
        if (!sala || sala.status === 'finalizado') return res.status(400).json({ error: 'Sala inválida ou já avaliada.' });

        let dialogo = '';
        if (sala.historico && sala.historico.length > 0) {
            sala.historico.forEach(fala => { dialogo += `[${fala.autorNome}]: ${fala.texto}\n`; });
        } else {
            dialogo = "(Os alunos permaneceram em silêncio.)";
        }

        // 🚀 O NOVO PROMPT: Avalia a evolução e forja os Cristais individualmente
        const promptIA = `
        Aja como um professor nativo de inglês. Dois alunos participaram num "Roleplay" (duelo de fluência).
        Avalie o diálogo e atribua um Cristal de Evolução a CADA aluno baseado no seu esforço e gramática.
        
        Níveis de Evolução (Do menor para o maior):
        1. "Safira" (Título: Orador Audaz) - Nível Básico/Bom.
        2. "Ametista" (Título: Mestre do Diálogo) - Nível Muito Bom.
        3. "Rubi" (Título: Embaixador da Fluência) - Nível Excelente.
        4. "Diamante Estelar" (Título: Lenda Nativa) - Nível Impecável.
        
        Diálogo:
        ${dialogo}

        Retorne APENAS um objeto JSON válido, com esta estrutura exata:
        {
            "vencedor": "Nome do Aluno que se destacou (ou 'Empate')",
            "feedbackGeral": "Comentário vibrante sobre o duelo geral",
            "jogadores": [
                { "nome": "Nome Aluno 1", "cristal": "Safira", "titulo": "Orador Audaz", "feedback": "Correção ou elogio direto" },
                { "nome": "Nome Aluno 2", "cristal": "Ametista", "titulo": "Mestre do Diálogo", "feedback": "Correção ou elogio direto" }
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

        // 🚀 Atualiza a Sala
        await db.collection('workspace_arenas').updateOne(
            { id: salaId }, { $set: { status: 'finalizado', resultado: resultadoAvaliacao, dataFim: new Date().toISOString() } }
        );

        // 🚀 EVOLUÇÃO DO ALUNO: Atualiza o Cristal no Perfil de cada participante no Banco de Dados
        if (resultadoAvaliacao.jogadores && resultadoAvaliacao.jogadores.length > 0) {
            for (const jogador of resultadoAvaliacao.jogadores) {
                // Soma +1 duelo concluído e atualiza a joia
                await db.collection('workspace_usuarios').updateOne(
                    { nome: jogador.nome }, // Procura o aluno pelo nome
                    { 
                        $inc: { 'arenaStats.duelosConcluidos': 1 },
                        $set: { 'arenaStats.cristalAtual': jogador.cristal, 'arenaStats.tituloAtual': jogador.titulo }
                    }
                );
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