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
        const { alunoId, alunoNome, escolaId } = req.body;
        const db = await connectDB();
        
        // Procura se já existe alguma sala aleatória à espera de jogador na mesma escola
        const salaEspera = await db.collection('workspace_arenas').findOne({
            escolaId: escolaId,
            tipo: 'aleatorio',
            status: 'aguardando',
            'jogador1.id': { $ne: alunoId } // Não pode jogar contra si mesmo
        });

        if (salaEspera) {
            // MATCH ENCONTRADO! Junta o jogador 2 à sala
            await db.collection('workspace_arenas').updateOne(
                { id: salaEspera.id },
                { $set: { 
                    status: 'em_curso', 
                    jogador2: { id: alunoId, nome: alunoNome },
                    iniciadoEm: new Date().toISOString(),
                    limiteMinutos: 50 // Duração máxima definida
                }}
            );

            // Avisa ambos os jogadores em tempo real (SSE)
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'ARENA_MATCH_ENCONTRADO',
                    salaId: salaEspera.id,
                    destinatarios: [salaEspera.jogador1.nome, alunoNome],
                    escolaId: escolaId
                });
            }
            return res.status(200).json({ success: true, salaId: salaEspera.id, mensagem: 'Oponente encontrado!' });
        } else {
            // NINGUÉM À ESPERA: Cria uma nova sala e fica a aguardar
            const novaSala = {
                id: crypto.randomUUID(),
                escolaId: escolaId,
                tipo: 'aleatorio',
                status: 'aguardando',
                jogador1: { id: alunoId, nome: alunoNome },
                jogador2: null,
                criadoEm: new Date().toISOString()
            };
            await db.collection('workspace_arenas').insertOne(novaSala);
            return res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'A aguardar oponente...' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erro ao aceder à Arena.' });
    }
});

// 2. Rota para Convidar um Colega Específico
router.post('/convidar', verificarToken, async (req, res) => {
    try {
        const { alunoId, alunoNome, colegaNome, escolaId } = req.body;
        const db = await connectDB();

        const novaSala = {
            id: crypto.randomUUID(),
            escolaId: escolaId,
            tipo: 'convite',
            status: 'aguardando',
            jogador1: { id: alunoId, nome: alunoNome },
            jogador2: { id: null, nome: colegaNome }, // Guarda quem foi convidado
            criadoEm: new Date().toISOString()
        };

        await db.collection('workspace_arenas').insertOne(novaSala);

        // Dispara o convite em tempo real para a tela do colega
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_CONVITE_RECEBIDO',
                salaId: novaSala.id,
                remetenteNome: alunoNome,
                destinatarios: [colegaNome],
                escolaId: escolaId
            });
        }

        res.status(201).json({ success: true, salaId: novaSala.id, mensagem: 'Convite enviado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao enviar convite.' });
    }
});

// 3. Rota para Receber a Voz (Transcrita) e Enviar ao Oponente em Tempo Real
router.post('/:salaId/falar', verificarToken, async (req, res) => {
    try {
        const { texto, autorId, autorNome, escolaId } = req.body;
        const salaId = req.params.salaId;
        const db = await connectDB();

        // Documenta a fala com um ID único e a data exata
        const novaFala = {
            id: crypto.randomUUID(),
            autorId,
            autorNome,
            texto,
            data: new Date().toISOString()
        };

        // Guarda a fala no histórico da Arena na Base de Dados
        await db.collection('workspace_arenas').updateOne(
            { id: salaId },
            { $push: { historico: novaFala } }
        );

        // Grita pelo túnel SSE para que o ecrã do oponente seja atualizado instantaneamente
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', {
                type: 'ARENA_NOVA_FALA',
                salaId: salaId,
                fala: novaFala,
                escolaId: escolaId || 'DEFAULT'
            });
        }

        res.status(200).json({ success: true, fala: novaFala });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao processar e transmitir a fala.' });
    }
});

module.exports = router;