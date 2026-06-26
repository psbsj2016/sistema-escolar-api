// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();

let dbAvaliacoes = []; 
let dbEntregas = [];
let dbBancoQuestoes = []; // 🚀 O COFRE DAS QUESTÕES PERMANENTES

router.post('/', async (req, res) => {
    try {
        const { titulo, tipo, tempo, questoes, instrucoes, escolaId, autorNome, destino, destinoNome, tentativas } = req.body;
        const novaAvaliacao = {
            id: 'av_' + Date.now(), titulo, tipo, tempo: tempo || null, questoes: questoes || [], instrucoes: instrucoes || '', escolaId, autorNome, destino: destino || 'global', destinoNome: destinoNome || 'Todas as Turmas', tentativas: tentativas || 1, dataCriacao: new Date().toISOString(), ultimaAtualizacao: new Date().toISOString(), status: 'ativa'
        };
        dbAvaliacoes.push(novaAvaliacao);
        res.json({ success: true, avaliacao: novaAvaliacao });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.get('/', async (req, res) => {
    try {
        const { escolaId } = req.query;
        res.json({ success: true, avaliacoes: dbAvaliacoes.filter(p => !escolaId || p.escolaId === escolaId) });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.put('/:id', async (req, res) => {
    try {
        const temEntregas = dbEntregas.some(e => e.avaliacaoId === req.params.id);
        if (temEntregas) return res.json({ success: false, error: "Possui entregas. Não pode ser editada." });
        
        const index = dbAvaliacoes.findIndex(a => a.id === req.params.id);
        if (index === -1) return res.status(404).json({ success: false });
        dbAvaliacoes[index] = { ...dbAvaliacoes[index], ...req.body, ultimaAtualizacao: new Date().toISOString() };
        res.json({ success: true, avaliacao: dbAvaliacoes[index] });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.patch('/:id/status', async (req, res) => {
    try {
        const prova = dbAvaliacoes.find(a => a.id === req.params.id);
        if (prova) { prova.status = req.body.status; prova.ultimaAtualizacao = new Date().toISOString(); }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.delete('/:id', async (req, res) => {
    try {
        dbAvaliacoes = dbAvaliacoes.filter(a => a.id !== req.params.id);
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// ==========================================
// 🚀 ETAPA C: ROTAS DO BANCO DE QUESTÕES
// ==========================================
router.post('/banco-questoes', async (req, res) => {
    try {
        const { questao, escolaId } = req.body;
        const novaQuestaoBanco = {
            id: 'qbank_' + Date.now() + Math.floor(Math.random() * 1000),
            escolaId: escolaId || 'DEFAULT',
            tipo: questao.tipo,
            pergunta: questao.pergunta,
            opcoes: questao.opcoes || null,
            respostaCorreta: questao.respostaCorreta || null,
            dataGuardado: new Date().toISOString()
        };
        dbBancoQuestoes.push(novaQuestaoBanco);
        res.json({ success: true, questao: novaQuestaoBanco });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.get('/banco-questoes', async (req, res) => {
    try {
        const { escolaId } = req.query;
        const lista = dbBancoQuestoes.filter(q => !escolaId || q.escolaId === escolaId);
        res.json({ success: true, questoes: lista });
    } catch (error) { res.status(500).json({ success: false }); }
});
// ==========================================

router.post('/:id/iniciar', async (req, res) => {
    try {
        const { id } = req.params;
        const { alunoId, alunoNome } = req.body;
        
        const prova = dbAvaliacoes.find(a => a.id === id);
        if (!prova) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        const tentativasFeitas = dbEntregas.filter(e => e.avaliacaoId === id && e.alunoId === alunoId).length;
        
        if (tentativasFeitas >= (prova.tentativas || 1)) {
            return res.json({ success: false, error: "Limite de tentativas esgotado." });
        }

        const novaEntrega = {
            id: 'ent_' + Date.now(),
            avaliacaoId: id,
            alunoId,
            alunoNome,
            status: 'em_curso', 
            dataInicio: new Date().toISOString()
        };
        dbEntregas.push(novaEntrega);

        res.json({ success: true, entregaId: novaEntrega.id });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.post('/:id/entregar', async (req, res) => {
    try {
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, relatorioFraude, entregaId } = req.body;
        
        let entrega = dbEntregas.find(e => e.id === entregaId && e.alunoId === alunoId);
        
        if (!entrega) {
            entrega = { id: 'ent_' + Date.now(), avaliacaoId: id, alunoId, alunoNome: req.body.alunoNome };
            dbEntregas.push(entrega);
        }

        entrega.respostas = respostas || null;
        entrega.audioUrl = audioUrl || null;
        entrega.relatorioFraude = relatorioFraude || { fugas: 0, tempoFora: 0 };
        entrega.status = 'concluida';
        entrega.dataEntrega = new Date().toISOString();

        res.json({ success: true, entrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro na entrega." }); }
});

router.get('/entregas', async (req, res) => {
    try { 
        res.json({ success: true, entregas: dbEntregas.filter(e => e.status === 'concluida') });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        res.json({ success: true, entregas: dbEntregas.filter(e => e.alunoId === req.params.alunoId) });
    } catch (error) { res.status(500).json({ success: false }); }
});

module.exports = router;