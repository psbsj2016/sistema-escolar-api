// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();

let dbAvaliacoes = []; 
let dbEntregas = [];

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
        if (temEntregas) return res.status(403).json({ success: false, error: "Possui entregas. Não pode ser editada." });
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

// 🚀 1. NOVO: INICIAR AVALIAÇÃO (Consome a tentativa imediatamente)
router.post('/:id/iniciar', async (req, res) => {
    try {
        const { id } = req.params;
        const { alunoId, alunoNome } = req.body;
        
        const prova = dbAvaliacoes.find(a => a.id === id);
        if (!prova) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        // Verifica quantas tentativas o aluno já gastou (em curso ou concluídas)
        const tentativasFeitas = dbEntregas.filter(e => e.avaliacaoId === id && e.alunoId === alunoId).length;
        if (tentativasFeitas >= (prova.tentativas || 1)) {
            return res.status(403).json({ success: false, error: "Limite de tentativas esgotado." });
        }

        const novaEntrega = {
            id: 'ent_' + Date.now(),
            avaliacaoId: id,
            alunoId,
            alunoNome,
            status: 'em_curso', // ⏳ Regista que está a fazer
            dataInicio: new Date().toISOString()
        };
        dbEntregas.push(novaEntrega);

        res.json({ success: true, entregaId: novaEntrega.id });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 🚀 2. ATUALIZADO: ENTREGAR AVALIAÇÃO (Atualiza a tentativa "Em Curso")
router.post('/:id/entregar', async (req, res) => {
    try {
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, relatorioFraude, entregaId } = req.body;
        
        // Puxa a tentativa ativa
        let entrega = dbEntregas.find(e => e.id === entregaId && e.alunoId === alunoId);
        
        if (!entrega) {
            // Fallback de segurança caso a sessão tenha caído
            entrega = { id: 'ent_' + Date.now(), avaliacaoId: id, alunoId, alunoNome: req.body.alunoNome };
            dbEntregas.push(entrega);
        }

        // Salva tudo e tranca o exame
        entrega.respostas = respostas || null;
        entrega.audioUrl = audioUrl || null;
        entrega.relatorioFraude = relatorioFraude || { fugas: 0, tempoFora: 0 };
        entrega.status = 'concluida'; // ✅ Trancou!
        entrega.dataEntrega = new Date().toISOString();

        res.json({ success: true, entrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro na entrega." }); }
});

// 🚀 3. ATUALIZADO: O PROFESSOR SÓ VÊ EXAMES CONCLUÍDOS
router.get('/entregas', async (req, res) => {
    try { 
        res.json({ success: true, entregas: dbEntregas.filter(e => e.status === 'concluida') });
    } catch (error) { res.status(500).json({ success: false }); }
});

// O ALUNO VÊ TODAS AS TENTATIVAS (Para o sistema saber que ele já esgotou a chance)
router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        res.json({ success: true, entregas: dbEntregas.filter(e => e.alunoId === req.params.alunoId) });
    } catch (error) { res.status(500).json({ success: false }); }
});

module.exports = router;