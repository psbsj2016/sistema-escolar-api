const express = require('express');
const router = express.Router();

// Memória temporária (Substitua depois por consultas reais à Base de Dados)
let dbAvaliacoes = []; 
let dbEntregas = [];

// 1. CRIAR NOVA AVALIAÇÃO
router.post('/', async (req, res) => {
    try {
        const { titulo, tipo, tempo, questoes, instrucoes, escolaId, autorNome } = req.body;
        const novaAvaliacao = {
            id: 'av_' + Date.now(), titulo, tipo, tempo: tempo || null, questoes: questoes || [], instrucoes: instrucoes || '', escolaId, autorNome, dataCriacao: new Date().toISOString(), status: 'ativa'
        };
        dbAvaliacoes.push(novaAvaliacao);
        res.json({ success: true, avaliacao: novaAvaliacao });
    } catch (error) { res.status(500).json({ success: false, error: "Erro interno." }); }
});

// 2. LISTAR AVALIAÇÕES DISPONÍVEIS
router.get('/', async (req, res) => {
    try {
        const { escolaId } = req.query;
        const provas = dbAvaliacoes.filter(p => !escolaId || p.escolaId === escolaId);
        res.json({ success: true, avaliacoes: provas });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao buscar." }); }
});

// 3. ALUNO ENTREGA AVALIAÇÃO
router.post('/:id/entregar', async (req, res) => {
    try {
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, alunoNome } = req.body;
        const novaEntrega = {
            id: 'ent_' + Date.now(), avaliacaoId: id, alunoId, alunoNome, respostas: respostas || null, audioUrl: audioUrl || null, dataEntrega: new Date().toISOString()
        };
        dbEntregas.push(novaEntrega);
        res.json({ success: true, entrega: novaEntrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro na entrega." }); }
});

// 🚀 4. PROFESSOR BUSCA TODAS AS ENTREGAS PARA CORRIGIR
router.get('/entregas', async (req, res) => {
    try {
        res.json({ success: true, entregas: dbEntregas });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao buscar entregas." }); }
});

// 🚀 5. ALUNO BUSCA AS SUAS PRÓPRIAS ENTREGAS (Para a aba de Concluídos)
router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        const { alunoId } = req.params;
        const minhas = dbEntregas.filter(e => e.alunoId === alunoId);
        res.json({ success: true, entregas: minhas });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao buscar histórico do aluno." }); }
});

module.exports = router;