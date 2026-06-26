// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();

let dbAvaliacoes = []; 
let dbEntregas = [];

// 1. CRIAR NOVA AVALIAÇÃO
router.post('/', async (req, res) => {
    try {
        const { titulo, tipo, tempo, questoes, instrucoes, escolaId, autorNome, destino, destinoNome } = req.body;
        const novaAvaliacao = {
            id: 'av_' + Date.now(), 
            titulo, tipo, 
            tempo: tempo || null, 
            questoes: questoes || [], 
            instrucoes: instrucoes || '', 
            escolaId, autorNome, 
            destino: destino || 'global', 
            destinoNome: destinoNome || 'Todas as Turmas', 
            dataCriacao: new Date().toISOString(),
            ultimaAtualizacao: new Date().toISOString(), // 🚀 NOVO: Carimbo de tempo
            status: 'ativa'
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

// 3. EDITAR AVALIAÇÃO EXISTENTE
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const index = dbAvaliacoes.findIndex(a => a.id === id);
        if (index === -1) return res.status(404).json({ success: false, error: "Não encontrada." });
        
        // 🚀 Atualiza e muda o carimbo de tempo
        dbAvaliacoes[index] = { ...dbAvaliacoes[index], ...req.body, ultimaAtualizacao: new Date().toISOString() };
        res.json({ success: true, avaliacao: dbAvaliacoes[index] });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao editar." }); }
});

// 4. MUDAR STATUS (Ocultar/Ativar)
router.patch('/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        const prova = dbAvaliacoes.find(a => a.id === id);
        if (prova) {
            prova.status = status;
            prova.ultimaAtualizacao = new Date().toISOString(); // 🚀 Muda o carimbo de tempo
        }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 5. EXCLUIR AVALIAÇÃO DEFINITIVAMENTE
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        dbAvaliacoes = dbAvaliacoes.filter(a => a.id !== id);
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 6. ALUNO ENTREGA AVALIAÇÃO
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

// 7. PROFESSOR BUSCA TODAS AS ENTREGAS
router.get('/entregas', async (req, res) => {
    try { res.json({ success: true, entregas: dbEntregas });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao buscar entregas." }); }
});

// 8. ALUNO BUSCA AS SUAS PRÓPRIAS ENTREGAS
router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        const { alunoId } = req.params;
        const minhas = dbEntregas.filter(e => e.alunoId === alunoId);
        res.json({ success: true, entregas: minhas });
    } catch (error) { res.status(500).json({ success: false, error: "Erro ao buscar histórico." }); }
});

module.exports = router;