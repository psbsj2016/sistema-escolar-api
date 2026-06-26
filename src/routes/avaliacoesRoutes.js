// backend/routes/avaliacoesRoutes.js (ou onde gerencia as rotas da API)
const express = require('express');
const router = express.Router();

// ⚠️ NOTA: Estou a usar arrays em memória como exemplo. 
// No seu sistema real, substitua "dbAvaliacoes.push" por consultas à sua Base de Dados (MongoDB, MySQL, Firebase, etc.)
let dbAvaliacoes = []; 
let dbEntregas = [];

// 1. ROTA: CRIAR NOVA AVALIAÇÃO (Professor / Gestor)
router.post('/', async (req, res) => {
    try {
        const { titulo, tipo, tempo, questoes, instrucoes, escolaId, autorNome } = req.body;
        
        const novaAvaliacao = {
            id: 'av_' + Date.now(),
            titulo,
            tipo, // 'escrita' ou 'oral'
            tempo: tempo || null, // tempo em minutos (apenas para escrita)
            questoes: questoes || [],
            instrucoes: instrucoes || '', // apenas para oral
            escolaId,
            autorNome,
            dataCriacao: new Date().toISOString(),
            status: 'ativa'
        };

        // 💾 SALVAR NA BASE DE DADOS AQUI
        dbAvaliacoes.push(novaAvaliacao);
        
        console.log(`✅ Nova avaliação criada: ${titulo}`);
        res.json({ success: true, avaliacao: novaAvaliacao });

    } catch (error) {
        console.error("Erro ao criar avaliação:", error);
        res.status(500).json({ success: false, error: "Erro interno ao criar avaliação." });
    }
});

// 2. ROTA: LISTAR AVALIAÇÕES (Alunos e Professores)
router.get('/', async (req, res) => {
    try {
        const { escolaId } = req.query; // Para filtrar apenas as da escola atual
        
        // 🔍 BUSCAR NA BASE DE DADOS AQUI (Ex: SELECT * FROM avaliacoes WHERE escolaId = ?)
        // Neste exemplo, devolvemos tudo o que está em memória:
        const provas = dbAvaliacoes.filter(p => !escolaId || p.escolaId === escolaId);
        
        res.json({ success: true, avaliacoes: provas });
    } catch (error) {
        res.status(500).json({ success: false, error: "Erro ao buscar avaliações." });
    }
});

// 3. ROTA: ENTREGAR AVALIAÇÃO (Aluno)
router.post('/:id/entregar', async (req, res) => {
    try {
        const { id } = req.params; // ID da avaliação
        const { respostas, audioUrl, alunoId, alunoNome } = req.body;

        const novaEntrega = {
            id: 'ent_' + Date.now(),
            avaliacaoId: id,
            alunoId,
            alunoNome,
            respostas: respostas || null, // Se for escrita
            audioUrl: audioUrl || null,   // Se for oral
            dataEntrega: new Date().toISOString(),
            nota: null // Fica nulo até o professor corrigir
        };

        // 💾 SALVAR ENTREGA NA BASE DE DADOS AQUI
        dbEntregas.push(novaEntrega);

        res.json({ success: true, entrega: novaEntrega });
    } catch (error) {
        res.status(500).json({ success: false, error: "Erro ao entregar a prova." });
    }
});

module.exports = router;