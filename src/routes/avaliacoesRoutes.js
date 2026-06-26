// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();
const connectDB = require('../config/db'); // 🚀 LIGAÇÃO À BD REAL

// 1. CRIAR NOVA AVALIAÇÃO
router.post('/', async (req, res) => {
    try {
        const db = await connectDB();
        const { titulo, tipo, tempo, questoes, instrucoes, escolaId, autorNome, destino, destinoNome, tentativas } = req.body;
        const novaAvaliacao = {
            id: 'av_' + Date.now(), titulo, tipo, tempo: tempo || null, questoes: questoes || [], instrucoes: instrucoes || '', escolaId, autorNome, destino: destino || 'global', destinoNome: destinoNome || 'Todas as Turmas', tentativas: tentativas || 1, dataCriacao: new Date().toISOString(), ultimaAtualizacao: new Date().toISOString(), status: 'ativa'
        };
        await db.collection('workspace_avaliacoes').insertOne(novaAvaliacao);
        res.json({ success: true, avaliacao: novaAvaliacao });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 2. LISTAR AVALIAÇÕES DISPONÍVEIS
router.get('/', async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId } = req.query;
        const query = escolaId ? { escolaId } : {};
        const avaliacoes = await db.collection('workspace_avaliacoes').find(query).toArray();
        res.json({ success: true, avaliacoes });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 3. EDITAR AVALIAÇÃO EXISTENTE
router.put('/:id', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        
        const temEntregas = await db.collection('workspace_entregas_provas').findOne({ avaliacaoId: id });
        if (temEntregas) return res.json({ success: false, error: "Esta avaliação possui entregas e não pode ser editada." });
        
        const updateData = { ...req.body, ultimaAtualizacao: new Date().toISOString() };
        delete updateData._id; // Impede que o Express tente sobrescrever o ID interno do Mongo
        delete updateData.id;

        const result = await db.collection('workspace_avaliacoes').findOneAndUpdate(
            { id: id },
            { $set: updateData },
            { returnDocument: 'after' }
        );
        
        if (!result) return res.status(404).json({ success: false, error: "Prova não encontrada." });
        res.json({ success: true, avaliacao: result });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 4. MUDAR STATUS
router.patch('/:id/status', async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_avaliacoes').updateOne(
            { id: req.params.id },
            { $set: { status: req.body.status, ultimaAtualizacao: new Date().toISOString() } }
        );
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 5. EXCLUIR AVALIAÇÃO DEFINITIVAMENTE
router.delete('/:id', async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_avaliacoes').deleteOne({ id: req.params.id });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// ==========================================
// 🚀 ETAPA C: ROTAS DO BANCO DE QUESTÕES
// ==========================================
router.post('/banco-questoes', async (req, res) => {
    try {
        const db = await connectDB();
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
        await db.collection('workspace_banco_questoes').insertOne(novaQuestaoBanco);
        res.json({ success: true, questao: novaQuestaoBanco });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.get('/banco-questoes', async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId } = req.query;
        const query = escolaId ? { escolaId } : {};
        const questoes = await db.collection('workspace_banco_questoes').find(query).toArray();
        res.json({ success: true, questoes });
    } catch (error) { res.status(500).json({ success: false }); }
});
// ==========================================

// 6. ALUNO INICIA AVALIAÇÃO
router.post('/:id/iniciar', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { alunoId, alunoNome } = req.body;
        
        const prova = await db.collection('workspace_avaliacoes').findOne({ id: id });
        if (!prova) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        const tentativasFeitas = await db.collection('workspace_entregas_provas').countDocuments({ avaliacaoId: id, alunoId: alunoId });
        
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
        await db.collection('workspace_entregas_provas').insertOne(novaEntrega);

        res.json({ success: true, entregaId: novaEntrega.id });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 7. ALUNO ENTREGA AVALIAÇÃO
router.post('/:id/entregar', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, relatorioFraude, entregaId } = req.body;
        
        let entrega = await db.collection('workspace_entregas_provas').findOne({ id: entregaId, alunoId: alunoId });
        
        if (!entrega) {
            entrega = { id: 'ent_' + Date.now(), avaliacaoId: id, alunoId, alunoNome: req.body.alunoNome };
            await db.collection('workspace_entregas_provas').insertOne(entrega);
        }

        await db.collection('workspace_entregas_provas').updateOne(
            { id: entrega.id },
            { $set: { 
                respostas: respostas || null,
                audioUrl: audioUrl || null,
                relatorioFraude: relatorioFraude || { fugas: 0, tempoFora: 0 },
                status: 'concluida',
                dataEntrega: new Date().toISOString()
            }}
        );

        res.json({ success: true, entrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro na entrega." }); }
});

// 8. PROFESSOR BUSCA TODAS AS ENTREGAS
router.get('/entregas', async (req, res) => {
    try { 
        const db = await connectDB();
        const entregas = await db.collection('workspace_entregas_provas').find({ status: 'concluida' }).toArray();
        res.json({ success: true, entregas });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 9. ALUNO BUSCA AS SUAS PRÓPRIAS ENTREGAS
router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        const db = await connectDB();
        const entregas = await db.collection('workspace_entregas_provas').find({ alunoId: req.params.alunoId }).toArray();
        res.json({ success: true, entregas });
    } catch (error) { res.status(500).json({ success: false }); }
});

module.exports = router;