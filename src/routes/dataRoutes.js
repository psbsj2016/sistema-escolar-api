const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const { filtroTenant } = require('../middlewares/auth');
const crypto = require('crypto');
const { z } = require('zod');

const COLECOES_OK = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'estoques', 'contratos', 'notificacoes'];

// 🛡️ REGRAS DE VALIDAÇÃO (ZOD)
const validacoes = {
    alunos: z.object({
        nome: z.string().min(2, "O nome deve ter pelo menos 2 letras"),
        // O passthrough permite que outros campos (como whatsapp, morada) passem, 
        // mas garante que o 'nome' é sempre válido e não está vazio.
    }).passthrough(), 

    financeiro: z.object({
        valor: z.number().or(z.string()), // Aceita número ou texto (ex: "150.00")
        status: z.enum(['Pago', 'Pendente', 'Cancelado']),
    }).passthrough()
};

// --- NOTIFICAÇÕES (Têm de vir antes do genérico) ---
router.get('/sistema/notificacoes/nao-lidas', async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = await database.collection('notificacoes')
            .find({ ...filtroTenant(req), lida: false }).sort({ dataCriacao: -1 }).toArray();
        res.json(notificacoes.map(({_id, ...rest}) => rest));
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar notificações.' }); }
});

router.put('/sistema/notificacoes/lida/:id', async (req, res) => {
    try {
        const database = await connectDB();
        await database.collection('notificacoes').updateOne(
            { id: req.params.id, ...filtroTenant(req) }, { $set: { lida: true } }
        );
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao marcar como lida.' }); }
});

// --- CRUD GENÉRICO RESTAURADO ---
router.get('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).find(filtroTenant(req)).toArray();
    res.json(data.map(({_id, ...rest}) => rest));
});

router.get('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).send();
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({ id: req.params.id, ...filtroTenant(req) });
    if (data) delete data._id;
    res.json(data || {});
});

router.post('/:collection', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });

    let dadosValidados = req.body;

    // Se existir uma regra de validação para esta coleção, o Zod entra em ação!
    if (validacoes[req.params.collection]) {
        const resultado = validacoes[req.params.collection].safeParse(req.body);

        if (!resultado.success) {
            // Se os dados estiverem sujos, bloqueamos a gravação imediatamente!
            return res.status(400).json({ 
                error: 'Dados inválidos detectados pelo sistema de segurança.', 
                detalhes: resultado.error.issues 
            });
        }
        dadosValidados = resultado.data; // Passa os dados limpos
    }

    const database = await connectDB();
    const body = { ...dadosValidados, id: req.body.id || crypto.randomUUID(), escolaId: req.escolaId };
    await database.collection(req.params.collection).insertOne(body);
    res.json(body);
});

router.put('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });
    const database = await connectDB();
    const { _id, escolaId, ...body } = req.body;
    const resultado = await database.collection(req.params.collection).updateOne(
        { id: req.params.id, ...filtroTenant(req) }, { $set: body }
    );
    if (resultado.matchedCount === 0) return res.status(404).json({ error: 'Registro não encontrado.' });
    res.json({ success: true, ...body });
});

router.delete('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });
    const database = await connectDB();
    const resultado = await database.collection(req.params.collection).deleteOne({ id: req.params.id, ...filtroTenant(req) });
    if (resultado.deletedCount === 0) return res.status(404).json({ error: 'Registro não encontrado.' });
    res.json({ success: true });
});

module.exports = router;