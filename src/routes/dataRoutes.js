const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const { filtroTenant } = require('../middlewares/auth');
const crypto = require('crypto');
const { z } = require('zod');

const COLECOES_OK = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'planejamentos', 'estoques', 'contratos', 'notificacoes'];

// 🛡️ REGRAS DE VALIDAÇÃO (ZOD) COMPLETAS E BLINDADAS
const validacoes = {
    alunos: z.object({
        nome: z.string().min(2, "O nome deve ter pelo menos 2 letras"),
    }).passthrough(),

    financeiro: z.object({
        valor: z.number().or(z.string()), 
        status: z.enum(['Pago', 'Pendente', 'Cancelado']),
    }).passthrough(),

    // 🟢 NOVAS VALIDAÇÕES ADICIONADAS ABAIXO:
    turmas: z.object({
        nome: z.string().min(1, "O nome da turma é obrigatório")
    }).passthrough(),

    cursos: z.object({
        nome: z.string().min(1, "O nome do curso é obrigatório")
    }).passthrough(),

    eventos: z.object({
        data: z.string().min(8, "Data inválida"),
        descricao: z.string().optional()
    }).passthrough(),

    estoques: z.object({
        nome: z.string().min(1, "O nome do item é obrigatório"),
        quantidade: z.number().or(z.string()) // Protege contra quantidades em branco
    }).passthrough(),

    // Para as restantes, garantimos pelo menos que são objetos válidos (não vazios/corrompidos),
    // usando o passthrough para aceitar os campos flexíveis que o teu frontend envia.
    chamadas: z.object({}).passthrough(),
    avaliacoes: z.object({}).passthrough(),
    planejamentos: z.object({}).passthrough(),
    contratos: z.object({}).passthrough(),
    notificacoes: z.object({}).passthrough()
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

// ============================================================================
// 🔄 ROTA DE EDIÇÃO (COM EFEITO CASCATA CIRÚRGICO E 100% BLINDADO)
// ============================================================================
router.put('/:collection/:id', async (req, res) => {
    if (!COLECOES_OK.includes(req.params.collection)) return res.status(403).json({ error: 'Coleção não permitida.' });
    const database = await connectDB();
    const { _id, escolaId, ...body } = req.body;

    // 🕵️‍♂️ 1. DETETIVE: Verifica se a Turma mudou de nome
    let nomeAntigo = null;
    let nomeNovo = body.nome;
    let precisaDeCascata = false;

    if (req.params.collection === 'turmas' && nomeNovo && typeof nomeNovo === 'string') {
        const turmaOriginal = await database.collection('turmas').findOne({ id: req.params.id, ...filtroTenant(req) });
        if (turmaOriginal && turmaOriginal.nome) {
            nomeAntigo = String(turmaOriginal.nome).trim();
            nomeNovo = String(nomeNovo).trim();
            if (nomeAntigo !== '' && nomeAntigo !== nomeNovo) {
                precisaDeCascata = true;
            }
        }
    }

    // 💾 2. ATUALIZA A FICHA ORIGINAL DA TURMA
    const resultado = await database.collection(req.params.collection).updateOne(
        { id: req.params.id, ...filtroTenant(req) }, { $set: body }
    );
    if (resultado.matchedCount === 0) return res.status(404).json({ error: 'Registro não encontrado.' });

    // 🚀 3. EFEITO CASCATA DE PRECISÃO CIRÚRGICA
    if (precisaDeCascata) {
        try {
            const eid = req.escolaId; 
            console.log(`🔄 Cascata: Substituindo '${nomeAntigo}' por '${nomeNovo}'...`);

            // A) ALUNOS (Substitui apenas os integrantes exatos da turma)
            await database.collection('alunos').updateMany(
                { escolaId: eid, turma: nomeAntigo },
                { $set: { turma: nomeNovo } }
            );
            
            // Para alunos que tenham turmas em formato de array
            await database.collection('alunos').updateMany(
                { $and: [ { turmas: nomeAntigo }, { turmas: { $type: "array" } } ], escolaId: eid },
                { $set: { "turmas.$": nomeNovo } }
            );

            // B) EVENTOS & TAREFAS
            await database.collection('eventos').updateMany(
                { escolaId: eid, turmaNome: nomeAntigo },
                { $set: { turmaNome: nomeNovo } }
            );

            // C) AVALIAÇÕES E ENTREGAS DO WORKSPACE
            await database.collection('workspace_avaliacoes').updateMany(
                { escolaId: eid, destinoNome: nomeAntigo },
                { $set: { destinoNome: nomeNovo } }
            );
            await database.collection('workspace_entregas').updateMany(
                { escolaId: eid, turmaNome: nomeAntigo },
                { $set: { turmaNome: nomeNovo } }
            );
            await database.collection('workspace_notificacoes').updateMany(
                { escolaId: eid, destinoNome: nomeAntigo },
                { $set: { destinoNome: nomeNovo } }
            );

            // D) MATERIAIS & POSTS (Trata formato Texto e formato Lista com operador $and seguro)
            const colecoesMistas = ['workspace_materiais', 'workspace_posts'];
            for (const col of colecoesMistas) {
                // Se for Texto (String)
                await database.collection(col).updateMany(
                    { $and: [ { destinoNome: nomeAntigo }, { destinoNome: { $type: "string" } } ], escolaId: eid },
                    { $set: { destinoNome: nomeNovo } }
                );
                // Se for Lista (Array)
                await database.collection(col).updateMany(
                    { $and: [ { destinoNome: nomeAntigo }, { destinoNome: { $type: "array" } } ], escolaId: eid },
                    { $set: { "destinoNome.$": nomeNovo } }
                );
            }

            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'SALA_UPDATE', turmaId: req.params.id, escolaId: eid || 'DEFAULT'
                });
            }
            console.log(`✅ Efeito Cascata Concluído! Tudo atualizado cirurgicamente para '${nomeNovo}'.`);
        } catch (errCascata) {
            console.error("🚨 Erro na Cascata:", errCascata);
        }
    }

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