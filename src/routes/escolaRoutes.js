const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');
const { filtroTenant } = require('../middlewares/auth');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// 🚀 1. CRIAMOS O MEGA-FONE GLOBAL SE NÃO EXISTIR
if (!global.escolaEmitter) {
    const EventEmitter = require('events');
    global.escolaEmitter = new EventEmitter();
}

router.get('/', async (req, res) => {
    try {
        const db = await connectDB();
        const data = await db.collection('escola').findOne({ $or: [{ escolaId: req.escolaId }, { donoId: req.userId }] });
        if (data) delete data._id;
        res.json(data || {});
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar dados da escola.' });
    }
});

router.put('/', async (req, res) => {
    try {
        const db = await connectDB();
        // 🛡️ BLINDAGEM DE SEGURANÇA: Impede que o navegador altere 'plano' ou 'dataExpiracao' sem validar PIN
        const { _id, plano, dataExpiracao, pinUsado, ...dadosPerfilSeguros } = req.body;
        
        await db.collection('escola').updateOne(
            { escolaId: req.escolaId },
            { $set: { ...dadosPerfilSeguros, escolaId: req.escolaId } },
            { upsert: true }
        );
        
        if (global.escolaEmitter) {
            global.escolaEmitter.emit('atualizacao-escola', req.escolaId);
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar perfil da escola.' });
    }
});

// 🔐 VALIDAÇÃO DE PIN 100% NO SERVIDOR (COM RENOVAÇÃO CUMULATIVA)
router.post('/validar-pin', async (req, res) => {
    try {
        const pinLimpo = String(req.body.pin ? req.body.pin : '').trim().toUpperCase();
        if (!pinLimpo) {
            return res.status(400).json({ error: 'Por favor, digite um PIN válido.' });
        }

        const db = await connectDB();
        const escolaAtual = await db.collection('escola').findOne({ $or: [{ escolaId: req.escolaId }, { donoId: req.userId }] });

        // Aceita tanto 'Pendente' quanto 'Aguardando Ativação' ou 'Aguardando'
        const ativacao = await db.collection('ativacoes').findOne({
            pinAtivacao: pinLimpo,
            status: { $in: ['Pendente', 'Aguardando Ativação', 'Aguardando'] }
        });

        if (!ativacao) {
            return res.status(404).json({ error: 'PIN inválido, expirado ou já utilizado.' });
        }

        // Se o PIN foi gerado para um e-mail específico, garante que pertence a esta escola
        if (escolaAtual && escolaAtual.email && ativacao.email) {
            const emailEscola = String(escolaAtual.email).toLowerCase().trim();
            const emailPin = String(ativacao.email).toLowerCase().trim();
            if (emailEscola !== emailPin) {
                return res.status(403).json({ error: 'Este PIN pertence a outra instituição.' });
            }
        }

        const novoPlano = ativacao.plano ? ativacao.plano : 'Profissional';
        const diasAdicionar = parseInt(ativacao.diasValidade) ? parseInt(ativacao.diasValidade) : (novoPlano === 'Teste' ? 7 : 30);

        // 📅 CÁLCULO CUMULATIVO: Se a escola ainda tem dias vigentes (e não era plano Teste), soma a partir do vencimento atual
        const agora = new Date();
        let baseCalculo = agora;
        if (escolaAtual && escolaAtual.dataExpiracao && escolaAtual.plano !== 'Teste' && escolaAtual.plano !== 'Bloqueado') {
            const expAtual = new Date(escolaAtual.dataExpiracao);
            if (!isNaN(expAtual.getTime()) && expAtual > agora) {
                baseCalculo = expAtual;
            }
        }

        const novaDataExp = new Date(baseCalculo.getTime() + (diasAdicionar * 24 * 60 * 60 * 1000));
        const agoraIso = agora.toISOString();
        const novaDataExpIso = novaDataExp.toISOString();

        // 1. Atualiza a coleção 'ativacoes' marcando como Ativo e inutilizando o PIN já usado
        await db.collection('ativacoes').updateOne(
            { _id: ativacao._id },
            {
                $set: {
                    status: 'Ativo',
                    plano: novoPlano,
                    dataAtivacao: agoraIso,
                    dataExpiracao: novaDataExpIso,
                    pinAtivacao: '',
                    ultimoPinUsado: pinLimpo
                }
            }
        );

        // 2. Atualiza a coleção 'escola' com o novo plano e a nova validade
        const filtroEscola = escolaAtual && escolaAtual.escolaId ? { escolaId: escolaAtual.escolaId } : { escolaId: req.escolaId };
        await db.collection('escola').updateOne(
            filtroEscola,
            {
                $set: {
                    plano: novoPlano,
                    status: 'Ativo',
                    pinUsado: pinLimpo,
                    dataAtivacao: agoraIso,
                    dataExpiracao: novaDataExpIso
                }
            },
            { upsert: true }
        );

        if (global.escolaEmitter) {
            global.escolaEmitter.emit('atualizacao-escola', req.escolaId);
        }

        return res.json({
            success: true,
            plano: novoPlano,
            dataExpiracao: novaDataExpIso,
            diasAdicionados: diasAdicionar
        });
    } catch (error) {
        console.error('Erro ao validar PIN:', error);
        res.status(500).json({ error: 'Erro interno ao validar o PIN.' });
    }
});

// Gestão de Usuários da Escola
router.get('/usuarios', async (req, res) => {
    try {
        const db = await connectDB();
        const data = await db.collection('usuarios').find({ escolaId: req.escolaId }).toArray();
        res.json(data.map(({ _id, senha, ...rest }) => rest));
    } catch (error) {
        res.status(500).json({ error: 'Erro ao listar usuários.' });
    }
});

module.exports = router;