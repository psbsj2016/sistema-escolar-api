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

// 🔍 Função Auxiliar: Encontra e unifica o registo da escola por escolaId, donoId e E-mail
async function obterEscolaUnificada(db, req) {
    const usuarioLogado = await db.collection('usuarios').findOne({
        $or: [{ id: req.userId }, { escolaId: req.escolaId }]
    });

    const emailUsuario = usuarioLogado && (usuarioLogado.email || usuarioLogado.login)
        ? String(usuarioLogado.email || usuarioLogado.login).toLowerCase().trim()
        : '';

    const criterios = [{ escolaId: req.escolaId }];
    if (req.userId) criterios.push({ donoId: req.userId });
    if (emailUsuario) {
        const emailEscapado = emailUsuario.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        criterios.push({ email: new RegExp(`^${emailEscapado}$`, 'i') });
    }

    const docsEscola = await db.collection('escola').find({ $or: criterios }).toArray();
    const ativacao = emailUsuario
        ? await db.collection('ativacoes').findOne({ email: emailUsuario })
        : null;

    if (docsEscola.length === 0 && !ativacao) {
        return { escola: null, emailUsuario, ativacao: null };
    }

    // Junta todos os campos caso existissem 2 documentos separados (um com escolaId e outro com email)
    let escolaUnificada = {};
    docsEscola.forEach(doc => {
        escolaUnificada = { ...escolaUnificada, ...doc };
    });

    // Dá prioridade ao plano e dataExpiracao mais recentes vindos do documento com email ou da ativação
    const docPorEmail = docsEscola.find(d => d.email && String(d.email).toLowerCase().trim() === emailUsuario);
    if (docPorEmail && docPorEmail.plano) {
        escolaUnificada.plano = docPorEmail.plano;
        if (docPorEmail.dataExpiracao) escolaUnificada.dataExpiracao = docPorEmail.dataExpiracao;
    }

    if (ativacao && (ativacao.status === 'Ativo' || ativacao.status === 'Verificado')) {
        if (ativacao.plano && (!escolaUnificada.plano || escolaUnificada.plano === 'Teste')) {
            escolaUnificada.plano = ativacao.plano;
        }
        if (ativacao.dataExpiracao && !escolaUnificada.dataExpiracao) {
            escolaUnificada.dataExpiracao = ativacao.dataExpiracao;
        }
    }

    escolaUnificada.escolaId = req.escolaId || escolaUnificada.escolaId;
    if (emailUsuario) escolaUnificada.email = emailUsuario;

    // Se havia mais de 1 documento para a mesma escola, unifica no banco de dados automaticamente
    if (docsEscola.length > 1) {
        const idPrincipal = docsEscola[0]._id;
        const { _id, ...dadosSemId } = escolaUnificada;
        await db.collection('escola').updateOne({ _id: idPrincipal }, { $set: dadosSemId });
        const idsDuplicados = docsEscola.slice(1).map(d => d._id);
        await db.collection('escola').deleteMany({ _id: { $in: idsDuplicados } });
    }

    return { escola: escolaUnificada, emailUsuario, ativacao };
}

router.get('/', async (req, res) => {
    try {
        const db = await connectDB();
        const { escola } = await obterEscolaUnificada(db, req);
        if (escola) {
            const copia = { ...escola };
            delete copia._id;
            return res.json(copia);
        }
        res.json({});
    } catch (error) {
        console.error('Erro em GET /escola:', error);
        res.status(500).json({ error: 'Erro ao carregar dados da escola.' });
    }
});

router.put('/', async (req, res) => {
    try {
        const db = await connectDB();
        const { emailUsuario } = await obterEscolaUnificada(db, req);
        const { _id, plano, dataExpiracao, pinUsado, ...dadosPerfilSeguros } = req.body;

        const payload = { ...dadosPerfilSeguros, escolaId: req.escolaId };
        if (emailUsuario) payload.email = emailUsuario;

        await db.collection('escola').updateOne(
            { escolaId: req.escolaId },
            { $set: payload },
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

// 🔐 VALIDAÇÃO DE PIN BLINDADA (Sem Erro 404 indevido + Renovação Cumulativa)
router.post('/validar-pin', async (req, res) => {
    try {
        const pinLimpo = String(req.body.pin ? req.body.pin : '').trim().toUpperCase();
        if (!pinLimpo) {
            return res.status(400).json({ error: 'Por favor, digite um PIN válido.' });
        }

        const db = await connectDB();
        const { escola: escolaAtual, emailUsuario } = await obterEscolaUnificada(db, req);

        // 1. Procura o PIN na coleção 'ativacoes' (mesmo que o status já esteja como Ativo/Verificado/Pendente)
        let ativacao = await db.collection('ativacoes').findOne({
            $or: [
                { pinAtivacao: pinLimpo },
                { ultimoPinGerado: pinLimpo }
            ]
        });

        // 2. Fallback: Se o CEO ativou direto pelo Painel Master, encontra pelo e-mail da escola
        if (!ativacao && emailUsuario) {
            const ativPorEmail = await db.collection('ativacoes').findOne({ email: emailUsuario });
            if (ativPorEmail && (ativPorEmail.status === 'Ativo' || ativPorEmail.status === 'Verificado')) {
                ativacao = ativPorEmail;
            }
        }

        if (!ativacao) {
            return res.status(400).json({ error: 'PIN inválido, expirado ou já utilizado.' });
        }

        const novoPlano = ativacao.plano ? ativacao.plano : 'Profissional';
        const diasAdicionar = parseInt(ativacao.diasValidade) ? parseInt(ativacao.diasValidade) : (novoPlano === 'Teste' ? 7 : 30);

        // 📅 CÁLCULO CUMULATIVO: Soma os dias se o plano já não tiver sido somado no modo direto
        const agora = new Date();
        let novaDataExpIso = ativacao.dataExpiracao;

        // Se o PIN estava aguardando uso, calcula a nova data de expiração somando os dias
        if (ativacao.pinAtivacao === pinLimpo) {
            let baseCalculo = agora;
            if (escolaAtual && escolaAtual.dataExpiracao && escolaAtual.plano !== 'Teste' && escolaAtual.plano !== 'Bloqueado') {
                const expAtual = new Date(escolaAtual.dataExpiracao);
                if (!isNaN(expAtual.getTime()) && expAtual > agora) {
                    baseCalculo = expAtual;
                }
            }
            const novaDataExp = new Date(baseCalculo.getTime() + (diasAdicionar * 24 * 60 * 60 * 1000));
            novaDataExpIso = novaDataExp.toISOString();
        } else if (!novaDataExpIso) {
            novaDataExpIso = new Date(agora.getTime() + (diasAdicionar * 24 * 60 * 60 * 1000)).toISOString();
        }

        const agoraIso = agora.toISOString();
        const emailFinal = emailUsuario || ativacao.email || '';

        // Atualiza a coleção 'ativacoes'
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

        // Atualiza a coleção 'escola' vinculando escolaId e email no mesmo documento
        const dadosAtualizadosEscola = {
            escolaId: req.escolaId,
            plano: novoPlano,
            status: 'Ativo',
            pinUsado: pinLimpo,
            dataAtivacao: agoraIso,
            dataExpiracao: novaDataExpIso
        };
        if (emailFinal) dadosAtualizadosEscola.email = emailFinal;

        await db.collection('escola').updateOne(
            { escolaId: req.escolaId },
            { $set: dadosAtualizadosEscola },
            { upsert: true }
        );

        // Limpa eventuais documentos órfãos que tinham apenas email sem escolaId
        if (emailFinal) {
            await db.collection('escola').deleteMany({
                email: emailFinal,
                escolaId: { $ne: req.escolaId }
            });
        }

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