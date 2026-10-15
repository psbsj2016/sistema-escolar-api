const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); 
const connectDB = require('../config/db');

// 🛡️ Middleware de Segurança do Master
const verifyMaster = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Não autorizado.' });
    
    const segredo = process.env.JWT_SECRET ? process.env.JWT_SECRET : 'fallback_secret_ptt_2024_seguro';

    try {
        jwt.verify(authHeader.split(' ')[1], segredo, (err, decoded) => {
            if (err || !decoded.master) return res.status(401).json({ error: 'Acesso negado.' });
            next();
        });
    } catch (e) {
        return res.status(500).json({ error: 'Erro interno de validação.' });
    }
};

// 🔍 Descobre o documento real da escola cruzando email e escolaId do utilizador
async function localizarEscolaPorEmail(database, targetEmail) {
    const emailEscapado = targetEmail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regexEmail = new RegExp(`^${emailEscapado}$`, 'i');

    const usuario = await database.collection('usuarios').findOne({
        $or: [{ login: regexEmail }, { email: regexEmail }]
    });

    const escolaId = usuario && usuario.escolaId ? usuario.escolaId : null;
    const criterios = [{ email: regexEmail }];
    if (escolaId) criterios.push({ escolaId: escolaId });
    if (usuario && usuario.id) criterios.push({ donoId: usuario.id });

    const docsEscola = await database.collection('escola').find({ $or: criterios }).toArray();
    let escolaUnificada = null;

    if (docsEscola.length > 0) {
        escolaUnificada = {};
        docsEscola.forEach(d => { escolaUnificada = { ...escolaUnificada, ...d }; });
    }

    const filtroAtualizacao = escolaId ? { escolaId: escolaId } : { email: targetEmail };
    return {
        escola: escolaUnificada,
        escolaId: escolaId || (escolaUnificada ? escolaUnificada.escolaId : null),
        filtroAtualizacao
    };
}

function calcularEstadoValidade(escola, ativacao) {
    const agora = new Date();
    const planoRef = (escola && escola.plano) ? escola.plano : (ativacao && ativacao.plano ? ativacao.plano : 'Pendente');
    const diasPadrao = planoRef === 'Teste' ? 7 : 30;

    let dataExpStr = (escola && escola.dataExpiracao)
        ? escola.dataExpiracao
        : (ativacao && ativacao.dataExpiracao ? ativacao.dataExpiracao : null);

    if (!dataExpStr) {
        const dataBaseStr = (ativacao && ativacao.dataAtivacao)
            ? ativacao.dataAtivacao
            : (escola && escola.dataCriacao ? escola.dataCriacao : null);
        if (dataBaseStr) {
            const dBase = new Date(dataBaseStr);
            if (!isNaN(dBase.getTime())) {
                dataExpStr = new Date(dBase.getTime() + (diasPadrao * 24 * 60 * 60 * 1000)).toISOString();
            }
        }
    }

    let diasRestantes = null;
    if (dataExpStr) {
        const dExp = new Date(dataExpStr);
        if (!isNaN(dExp.getTime())) {
            diasRestantes = Math.ceil((dExp.getTime() - agora.getTime()) / (1000 * 60 * 60 * 24));
        }
    }

    return { dataExpiracao: dataExpStr, diasRestantes };
}

// ==========================================
// 1. LOGIN MASTER
// ==========================================
router.post('/login', async (req, res) => {
    try {
        const senhaDigitada = req.body.senha;
        const senhaEnv = process.env.SENHA_DONO_HASH;
        const segredo = process.env.JWT_SECRET ? process.env.JWT_SECRET : 'fallback_secret_ptt_2024_seguro';
        
        if (!senhaDigitada) return res.status(400).json({ error: 'Senha não fornecida.' });
        if (!senhaEnv) return res.status(500).json({ error: 'A variável SENHA_DONO_HASH não está configurada no seu servidor.' });

        let senhaValida = false;

        if (String(senhaEnv).startsWith('$2')) {
            senhaValida = await bcrypt.compare(String(senhaDigitada), String(senhaEnv));
        } else {
            senhaValida = (String(senhaDigitada) === String(senhaEnv));
        }

        if (senhaValida) {
            const token = jwt.sign({ master: true }, segredo, { expiresIn: '2h' });
            return res.json({ success: true, token });
        }
        res.status(401).json({ error: 'Senha incorreta.' });
    } catch (error) {
        console.error("🚨 Erro Crítico no login master:", error.message);
        res.status(500).json({ error: `Erro 500: ${error.message}` });
    }
});

// ==========================================
// 2. LISTAR TODAS AS ESCOLAS
// ==========================================
router.get('/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();
        const usuarios = await database.collection('usuarios').find({}).toArray();

        const listaFinal = [];
        const emailsProcessados = new Set(); 

        for (let a of ativacoes) {
            if (!a.email) continue;
            
            const email = String(a.email).toLowerCase().trim();
            const user = usuarios.find(u => (u.login && String(u.login).toLowerCase().trim() === email) || (u.email && String(u.email).toLowerCase().trim() === email));
            const escola = escolas.find(e => 
                (e.email && String(e.email).toLowerCase().trim() === email) ||
                (user && user.escolaId && e.escolaId === user.escolaId)
            );
            
            let statusFinal = a.status ? a.status : 'Pendente';
            if (statusFinal === 'Ativo') statusFinal = 'Verificado';
            if (escola && escola.plano === 'Bloqueado') statusFinal = 'Bloqueado';

            const planoAtual = (escola && escola.plano) ? escola.plano : (a.plano ? a.plano : 'Pendente');
            const { dataExpiracao, diasRestantes } = calcularEstadoValidade(escola, a);

            listaFinal.push({
                email: email,
                status: statusFinal,
                pinAtivacao: a.pinAtivacao ? a.pinAtivacao : '',
                plano: planoAtual,
                dataExpiracao: dataExpiracao,
                diasRestantes: diasRestantes
            });
            emailsProcessados.add(email);
        }

        for (let e of escolas) {
            if (!e.email) continue;
            const email = String(e.email).toLowerCase().trim();
            
            if (!emailsProcessados.has(email)) {
                const { dataExpiracao, diasRestantes } = calcularEstadoValidade(e, null);
                listaFinal.push({
                    email: email,
                    status: e.plano === 'Bloqueado' ? 'Bloqueado' : 'Verificado',
                    pinAtivacao: '',
                    plano: e.plano ? e.plano : 'Essencial',
                    dataExpiracao: dataExpiracao,
                    diasRestantes: diasRestantes
                });
                emailsProcessados.add(email);
            }
        }

        res.json(listaFinal);
    } catch (error) {
        console.error("🚨 Erro Crítico ao puxar ativações:", error.message);
        res.status(500).json({ error: 'Erro interno ao carregar dados.' });
    }
});

// ==========================================
// 3. GERAR PIN OU ATIVAR DIRETAMENTE (SINCRONIZADO COM ESCOLAID)
// ==========================================
router.post('/gerar-pin', verifyMaster, async (req, res) => {
    try {
        const { email, plano, diasValidade, modoAtivacao } = req.body;
        if (!email || !plano) return res.status(400).json({ error: 'Dados incompletos.' });

        const database = await connectDB();
        const targetEmail = String(email).toLowerCase().trim();
        const dias = parseInt(diasValidade) ? parseInt(diasValidade) : (plano === 'Teste' ? 7 : 30);
        const modo = modoAtivacao ? modoAtivacao : 'pin';

        const { escola: escolaExistente, escolaId, filtroAtualizacao } = await localizarEscolaPorEmail(database, targetEmail);
        const agora = new Date();

        const prefix = String(plano).substring(0, 3).toUpperCase();
        const randomCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const pin = `${prefix}-${randomCode}`;

        if (modo === 'direto') {
            let baseData = agora;
            if (escolaExistente && escolaExistente.dataExpiracao && escolaExistente.plano !== 'Teste' && escolaExistente.plano !== 'Bloqueado') {
                const expAtual = new Date(escolaExistente.dataExpiracao);
                if (!isNaN(expAtual.getTime()) && expAtual > agora) {
                    baseData = expAtual;
                }
            }
            const novaDataExp = new Date(baseData.getTime() + (dias * 24 * 60 * 60 * 1000)).toISOString();
            const agoraIso = agora.toISOString();

            await database.collection('ativacoes').updateOne(
                { email: targetEmail },
                {
                    $set: {
                        email: targetEmail,
                        plano: plano,
                        diasValidade: dias,
                        pinAtivacao: '',
                        ultimoPinGerado: pin,
                        status: 'Ativo',
                        dataAtivacao: agoraIso,
                        dataExpiracao: novaDataExp
                    }
                },
                { upsert: true }
            );

            const dadosEscola = {
                email: targetEmail,
                plano: plano,
                status: 'Ativo',
                dataAtivacao: agoraIso,
                dataExpiracao: novaDataExp
            };
            if (escolaId) dadosEscola.escolaId = escolaId;

            await database.collection('escola').updateOne(
                filtroAtualizacao,
                { $set: dadosEscola },
                { upsert: true }
            );

            // Remove eventuais duplicados órfãos sem escolaId
            if (escolaId) {
                await database.collection('escola').deleteMany({
                    email: targetEmail,
                    escolaId: { $ne: escolaId }
                });
                if (global.escolaEmitter) global.escolaEmitter.emit('atualizacao-escola', escolaId);
            }

            return res.json({
                success: true,
                modo: 'direto',
                pin: pin,
                plano: plano,
                dias: dias,
                dataExpiracao: novaDataExp
            });
        }

        // Modo PIN: Gera o PIN e deixa pronto para o cliente validar em "Meu Plano" ou no Cadastro Inicial
        await database.collection('ativacoes').updateOne(
            { email: targetEmail },
            {
                $set: {
                    email: targetEmail,
                    plano: plano,
                    diasValidade: dias,
                    pinAtivacao: pin,
                    ultimoPinGerado: pin,
                    status: 'Aguardando Ativação'
                }
            },
            { upsert: true }
        );

        res.json({ success: true, modo: 'pin', pin, plano, dias });
    } catch (error) {
        console.error("🚨 Erro ao gerar PIN / atualizar plano:", error.message);
        res.status(500).json({ error: 'Erro ao processar atualização de plano.' });
    }
});

// ==========================================
// 4. BLOQUEAR CONTA
// ==========================================
router.post('/bloquear', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail obrigatório.' });

        const database = await connectDB();
        const target = String(email).toLowerCase().trim();
        const { escola: escolaAtual, escolaId, filtroAtualizacao } = await localizarEscolaPorEmail(database, target);

        const planoAnterior = (escolaAtual && escolaAtual.plano && escolaAtual.plano !== 'Bloqueado')
            ? escolaAtual.plano
            : 'Profissional';

        await database.collection('ativacoes').updateOne(
            { email: target },
            { $set: { status: 'Bloqueado', planoAnterior: planoAnterior } }
        );

        const dadosBloqueio = { email: target, plano: 'Bloqueado', status: 'Bloqueado', planoAnterior: planoAnterior };
        if (escolaId) dadosBloqueio.escolaId = escolaId;

        await database.collection('escola').updateOne(filtroAtualizacao, { $set: dadosBloqueio });

        if (escolaId && global.escolaEmitter) {
            global.escolaEmitter.emit('atualizacao-escola', escolaId);
        }

        res.json({ success: true });
    } catch (error) {
        console.error("🚨 Erro ao bloquear conta:", error.message);
        res.status(500).json({ error: 'Erro ao bloquear conta.' });
    }
});

// ==========================================
// 4.1 DESBLOQUEAR / REATIVAR CONTA COM 1 CLIQUE
// ==========================================
router.post('/desbloquear', verifyMaster, async (req, res) => {
    try {
        const { email, diasExtras } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail obrigatório.' });

        const database = await connectDB();
        const target = String(email).toLowerCase().trim();
        const { escola, escolaId, filtroAtualizacao } = await localizarEscolaPorEmail(database, target);
        const ativacao = await database.collection('ativacoes').findOne({ email: target });

        const planoRestaurado = (escola && escola.planoAnterior)
            ? escola.planoAnterior
            : ((ativacao && ativacao.plano && ativacao.plano !== 'Bloqueado') ? ativacao.plano : 'Profissional');

        const agora = new Date();
        let novaDataExp = (escola && escola.dataExpiracao) ? new Date(escola.dataExpiracao) : agora;
        const diasSomar = parseInt(diasExtras) ? parseInt(diasExtras) : 30;

        if (isNaN(novaDataExp.getTime()) || novaDataExp <= agora) {
            novaDataExp = new Date(agora.getTime() + (diasSomar * 24 * 60 * 60 * 1000));
        }

        const novaDataExpIso = novaDataExp.toISOString();

        await database.collection('ativacoes').updateOne(
            { email: target },
            {
                $set: {
                    status: 'Ativo',
                    plano: planoRestaurado,
                    dataAtivacao: agora.toISOString(),
                    dataExpiracao: novaDataExpIso
                }
            },
            { upsert: true }
        );

        const dadosDesbloqueio = {
            email: target,
            plano: planoRestaurado,
            status: 'Ativo',
            dataExpiracao: novaDataExpIso
        };
        if (escolaId) dadosDesbloqueio.escolaId = escolaId;

        await database.collection('escola').updateOne(
            filtroAtualizacao,
            { $set: dadosDesbloqueio },
            { upsert: true }
        );

        if (escolaId) {
            await database.collection('escola').deleteMany({
                email: target,
                escolaId: { $ne: escolaId }
            });
            if (global.escolaEmitter) global.escolaEmitter.emit('atualizacao-escola', escolaId);
        }

        res.json({ success: true, plano: planoRestaurado, dataExpiracao: novaDataExpIso });
    } catch (error) {
        console.error("🚨 Erro ao desbloquear conta:", error.message);
        res.status(500).json({ error: 'Erro ao desbloquear conta.' });
    }
});

// ==========================================
// 5. OBLITERAR CONTA
// ==========================================
router.post('/excluir-conta', verifyMaster, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail obrigatório.' });

        const target = String(email).toLowerCase().trim();
        const database = await connectDB();
        const { escolaId } = await localizarEscolaPorEmail(database, target);

        if (escolaId) {
            const colecoes = [
                'alunos', 'turmas', 'cursos', 'financeiro', 'eventos',
                'chamadas', 'avaliacoes', 'planejamentos', 'usuarios',
                'estoques', 'contratos', 'notificacoes', 'workspace_posts',
                'workspace_notificacoes', 'workspace_entregas', 'workspace_materiais'
            ];
            for (const col of colecoes) {
                await database.collection(col).deleteMany({ escolaId: escolaId });
            }
            await database.collection('escola').deleteMany({ escolaId: escolaId });
        }
        await database.collection('escola').deleteMany({ email: target });
        await database.collection('usuarios').deleteMany({ login: target });
        await database.collection('ativacoes').deleteOne({ email: target });
        res.json({ success: true, message: 'Conta obliterada.' });
    } catch (error) {
        console.error("🚨 Erro ao excluir conta:", error.message);
        res.status(500).json({ error: 'Erro ao excluir conta.' });
    }
});

// ==========================================
// 6. NOTIFICAÇÕES MASTER
// ==========================================
router.get('/notificacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = [];

        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();

        escolas.forEach(escola => {
            if (!escola.email || escola.plano === 'Bloqueado') return;
            const email = String(escola.email).toLowerCase().trim();
            const ativ = ativacoes.find(a => a.email && String(a.email).toLowerCase().trim() === email);
            const { diasRestantes } = calcularEstadoValidade(escola, ativ);

            if (diasRestantes !== null) {
                if (diasRestantes <= 5 && diasRestantes >= 0) {
                    notificacoes.push({
                        tipo: 'aviso',
                        titulo: 'Renovação Próxima',
                        mensagem: `O plano <b>${escola.plano || 'Ativo'}</b> de ${email} vence em ${diasRestantes} dia(s).`
                    });
                } else if (diasRestantes < 0) {
                    notificacoes.push({
                        tipo: 'perigo',
                        titulo: 'Plano Vencido',
                        mensagem: `O acesso de ${email} (${escola.plano || 'Plano'}) venceu há ${Math.abs(diasRestantes)} dia(s).`
                    });
                }
            }
        });

        const pendentes = ativacoes.filter(a => ['Pendente', 'Aguardando', 'Aguardando Ativação'].includes(a.status));
        pendentes.forEach(p => {
            notificacoes.push({
                tipo: 'info',
                titulo: p.pinAtivacao ? 'Aguardando Uso do PIN' : 'Novo Cliente',
                mensagem: p.pinAtivacao
                    ? `A escola ${p.email} possui o PIN <b>${p.pinAtivacao}</b> pendente de ativação.`
                    : `A escola ${p.email} pediu acesso e aguarda a geração do PIN.`
            });
        });

        res.json(notificacoes);
    } catch (error) {
        console.error("🚨 Erro ao carregar notificações:", error.message);
        res.status(500).json({ error: 'Erro ao carregar alertas.' });
    }
});

module.exports = router;