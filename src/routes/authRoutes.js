const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const connectDB = require('../config/db');
const { Resend } = require('resend');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const resend = new Resend(process.env.RESEND_API_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL ? process.env.FRONTEND_URL : 'https://www.sistemaptt.com.br';
const isProduction = process.env.NODE_ENV === 'production';

router.post('/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
    
    email = email.toLowerCase().trim();
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    const validade = new Date(Date.now() + 10 * 60 * 1000);

    try {
        const respostaResend = await resend.emails.send({
            from: 'Sistema PTT <contato@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Seu Código de Acesso',
            html: `<div style="text-align:center;"><h2>Verificação:</h2><h1>${codigoGerado}</h1><p>Expira em 10 min.</p></div>`
        });

        if (respostaResend.error) return res.status(500).json({ error: 'Falha no servidor de e-mail. Tente novamente.' });

        const database = await connectDB();
        // Preserva o PIN e o plano caso o CEO já tenha gerado um Cadastro VIP antes para este e-mail
        await database.collection('ativacoes').updateOne(
            { email },
            {
                $set: { email, codigoValidacao: codigoGerado, expiracaoCodigo: validade },$setOnInsert: { status: 'Pendente' }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro interno ao processar envio.' }); }
});

router.post('/validar-cadastro', async (req, res) => {
    try {
        let { email, codigo, pin } = req.body;
        if (!email || !codigo || !pin) {
            return res.status(400).json({ error: 'Preencha todos os campos.' });
        }

        email = email.toLowerCase().trim();
        const pinLimpo = String(pin).trim().toUpperCase();
        const database = await connectDB();
        const ativacao = await database.collection('ativacoes').findOne({ email });

        const pinGuardado = ativacao && ativacao.pinAtivacao ? String(ativacao.pinAtivacao).trim().toUpperCase() : '';
        if (!ativacao || !pinGuardado || pinGuardado !== pinLimpo || String(ativacao.codigoValidacao) !== String(codigo).trim()) {
            return res.status(401).json({ error: 'Código ou PIN inválidos ou expirados.' });
        }

        // Verifica se a escola já existia para manter o mesmo escolaId, ou gera um novo
        const escolaExistente = await database.collection('escola').findOne({ email });
        const escolaId = (escolaExistente && escolaExistente.escolaId)
            ? escolaExistente.escolaId
            : 'ESC-' + crypto.randomUUID().split('-')[0].toUpperCase();

        // Define o plano e os dias exatos (7 dias se for Teste, 30 dias padrão ou o período definido pelo CEO)
        const planoContratado = ativacao.plano ? ativacao.plano : 'Profissional';
        const diasValidade = parseInt(ativacao.diasValidade)
            ? parseInt(ativacao.diasValidade)
            : (planoContratado === 'Teste' ? 7 : 30);

        const agora = new Date();
        const dataVenc = new Date(agora.getTime() + (diasValidade * 24 * 60 * 60 * 1000));
        const agoraIso = agora.toISOString();
        const dataVencIso = dataVenc.toISOString();
        const senhaHash = await bcrypt.hash("123", 10);

        await database.collection('escola').updateOne(
            { email },
            {
                $set: { escolaId, email, plano: planoContratado, status: 'Ativo', dataAtivacao: agoraIso, dataExpiracao: dataVencIso },$setOnInsert: { dataCriacao: agoraIso }
            },
            { upsert: true }
        );

        // 🛡️ ANTI-DUPLICAÇÃO: Cria o utilizador Gestor apenas se ainda não existir conta para este e-mail
        const usuarioExistente = await database.collection('usuarios').findOne({ login: email });
        if (!usuarioExistente) {
            await database.collection('usuarios').insertOne({
                id: crypto.randomUUID(),
                escolaId,
                login: email,
                email: email,
                senha: senhaHash,
                tipo: "Gestor",
                isDono: true
            });
        } else {
            await database.collection('usuarios').updateOne(
                { login: email },
                { $set: { escolaId } }
            );
        }

        await database.collection('ativacoes').updateOne(
            { email },
            {
                $unset: { codigoValidacao: "", expiracaoCodigo: "" },
                $set: {
                    status: 'Ativo',
                    plano: planoContratado,
                    dataAtivacao: agoraIso,
                    dataExpiracao: dataVencIso,
                    pinAtivacao: '',
                    ultimoPinUsado: pinLimpo
                }
            }
        );

        res.json({ success: true, plano: planoContratado, dataExpiracao: dataVencIso });
    } catch (error) {
        console.error('Erro em validar-cadastro:', error);
        res.status(500).json({ error: 'Erro interno ao validar cadastro.' });
    }
});

router.post('/login', async (req, res) => {
    let { login, senha, sistema } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: new RegExp(`^${login.replace('*FORCAR','')}$`, 'i') });
    
    if (!user || !(await bcrypt.compare(senha, user.senha))) {
        return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    
    // 🛑 PROTEÇÃO RBAC: IMPEDE ALUNOS DE ACEDEREM AO PAINEL ADMINISTRATIVO
    if (user.tipo === 'Aluno' && sistema !== 'workspace') {
        return res.status(403).json({ error: 'Acesso negado. Área restrita. Faça login através do Portal do Aluno.' });
    }

    let escolaIdFinal = user.escolaId;
    const escolaVinculada = await database.collection('escola').findOne({ $or: [{ escolaId: user.escolaId }, { email: new RegExp(`^${user.login}$`, 'i') }, { donoId: user.id }] });

    if (escolaVinculada && escolaVinculada.escolaId) {
        escolaIdFinal = escolaVinculada.escolaId;
        await database.collection('usuarios').updateOne({ id: user.id }, { $set: { escolaId: escolaIdFinal } });
    } else if (!escolaIdFinal) { escolaIdFinal = user.id; }

    const token = jwt.sign({ id: user.id, tipo: user.tipo, escolaId: escolaIdFinal }, JWT_SECRET, { expiresIn: '12h' });

    res.cookie('token_acesso', token, { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: 'lax', 
        maxAge: 12*60*60*1000, 
        path: '/' 
    });
    
  let dadosExtras = {};
    if (user.tipo === 'Aluno') {
        const alunoMatriculado = user.alunoRefId
            ? await database.collection('alunos').findOne({ id: String(user.alunoRefId) })
            : await database.collection('alunos').findOne({ login: new RegExp(`^${user.login}$`, 'i') });

        if (alunoMatriculado) {
            const st = String(alunoMatriculado.status || 'Ativo').trim().toLowerCase();
            if (st.includes('cancel') || st.includes('tranc') || st.includes('exclu') || st.includes('inativ') || st.includes('desist')) {
                res.clearCookie('token_acesso', { path: '/' });
                return res.status(403).json({ error: 'A sua matrícula encontra-se inativa ou cancelada. Entre em contacto com a secretaria.' });
            }
            dadosExtras.turma = alunoMatriculado.turma;
            if (alunoMatriculado.turmas) dadosExtras.turmas = alunoMatriculado.turmas;
            if (alunoMatriculado.curso) dadosExtras.curso = alunoMatriculado.curso;
        }
    }

    res.json({ 
        success: true, 
        usuario: { 
            ...user, 
            ...dadosExtras,
            escolaId: escolaIdFinal, 
            senha: undefined 
        } 
    });
});

router.post('/recuperar-senha', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: "Informe um e-mail." });
    
    email = email.toLowerCase().trim();
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ $or: [{ login: email }, { email }] });

    if (!user || (user.status && user.status.toLowerCase() === 'inativo')) return res.status(200).json({ success: true, message: "Link enviado." });

    const tokenLimpo = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(tokenLimpo).digest('hex');
    
    await database.collection('password_resets').deleteMany({ userId: user.id });
    await database.collection('password_resets').insertOne({ userId: user.id, escolaId: user.escolaId, email, tokenHash, expiraEm: new Date(Date.now() + 30*60*1000), usado: false });

    try {
        const respostaResend = await resend.emails.send({
            from: 'Sistema PTT <contato@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Redefinição de Senha',
            html: `<p>Clique abaixo para criar nova senha:</p><p><a href="${FRONTEND_URL}/index.html?reset=${tokenLimpo}">Redefinir minha senha</a></p>`
        });

        if (respostaResend.error) return res.status(500).json({ error: "Erro no servidor de e-mail. Tente novamente." });
        res.status(200).json({ success: true, message: "Enviado." });
    } catch (e) { res.status(500).json({ error: "Erro interno ao processar pedido." }); }
});

router.post('/redefinir-senha', async (req, res) => {
    const { token, novaSenha } = req.body;
    if (!token || String(novaSenha).length < 6) return res.status(400).json({ error: "A senha deve ter pelo menos 6 caracteres." });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const database = await connectDB();
    const reset = await database.collection('password_resets').findOne({ tokenHash, usado: false, expiraEm: { $gt: new Date() } });

    if (!reset) return res.status(401).json({ error: "Link inválido ou expirado." });
    
    const senhaHash = await bcrypt.hash(novaSenha, 10);
    await database.collection('usuarios').updateOne({ id: reset.userId, escolaId: reset.escolaId }, { $set: { senha: senhaHash } });
    await database.collection('password_resets').updateOne({ _id: reset._id }, { $set: { usado: true } });
    
    res.status(200).json({ success: true, message: "Senha redefinida." });
});

router.post('/logout', (req, res) => {
    res.clearCookie('token_acesso', { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: 'lax', 
        path: '/' 
    });
    res.json({ success: true });
});

// ============================================================================
// 🔐 ROTAS DE BIOMETRIA (WEBAUTHN V10+) - 100% BLINDADO
// ============================================================================

const rpName = 'Sistema PTT';

const getOriginInfo = (req) => {
    let origin = req.headers.origin;
    if (!origin && req.headers.referer) origin = new URL(req.headers.referer).origin;
    if (!origin) origin = process.env.FRONTEND_URL ? process.env.FRONTEND_URL : 'https://sistemaptt.com.br';
    origin = origin.replace(/\/$/, '');
    return { expectedOrigin: origin, rpID: new URL(origin).hostname };
};

router.post('/biometria/remover', async (req, res) => {
    try {
        const { login } = req.body;
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ login: login });
        if (user) {
            await database.collection('biometria').deleteMany({ userId: user.id });
            await database.collection('usuarios').updateOne({ id: user.id }, { $unset: { currentChallenge: "" } });
        }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao remover' }); }
});

router.post('/biometria/gerar-registo', async (req, res) => {
    try {
        const { login } = req.body;
        const { rpID } = getOriginInfo(req);
        
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ login: login });
        if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });

        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userID: new Uint8Array(Buffer.from(user.id, 'utf8')), 
            userName: user.login,
            authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
        });

        await database.collection('usuarios').updateOne({ id: user.id }, { $set: { currentChallenge: options.challenge } });
        res.json(options);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro interno ao preparar biometria.' });
    }
});

router.post('/biometria/verificar-registo', async (req, res) => {
    try {
        const { login, respostaBio } = req.body;
        const { expectedOrigin, rpID } = getOriginInfo(req);
        
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ login: login });
        if (!user || !user.currentChallenge) return res.status(400).json({ error: 'Registo inválido.' });

        const verification = await verifyRegistrationResponse({
            response: respostaBio,
            expectedChallenge: user.currentChallenge,
            expectedOrigin,
            expectedRPID: rpID,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;
            const cred = registrationInfo.credential ? registrationInfo.credential : registrationInfo;
            const credID = cred.id ? cred.id : cred.credentialID;
            const credPublicKey = cred.publicKey ? cred.publicKey : cred.credentialPublicKey;

            await database.collection('biometria').deleteMany({ userId: user.id });

            await database.collection('biometria').insertOne({
                userId: user.id,
                credentialID: typeof credID === 'string' ? credID : Buffer.from(credID).toString('base64url'),
                credentialPublicKey: Buffer.from(credPublicKey).toString('base64url'),
                counter: cred.counter,
                deviceType: registrationInfo.credentialDeviceType ? registrationInfo.credentialDeviceType : 'platform',
                dataCriacao: new Date().toISOString()
            });
            await database.collection('usuarios').updateOne({ id: user.id }, { $unset: { currentChallenge: "" } });
            return res.json({ success: true, verified: true });
        }
        res.status(400).json({ error: 'Verificação falhou.' });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'A verificação biométrica falhou no servidor.' });
    }
});

router.post('/biometria/gerar-login', async (req, res) => {
    try {
        const { login } = req.body;
        const { rpID } = getOriginInfo(req);
        
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ login: login });
        if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });

        const userPasskeys = await database.collection('biometria').find({ userId: user.id }).toArray();
        const validPasskeys = userPasskeys.filter(p => p.credentialID); 
        if (validPasskeys.length === 0) return res.status(400).json({ error: 'Nenhuma biometria registada.' });

        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: validPasskeys.map(passkey => ({
                id: passkey.credentialID, type: 'public-key'
            })),
            userVerification: 'required',
        });

        await database.collection('usuarios').updateOne({ id: user.id }, { $set: { currentChallenge: options.challenge } });
        res.json(options);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao gerar desafio de login.' });
    }
});

router.post('/biometria/verificar-login', async (req, res) => {
    try {
        const { login, respostaBio } = req.body;
        const { expectedOrigin, rpID } = getOriginInfo(req);
        
        const database = await connectDB();
        const user = await database.collection('usuarios').findOne({ login: login });
        if (!user || !user.currentChallenge) return res.status(400).json({ error: 'Login inválido.' });

        const passkey = await database.collection('biometria').findOne({ userId: user.id, credentialID: respostaBio.id });
        
        if (!passkey || !passkey.credentialPublicKey) {
            return res.status(400).json({ error: 'Biometria corrompida. Faça login com senha e configure novamente.' });
        }

        const verification = await verifyAuthenticationResponse({
            response: respostaBio,
            expectedChallenge: user.currentChallenge,
            expectedOrigin,
            expectedRPID: rpID,
            credential: {
                id: passkey.credentialID,
                publicKey: new Uint8Array(Buffer.from(passkey.credentialPublicKey, 'base64url')),
                counter: passkey.counter ? passkey.counter : 0,
            },
        });

        if (verification.verified) {
            await database.collection('biometria').updateOne({ _id: passkey._id }, { $set: { counter: verification.authenticationInfo.newCounter } });
            await database.collection('usuarios').updateOne({ id: user.id }, { $unset: { currentChallenge: "" } });

            let escolaIdFinal = user.escolaId;
            const escolaVinculada = await database.collection('escola').findOne({ $or: [{ escolaId: user.escolaId }, { email: new RegExp(`^${user.login}$`, 'i') }, { donoId: user.id }] });
            if (escolaVinculada && escolaVinculada.escolaId) escolaIdFinal = escolaVinculada.escolaId;
            else if (!escolaIdFinal) escolaIdFinal = user.id;

            const token = jwt.sign({ id: user.id, tipo: user.tipo, escolaId: escolaIdFinal }, process.env.JWT_SECRET, { expiresIn: '12h' });
            res.cookie('token_acesso', token, { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 12*60*60*1000, path: '/' });

            let dadosExtras = {};
            if (user.tipo === 'Aluno' && user.alunoRefId) {
                const alunoMatriculado = await database.collection('alunos').findOne({ id: user.alunoRefId });
                if (alunoMatriculado) {
                    dadosExtras.turma = alunoMatriculado.turma;
                    if (alunoMatriculado.turmas) dadosExtras.turmas = alunoMatriculado.turmas;
                    if (alunoMatriculado.curso) dadosExtras.curso = alunoMatriculado.curso;
                }
            }

            return res.json({ success: true, usuario: { ...user, ...dadosExtras, escolaId: escolaIdFinal, senha: undefined } });
        }
        res.status(400).json({ error: 'A validação falhou.' });
    } catch (error) {
        console.error("Erro verificar-login:", error);
        res.status(400).json({ error: 'A validação criptográfica falhou.' });
    }
});

module.exports = router;