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

// 1. Variáveis de Ambiente primeiro!
const resend = new Resend(process.env.RESEND_API_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://www.sistemaptt.com.br';

// 👇 A CORREÇÃO AQUI: Definimos o 'isProduction' ANTES de o usarmos abaixo!
const isProduction = process.env.NODE_ENV === 'production';

// 2. Configurações da Biometria
const rpName = 'Sistema PTT';
const rpID = isProduction ? 'sistemaptt.com.br' : 'localhost';

const expectedOrigin = isProduction ? ['https://www.sistemaptt.com.br', 'https://sistemaptt.com.br'] : 'http://localhost:5173';

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
        await database.collection('ativacoes').updateOne({ email }, { $set: { email, codigoValidacao: codigoGerado, expiracaoCodigo: validade, status: 'Pendente' } }, { upsert: true });
        
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro interno ao processar envio.' }); }
});

router.post('/validar-cadastro', async (req, res) => {
    let { email, codigo, pin } = req.body;
    email = email.toLowerCase().trim();
    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email });

    if (!ativacao || ativacao.pinAtivacao?.toUpperCase() !== pin.toUpperCase() || ativacao.codigoValidacao !== codigo) {
        return res.status(401).json({ error: 'Dados inválidos ou expirados.' });
    }

    const escolaId = 'ESC-' + crypto.randomUUID().split('-')[0].toUpperCase();
    const dataVenc = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const senhaHash = await bcrypt.hash("123", 10);

    await database.collection('escola').updateOne({ email }, { $set: { escolaId, email, plano: ativacao.plano || 'Profissional', dataExpiracao: dataVenc.toISOString() } }, { upsert: true });
    await database.collection('usuarios').insertOne({ id: crypto.randomUUID(), escolaId, login: email, senha: senhaHash, tipo: "Gestor", isDono: true });
    await database.collection('ativacoes').updateOne({ email }, { $unset: { codigoValidacao: "", expiracaoCodigo: "" }, $set: { status: 'Ativo', dataAtivacao: new Date().toISOString() } });

    res.json({ success: true });
});

router.post('/login', async (req, res) => {
    let { login, senha } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: new RegExp(`^${login.replace('*FORCAR','')}$`, 'i') });
    
    if (!user || !(await bcrypt.compare(senha, user.senha))) return res.status(401).json({ error: 'Credenciais inválidas.' });
    
    let escolaIdFinal = user.escolaId;
    const escolaVinculada = await database.collection('escola').findOne({ $or: [{ escolaId: user.escolaId }, { email: new RegExp(`^${user.login}$`, 'i') }, { donoId: user.id }] });

    if (escolaVinculada && escolaVinculada.escolaId) {
        escolaIdFinal = escolaVinculada.escolaId;
        await database.collection('usuarios').updateOne({ id: user.id }, { $set: { escolaId: escolaIdFinal } });
    } else if (!escolaIdFinal) { escolaIdFinal = user.id; }

    const token = jwt.sign({ id: user.id, tipo: user.tipo, escolaId: escolaIdFinal }, JWT_SECRET, { expiresIn: '12h' });

   // 🔥 MÁGICA: Cookies super compatíveis que não quebram ao premir F5!
    res.cookie('token_acesso', token, { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: 'lax', 
        maxAge: 12*60*60*1000, 
        path: '/' 
    });
    
    // 🔗 O CASAMENTO DE DADOS (Injeção da Turma no Workspace)
    let dadosExtras = {};
    if (user.tipo === 'Aluno' && user.alunoRefId) {
        const alunoMatriculado = await database.collection('alunos').findOne({ id: user.alunoRefId });
        if (alunoMatriculado) {
            dadosExtras.turma = alunoMatriculado.turma; // Puxa a turma exata do cadastro
            if (alunoMatriculado.turmas) dadosExtras.turmas = alunoMatriculado.turmas;
            if (alunoMatriculado.curso) dadosExtras.curso = alunoMatriculado.curso;
        }
    }

    // Envia o utilizador com a turma fundida na bagagem
    res.json({ 
        success: true, 
        usuario: { 
            ...user, 
            ...dadosExtras, // <- A mágica acontece aqui!
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

    if (!user || user.status?.toLowerCase() === 'inativo') return res.status(200).json({ success: true, message: "Link enviado." });

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
// 🔐 ROTAS DE BIOMETRIA (WEBAUTHN / PASSKEYS)
// ============================================================================

// 1. O telemóvel pede permissão para registar a biometria
router.post('/biometria/gerar-registo', async (req, res) => {
    const { login } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: login });

    if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });

    // Puxa as credenciais que este utilizador já tem registadas (se houver)
    const userPasskeys = await database.collection('biometria').find({ userId: user.id }).toArray();

    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        // ✅ A CORREÇÃO: Transforma o ID em formato binário!
        userID: new Uint8Array(Buffer.from(user.id, 'utf8')), 
        userName: user.login,
        excludeCredentials: userPasskeys.map(passkey => ({
            id: passkey.credentialID,
            type: 'public-key',
        })),
        authenticatorSelection: {
            authenticatorAttachment: 'platform', 
            userVerification: 'required',
        },
    });

    // Guardamos o "desafio" temporário na base de dados para conferir no passo seguinte
    await database.collection('usuarios').updateOne({ id: user.id }, { $set: { currentChallenge: options.challenge } });

    res.json(options);
});

// 2. O telemóvel envia a chave gerada e nós guardamos na Base de Dados
router.post('/biometria/verificar-registo', async (req, res) => {
    const { login, respostaBio } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: login });

    if (!user || !user.currentChallenge) return res.status(400).json({ error: 'Registo inválido ou expirado.' });

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: respostaBio,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: expectedOrigin,
            expectedRPID: rpID,
        });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ error: 'Falha ao verificar a biometria.' });
    }

    if (verification.verified) {
        const { registrationInfo } = verification;
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        // Guardamos a "Fechadura" da biometria na nossa tabela
        await database.collection('biometria').insertOne({
            userId: user.id,
            credentialID: Buffer.from(credentialID).toString('base64url'),
            credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
            counter,
            deviceType: registrationInfo.credentialDeviceType,
            dataCriacao: new Date().toISOString()
        });

        // Limpamos o desafio temporário
        await database.collection('usuarios').updateOne({ id: user.id }, { $unset: { currentChallenge: "" } });

        return res.json({ success: true, verified: true });
    }

    res.status(400).json({ error: 'A verificação biométrica falhou.' });
});

// 3. O Utilizador abre o site e nós enviamos um "desafio" para ele resolver com o dedo/rosto
router.post('/biometria/gerar-login', async (req, res) => {
    const { login } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: login });

    if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });

    // Vamos buscar as "Fechaduras" que este utilizador tem
    const userPasskeys = await database.collection('biometria').find({ userId: user.id }).toArray();

    if (userPasskeys.length === 0) {
        return res.status(400).json({ error: 'Nenhuma biometria registada neste aparelho.' });
    }

    const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: userPasskeys.map(passkey => ({
            id: Buffer.from(passkey.credentialID, 'base64url'),
            type: 'public-key',
        })),
        userVerification: 'required',
    });

    await database.collection('usuarios').updateOne({ id: user.id }, { $set: { currentChallenge: options.challenge } });

    res.json(options);
});

// 4. O telemóvel resolveu o desafio e nós validamos o Login!
router.post('/biometria/verificar-login', async (req, res) => {
    const { login, respostaBio } = req.body;
    const database = await connectDB();
    const user = await database.collection('usuarios').findOne({ login: login });

    if (!user || !user.currentChallenge) return res.status(400).json({ error: 'Login inválido.' });

    // Procura a "Fechadura" específica que o telemóvel usou
    const passkey = await database.collection('biometria').findOne({ 
        userId: user.id, 
        credentialID: respostaBio.id 
    });

    if (!passkey) return res.status(400).json({ error: 'Dispositivo não reconhecido.' });

    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            response: respostaBio,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: expectedOrigin,
            expectedRPID: rpID,
            authenticator: {
                credentialPublicKey: Buffer.from(passkey.credentialPublicKey, 'base64url'),
                credentialID: Buffer.from(passkey.credentialID, 'base64url'),
                counter: passkey.counter,
            },
        });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ error: 'A validação criptográfica falhou.' });
    }

    if (verification.verified) {
        // Atualiza o contador de segurança contra ataques de clonagem
        await database.collection('biometria').updateOne({ _id: passkey._id }, { $set: { counter: verification.authenticationInfo.newCounter } });
        await database.collection('usuarios').updateOne({ id: user.id }, { $unset: { currentChallenge: "" } });

        // 🔥 AQUI ENTRA A MÁGICA DO SEU LOGIN NORMAL (Espelhada para a Biometria)
        let escolaIdFinal = user.escolaId;
        const escolaVinculada = await database.collection('escola').findOne({ $or: [{ escolaId: user.escolaId }, { email: new RegExp(`^${user.login}$`, 'i') }, { donoId: user.id }] });

        if (escolaVinculada && escolaVinculada.escolaId) {
            escolaIdFinal = escolaVinculada.escolaId;
            await database.collection('usuarios').updateOne({ id: user.id }, { $set: { escolaId: escolaIdFinal } });
        } else if (!escolaIdFinal) { escolaIdFinal = user.id; }

        // GERA O TOKEN DE ACESSO
        const token = jwt.sign({ id: user.id, tipo: user.tipo, escolaId: escolaIdFinal }, JWT_SECRET, { expiresIn: '12h' });

        res.cookie('token_acesso', token, { 
            httpOnly: true, 
            secure: isProduction, 
            sameSite: 'lax', 
            maxAge: 12*60*60*1000, 
            path: '/' 
        });

        // 🔗 O CASAMENTO DE DADOS (Injeção da Turma no Workspace)
        let dadosExtras = {};
        if (user.tipo === 'Aluno' && user.alunoRefId) {
            const alunoMatriculado = await database.collection('alunos').findOne({ id: user.alunoRefId });
            if (alunoMatriculado) {
                dadosExtras.turma = alunoMatriculado.turma;
                if (alunoMatriculado.turmas) dadosExtras.turmas = alunoMatriculado.turmas;
                if (alunoMatriculado.curso) dadosExtras.curso = alunoMatriculado.curso;
            }
        }

        return res.json({ 
            success: true, 
            usuario: { 
                ...user, 
                ...dadosExtras, // <- A mágica também acontece aqui agora!
                escolaId: escolaIdFinal, 
                senha: undefined 
            } 
        });
    }

    res.status(400).json({ error: 'Falha na autenticação biométrica.' });
});

module.exports = router;