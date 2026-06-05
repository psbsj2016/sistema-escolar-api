const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const connectDB = require('../config/db');
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://www.sistemaptt.com.br';
const isProduction = process.env.NODE_ENV === 'production';
const cookieDomain = isProduction ? '.sistemaptt.com.br' : undefined; // 'undefined' deixa funcionar no localhost!

// ============================================================================
// 1. ROTA: ENVIAR CÓDIGO DE CADASTRO
// ============================================================================
router.post('/enviar-codigo', async (req, res) => {
    let { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
    
    email = email.toLowerCase().trim();
    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();
    const validade = new Date(Date.now() + 10 * 60 * 1000);

    console.log(`\n==================================================`);
    console.log(`🚀 INICIANDO NOVO CADASTRO PARA: ${email}`);
    
    try {
        console.log(`⏳ PASSO 1: A tentar conectar ao servidor do Resend...`);
        const respostaResend = await resend.emails.send({
            from: 'Sistema PTT <contato@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Seu Código de Acesso',
            html: `<div style="text-align:center;"><h2>Verificação:</h2><h1>${codigoGerado}</h1><p>Expira em 10 min.</p></div>`
        });

        if (respostaResend.error) {
            console.error("🚨 PASSO 1 FALHOU - ERRO NO RESEND:", respostaResend.error);
            return res.status(500).json({ error: 'Falha no servidor de e-mail. Tente novamente.' });
        }
        console.log(`✅ PASSO 1 CONCLUÍDO: E-mail processado pelo Resend!`);

        console.log(`⏳ PASSO 2: A tentar conectar à base de dados MongoDB...`);
        const database = await connectDB();
        await database.collection('ativacoes').updateOne(
            { email }, 
            { $set: { email, codigoValidacao: codigoGerado, expiracaoCodigo: validade, status: 'Pendente' } }, 
            { upsert: true }
        );
        console.log(`✅ PASSO 2 CONCLUÍDO: Código salvo no MongoDB!`);
        
        console.log(`🎉 SUCESSO TOTAL!`);
        res.json({ success: true });
    } catch (e) { 
        console.error("🚨 EXPLODIU NO CATCH! Erro exato:", e.message);
        res.status(500).json({ error: 'Erro interno ao processar envio.' }); 
    }
});

// ============================================================================
// 2. ROTA: VALIDAR CADASTRO
// ============================================================================
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

// ============================================================================
// 3. ROTA: LOGIN
// ============================================================================
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

   // 🚀 SUBSTITUA A LINHA DO RES.COOKIE POR ESTA:
    res.cookie('token_acesso', token, { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: isProduction ? 'none' : 'lax', 
        domain: cookieDomain, 
        maxAge: 12*60*60*1000, 
        path: '/' 
    });
    
    res.json({ success: true, usuario: { ...user, escolaId: escolaIdFinal, senha: undefined } });
});

// ============================================================================
// 4. ROTA: RECUPERAR SENHA
// ============================================================================
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

        // 🛡️ O DETETOR DE ERROS
        if (respostaResend.error) {
            console.error("\n🚨 ERRO NO RESEND (Recuperação):", respostaResend.error);
            return res.status(500).json({ error: "Erro no servidor de e-mail. Tente novamente." });
        }

        console.log(`✅ Link de recuperação enviado para ${email}`);
        res.status(200).json({ success: true, message: "Enviado." });
    } catch (e) {
        console.error("Erro interno ao recuperar senha:", e);
        res.status(500).json({ error: "Erro interno ao processar pedido." });
    }
});

// ============================================================================
// 5. ROTA: REDEFINIR SENHA
// ============================================================================
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
   // 🚀 SUBSTITUA A LINHA DO CLEARCOOKIE POR ESTA:
    res.clearCookie('token_acesso', { 
        httpOnly: true, 
        secure: isProduction, 
        sameSite: isProduction ? 'none' : 'lax', 
        domain: cookieDomain, 
        path: '/' 
    });
    res.json({ success: true });
});

module.exports = router;