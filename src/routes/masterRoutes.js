const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); 
const connectDB = require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET;
const SENHA_DONO_HASH = process.env.SENHA_DONO_HASH; 

// 🛡️ Middleware de Segurança do Master
const verifyMaster = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Não autorizado.' });
    jwt.verify(authHeader.split(' ')[1], JWT_SECRET, (err, decoded) => {
        if (err || !decoded.master) return res.status(401).json({ error: 'Acesso negado.' });
        next();
    });
};

// ==========================================
// 1. LOGIN
// ==========================================
router.post('/login', async (req, res) => {
    try {
        const senhaDigitada = req.body.senha;
        const senhaValida = await bcrypt.compare(senhaDigitada, SENHA_DONO_HASH);

        if (senhaValida) {
            const token = jwt.sign({ master: true }, JWT_SECRET, { expiresIn: '2h' });
            return res.json({ success: true, token });
        }
        res.status(401).json({ error: 'Senha incorreta.' });
    } catch (error) {
        console.error("Erro na rota master:", error);
        res.status(500).json({ error: 'Erro interno.' });
    }
});

// ==========================================
// 2. 🟢 NOVA ROTA: LISTAR TODAS AS ESCOLAS (Ultra Segura)
// ==========================================
router.get('/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        
        // Puxa tudo sem filtros
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();

        const listaFinal = [];
        const emailsProcessados = new Set(); // Evita duplicados

        // 1. Processa a lista principal de ativações
        for (let a of ativacoes) {
            if (!a.email) continue;
            const email = a.email.toLowerCase().trim();
            
            const escola = escolas.find(e => e.email && e.email.toLowerCase().trim() === email);
            
            // Padroniza status velhos ou confusos para a linguagem do painel
            let statusFinal = a.status || 'Pendente';
            if (statusFinal === 'Ativo') statusFinal = 'Verificado';

            listaFinal.push({
                email: email,
                status: statusFinal,
                pinAtivacao: a.pinAtivacao || '',
                plano: (escola && escola.plano) ? escola.plano : (a.plano || 'Pendente')
            });
            
            emailsProcessados.add(email);
        }

        // 2. Resgata escolas antigas que sumiram da tabela de ativações
        for (let e of escolas) {
            if (!e.email) continue;
            const email = e.email.toLowerCase().trim();
            
            if (!emailsProcessados.has(email)) {
                listaFinal.push({
                    email: email,
                    status: 'Verificado', // Se tem escola formada, já foi verificado
                    pinAtivacao: '',
                    plano: e.plano || 'Essencial'
                });
                emailsProcessados.add(email);
            }
        }

        console.log(`\n📡 MASTER: Enviando ${listaFinal.length} registros para o Painel.`);
        res.json(listaFinal);
        
    } catch (error) {
        console.error("🚨 Erro Crítico ao puxar ativações:", error);
        res.status(500).json({ error: 'Erro interno.' });
    }
});

// ==========================================
// 3. 🟢 NOVA ROTA: GERAR PIN E MUDAR PLANO
// ==========================================
router.post('/gerar-pin', verifyMaster, async (req, res) => {
    try {
        const { email, plano } = req.body;
        if (!email || !plano) return res.status(400).json({ error: 'Dados incompletos.' });

        const database = await connectDB();
        const targetEmail = email.toLowerCase().trim();
        
        // Gera um PIN VIP (Ex: PRO-A1B2C)
        const prefix = plano.substring(0, 3).toUpperCase();
        const randomCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const pin = `${prefix}-${randomCode}`;

        // 🚀 AQUI ESTAVA O SEGREDO: Atualiza para um status claro
        await database.collection('ativacoes').updateOne(
            { email: targetEmail },
            { $set: { email: targetEmail, plano: plano, pinAtivacao: pin, status: 'Aguardando Ativação' } },
            { upsert: true }
        );

        await database.collection('escola').updateOne(
            { email: targetEmail },
            { $set: { plano: plano } },
            { upsert: true } 
        );

        res.json({ success: true, pin });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao gerar PIN.' });
    }
});

// ==========================================
// 4. BLOQUEAR CONTA
// ==========================================
router.post('/bloquear', verifyMaster, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    await database.collection('ativacoes').updateOne({ email: email.toLowerCase() }, { $set: { status: 'Bloqueado' } });
    await database.collection('escola').updateOne({ email: email.toLowerCase() }, { $set: { plano: 'Bloqueado' } });
    res.json({ success: true });
});

// ==========================================
// 5. OBLITERAR CONTA
// ==========================================
router.post('/excluir-conta', verifyMaster, async (req, res) => {
    const { email } = req.body;
    const target = email.toLowerCase().trim();
    const database = await connectDB();
    const escola = await database.collection('escola').findOne({ email: target });
    const id = escola?.escolaId;

    if (id) {
        const colecoes = ['alunos', 'turmas', 'cursos', 'financeiro', 'eventos', 'chamadas', 'avaliacoes', 'usuarios', 'estoques', 'contratos', 'notificacoes'];
        for (const col of colecoes) await database.collection(col).deleteMany({ escolaId: id });
    }
    await database.collection('escola').deleteOne({ email: target });
    await database.collection('usuarios').deleteMany({ login: target });
    await database.collection('ativacoes').deleteOne({ email: target });
    res.json({ success: true, message: 'Conta obliterada.' });
});

// ==========================================
// 6. 🔔 NOVA ROTA: NOTIFICAÇÕES MASTER
// ==========================================
router.get('/notificacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        const notificacoes = [];
        const hoje = new Date();

        // 1. Verificar Planos Expirando (Escolas Ativas)
        const ativacoes = await database.collection('ativacoes').find({ status: { $in: ['Ativo', 'Verificado'] } }).toArray();
        
        ativacoes.forEach(a => {
            if (!a.dataAtivacao) return; // Se não tem data, ignoramos por agora

            const dataAtiv = new Date(a.dataAtivacao);
            const diasPassados = Math.floor((hoje - dataAtiv) / (1000 * 60 * 60 * 24));
            
            // Regra de validade (Pode alterar consoante a sua regra de negócio)
            let diasLimite = 30; // Planos pagos: 30 dias
            if (a.plano === 'Teste') diasLimite = 7; // Teste: 7 dias

            const diasRestantes = diasLimite - diasPassados;

            // Se faltam 5 dias ou menos para vencer
            if (diasRestantes <= 5 && diasRestantes >= 0) {
                notificacoes.push({
                    tipo: 'aviso',
                    titulo: 'Renovação Próxima',
                    mensagem: `O plano <b>${a.plano}</b> de ${a.email} vence em ${diasRestantes} dia(s).`,
                });
            } 
            // Se já passou da data limite
            else if (diasRestantes < 0) {
                notificacoes.push({
                    tipo: 'perigo',
                    titulo: 'Plano Vencido',
                    mensagem: `O acesso de ${a.email} venceu há ${Math.abs(diasRestantes)} dia(s).`,
                });
            }
        });

        // 2. Verificar novos cadastros Aguardando PIN
        const pendentes = await database.collection('ativacoes').find({ status: { $in: ['Pendente', 'Aguardando', 'Aguardando Ativação'] } }).toArray();
        pendentes.forEach(p => {
            notificacoes.push({
                tipo: 'info',
                titulo: 'Novo Cliente',
                mensagem: `A escola ${p.email} pediu acesso e aguarda a geração do PIN.`,
            });
        });

        res.json(notificacoes);
    } catch (error) {
        console.error("Erro ao carregar notificações:", error);
        res.status(500).json({ error: 'Erro ao carregar alertas.' });
    }
});

module.exports = router;