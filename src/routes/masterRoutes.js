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
    
    // Fallback caso o JWT_SECRET demore a ser lido do .env
    const segredo = process.env.JWT_SECRET || 'fallback_secret_ptt_2024_seguro';

    try {
        jwt.verify(authHeader.split(' ')[1], segredo, (err, decoded) => {
            if (err || !decoded.master) return res.status(401).json({ error: 'Acesso negado.' });
            next();
        });
    } catch (e) {
        return res.status(500).json({ error: 'Erro interno de validação.' });
    }
};

// ==========================================
// 1. LOGIN (À Prova de Falhas)
// ==========================================
router.post('/login', async (req, res) => {
    try {
        const senhaDigitada = req.body.senha;
        // Lemos as variáveis de ambiente AQUI, no momento exato do clique!
        const senhaEnv = process.env.SENHA_DONO_HASH;
        const segredo = process.env.JWT_SECRET || 'fallback_secret_ptt_2024_seguro';
        
        if (!senhaDigitada) return res.status(400).json({ error: 'Senha não fornecida.' });
        if (!senhaEnv) return res.status(500).json({ error: 'A variável SENHA_DONO_HASH não está configurada no seu servidor.' });

        let senhaValida = false;

        // 🛡️ INTELIGÊNCIA DE FALLBACK: 
        // Verifica se a senha no .env é um Hash (começa com $2) ou se é texto normal.
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
        res.status(500).json({ error: `Erro 500: ${error.message}` }); // Agora mostra o motivo exato no navegador!
    }
});

// ==========================================
// 2. LISTAR TODAS AS ESCOLAS (Ultra Segura)
// ==========================================
router.get('/ativacoes', verifyMaster, async (req, res) => {
    try {
        const database = await connectDB();
        
        const ativacoes = await database.collection('ativacoes').find({}).toArray();
        const escolas = await database.collection('escola').find({}).toArray();

        const listaFinal = [];
        const emailsProcessados = new Set(); 

        for (let a of ativacoes) {
            if (!a.email) continue;
            
            // Blindagem: Garante que é sempre String
            const email = String(a.email).toLowerCase().trim();
            const escola = escolas.find(e => e.email && String(e.email).toLowerCase().trim() === email);
            
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

        for (let e of escolas) {
            if (!e.email) continue;
            const email = String(e.email).toLowerCase().trim();
            
            if (!emailsProcessados.has(email)) {
                listaFinal.push({
                    email: email,
                    status: 'Verificado',
                    pinAtivacao: '',
                    plano: e.plano || 'Essencial'
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
// 3. GERAR PIN E MUDAR PLANO
// ==========================================
router.post('/gerar-pin', verifyMaster, async (req, res) => {
    try {
        const { email, plano } = req.body;
        if (!email || !plano) return res.status(400).json({ error: 'Dados incompletos.' });

        const database = await connectDB();
        const targetEmail = String(email).toLowerCase().trim();
        
        const prefix = String(plano).substring(0, 3).toUpperCase();
        const randomCode = crypto.randomBytes(3).toString('hex').toUpperCase();
        const pin = `${prefix}-${randomCode}`;

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
        console.error("🚨 Erro ao gerar PIN:", error.message);
        res.status(500).json({ error: 'Erro ao gerar PIN.' });
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
        await database.collection('ativacoes').updateOne({ email: target }, { $set: { status: 'Bloqueado' } });
        await database.collection('escola').updateOne({ email: target }, { $set: { plano: 'Bloqueado' } });
        res.json({ success: true });
    } catch (error) {
        console.error("🚨 Erro ao bloquear conta:", error.message);
        res.status(500).json({ error: 'Erro ao bloquear conta.' });
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
        const hoje = new Date();

        const ativacoes = await database.collection('ativacoes').find({ status: { $in: ['Ativo', 'Verificado'] } }).toArray();
        
        ativacoes.forEach(a => {
            if (!a.dataAtivacao) return; 

            const dataAtiv = new Date(a.dataAtivacao);
            if (isNaN(dataAtiv.getTime())) return;

            const diasPassados = Math.floor((hoje - dataAtiv) / (1000 * 60 * 60 * 24));
            let diasLimite = (a.plano === 'Teste') ? 7 : 30; 
            const diasRestantes = diasLimite - diasPassados;

            if (diasRestantes <= 5 && diasRestantes >= 0) {
                notificacoes.push({
                    tipo: 'aviso',
                    titulo: 'Renovação Próxima',
                    mensagem: `O plano <b>${a.plano}</b> de ${a.email} vence em ${diasRestantes} dia(s).`,
                });
            } else if (diasRestantes < 0) {
                notificacoes.push({
                    tipo: 'perigo',
                    titulo: 'Plano Vencido',
                    mensagem: `O acesso de ${a.email} venceu há ${Math.abs(diasRestantes)} dia(s).`,
                });
            }
        });

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
        console.error("🚨 Erro ao carregar notificações:", error.message);
        res.status(500).json({ error: 'Erro ao carregar alertas.' });
    }
});

module.exports = router;