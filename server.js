const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Resend } = require('resend');
const jwt = require('jsonwebtoken'); // <-- O Gerador de Pulseiras VIP

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// A Senha Mestra do seu servidor (nunca a mostre a ninguém)
const JWT_SECRET = process.env.JWT_SECRET || 'chave_super_secreta_gestao_escolar_777';

// --- CONFIGURAÇÃO DE CORS REFORÇADA ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID'] 
}));

app.use(express.json({ limit: '10mb' })); 

// Conexão com o Banco de Dados (MongoDB)
const uri = process.env.MONGODB_URI;
let client;
let clientPromise;

async function connectDB() {
    if (!clientPromise) {
        client = new MongoClient(uri);
        clientPromise = client.connect();
        console.log("Iniciando conexão com o Banco de Dados Permanente...");
    }
    await clientPromise;
    return client.db('sistema-escolar');
}

// =========================================================
// MIDDLEWARE DE SEGURANÇA MÁXIMA (JWT)
// =========================================================
app.use((req, res, next) => {
    // Deixa passar livremente quem está a tentar fazer login, criar conta ou ver o logotipo da escola
    if (req.path.startsWith('/auth/') || (req.path === '/escola' && req.method === 'GET')) return next();

    // Pede a pulseira VIP (Token)
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acesso negado. Token não fornecido.' });

    const token = authHeader.split(' ')[1]; // Separa a palavra "Bearer" do token em si

    // Verifica se a pulseira é falsa ou expirou
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada ou token inválido.' });
        
        // Se for verdadeira, guardamos a identidade de forma segura no servidor!
        req.userId = decoded.id; 
        next();
    });
});

// =========================================================
// MOTOR DE E-MAILS (SAAS) E VALIDAÇÃO DE REGISTO
// =========================================================

// Cofre temporário para o código de 6 dígitos enviado por e-mail
const codigosAtivos = new Map();

// 👑 A SENHA SECRETA DO DONO DO SISTEMA (Mude se quiser)
const SENHA_DONO = process.env.SENHA_DONO || "master777"; 

app.post('/auth/enviar-codigo', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail não fornecido' });

    const codigoGerado = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        const { data, error } = await resend.emails.send({
            from: 'Sistema Escolar <nao-responda@sistemaptt.com.br>',
            to: email, 
            subject: '🔐 Seu Código - Sistema Escolar',
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; color: #333;">
                    <h2 style="color: #27ae60;">Bem-vindo ao Sistema Escolar!</h2>
                    <p>Você iniciou o cadastro para uma nova instituição.</p>
                    <p>Seu código de verificação do e-mail é:</p>
                    <h1 style="letter-spacing: 5px; color: #2c3e50; background: #f4f6f7; padding: 15px; border-radius: 8px; display: inline-block;">${codigoGerado}</h1>
                    <p style="font-size: 12px; color: #7f8c8d; margin-top: 20px;">Use este código junto com o <b>PIN Exclusivo de Liberação</b> fornecido pelo administrador para ativar a sua conta.</p>
                </div>
            `
        });

        if (error) {
            return res.status(500).json({ error: 'Erro ao disparar Resend' });
        }

        codigosAtivos.set(email, codigoGerado);
        setTimeout(() => codigosAtivos.delete(email), 10 * 60 * 1000);

        // --- MÁGICA: REGISTRA NA TABELA DO DONO COMO 'PENDENTE' (🟡) ---
        const database = await connectDB();
        const ativacao = await database.collection('ativacoes').findOne({ email: email });
        
        if (!ativacao) {
            await database.collection('ativacoes').insertOne({
                id: Date.now().toString(),
                email: email,
                status: 'Pendente',
                pinAtivacao: null, // Ainda precisa que o Dono gere!
                dataRequisicao: new Date().toLocaleDateString('pt-BR')
            });
        }

        res.json({ success: true, mensagem: 'Código enviado com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Falha no servidor' });
    }
});

app.post('/auth/validar-cadastro', async (req, res) => {
    const { email, codigo, pin } = req.body;

    if (!email || !codigo || !pin) return res.status(400).json({ error: 'Dados incompletos.' });

    const database = await connectDB();
    const ativacao = await database.collection('ativacoes').findOne({ email: email });

    // 1ª Barreira: Existe solicitação para este e-mail?
    if (!ativacao) return res.status(400).json({ error: 'E-mail não encontrado nas solicitações.' });

    // 2ª Barreira: Está bloqueado ou já ativado?
    if (ativacao.status === 'Verificado') return res.status(400).json({ error: 'Esta conta já está ativada e em uso!' });
    if (ativacao.status === 'Bloqueado') return res.status(403).json({ error: 'Cadastro bloqueado pelo administrador.' });

    // 3ª Barreira: O PIN digitado é o mesmo que o Dono gerou?
    if (!ativacao.pinAtivacao || ativacao.pinAtivacao !== pin) {
        return res.status(401).json({ error: 'O PIN Único está incorreto ou ainda não foi liberado pelo Dono.' });
    }

    // 4ª Barreira: O código do E-mail está certo?
    const codigoReal = codigosAtivos.get(email);
    if (!codigoReal || codigoReal !== codigo) {
        return res.status(401).json({ error: 'Código de e-mail inválido ou expirado.' });
    }

    codigosAtivos.delete(email); // Limpa da memória

    try {
        // MUDA O STATUS PARA VERIFICADO (🟢) E "QUEIMA" O PIN PARA NÃO SER REUTILIZADO!
        await database.collection('ativacoes').updateOne(
            { email: email }, 
            { $set: { status: 'Verificado', pinAtivacao: 'USADO E QUEIMADO' } }
        );
        
        // Garante que o Admin base existe para o login inicial
        const userExistente = await database.collection('usuarios').findOne({ login: "admin" });
        if (!userExistente) {
            const defaultAdmin = { id: Date.now().toString(), nome: "Gestor Principal", login: "admin", senha: "123", tipo: "Gestor", email: email };
            await database.collection('usuarios').insertOne(defaultAdmin);
        } else {
            await database.collection('usuarios').updateOne({ login: "admin" }, { $set: { email: email } });
        }

        res.json({ success: true, mensagem: 'Sistema ativado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao configurar a conta.' });
    }
});

// =========================================================
// 👑 ÁREA SECRETA DO DONO DO SISTEMA (MASTER)
// =========================================================

app.post('/master/login', (req, res) => {
    const { senha } = req.body;
    if (senha === SENHA_DONO) {
        const tokenMaster = jwt.sign({ master: true }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token: tokenMaster });
    } else {
        res.status(401).json({ error: 'Senha Mestra Incorreta!' });
    }
});

const masterAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Acesso negado.' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded.master) return res.status(401).json({ error: 'Sessão do dono inválida.' });
        next();
    });
};

// Puxar todos os e-mails
app.get('/master/ativacoes', masterAuth, async (req, res) => {
    const database = await connectDB();
    const lista = await database.collection('ativacoes').find({}).sort({ _id: -1 }).toArray();
    res.json(lista);
});

// Gerar o PIN Único
app.post('/master/gerar-pin', masterAuth, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    
    // Cria um PIN Único no formato ABX-9R2
    const novoPin = Math.random().toString(36).substring(2, 5).toUpperCase() + '-' + Math.random().toString(36).substring(2, 5).toUpperCase();
    
    await database.collection('ativacoes').updateOne(
        { email: email },
        { $set: { pinAtivacao: novoPin, status: 'Pendente' } }
    );
    res.json({ success: true, pin: novoPin });
});

// Botão de bloquear mal intencionados
app.post('/master/bloquear', masterAuth, async (req, res) => {
    const { email } = req.body;
    const database = await connectDB();
    await database.collection('ativacoes').updateOne(
        { email: email },
        { $set: { status: 'Bloqueado', pinAtivacao: 'BLOQUEADO' } }
    );
    res.json({ success: true });
});

// =========================================================
// ROTA SEGURA DE LOGIN
// =========================================================
app.post('/auth/login', async (req, res) => {
    const { login, senha } = req.body;
    
    if (!login || !senha) {
        return res.status(400).json({ error: 'Login e senha são obrigatórios.' });
    }

    try {
        const database = await connectDB();
        // Procura exatamente o utilizador com esse login e senha
        const usuario = await database.collection('usuarios').findOne({ login: login, senha: senha });

       if (usuario) {
            delete usuario.senha;
            delete usuario._id;
            
            // Cria a Pulseira VIP criptografada com validade de 12 horas!
            const token = jwt.sign({ id: usuario.id, tipo: usuario.tipo }, JWT_SECRET, { expiresIn: '12h' });
            
            // Devolve o utilizador E o token
            res.json({ success: true, usuario: usuario, token: token });
        } else {
            res.status(401).json({ error: 'Utilizador ou senha incorretos.' });
        }
    } catch (error) {
        console.error("Erro no login seguro:", error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// =========================================================
// ROTAS ESPECÍFICAS DE USUÁRIOS
// =========================================================
app.get('/usuarios', async (req, res) => {
    const database = await connectDB();
    let data = await database.collection('usuarios').find({}).toArray();
    if (data.length === 0) {
        // Criando o usuário inicial padrão, só que agora a senha fica no BD
        const defaultAdmin = { id: "1", nome: "Gestor Principal", login: "admin", senha: "123", tipo: "Gestor" };
        await database.collection('usuarios').insertOne(defaultAdmin);
        data = [defaultAdmin];
    }
    // IMPORTANTE DE SEGURANÇA: Não vamos enviar as senhas para o navegador em listas abertas!
    const formatted = data.map(item => { const { _id, senha, ...rest } = item; return rest; });
    res.json(formatted);
});

// =========================================================
// ROTA SEGURA PARA ATUALIZAR DADOS DA CONTA (LOGIN/SENHA/EMAIL)
// =========================================================
app.put('/usuarios/atualizar-conta', async (req, res) => {
    const { novoLogin, novoEmail, senhaAtual, novaSenha } = req.body;
    
    // O id do utilizador vem da nossa Pulseira VIP (Token JWT)
    const userId = req.userId;

    if (!senhaAtual) {
        return res.status(400).json({ error: 'A senha atual é obrigatória para autorizar alterações.' });
    }

    try {
        const database = await connectDB();
        
        // Vai ao cofre buscar o utilizador para ver a senha real dele
        const usuario = await database.collection('usuarios').findOne({ id: userId });

        // Se a senha digitada for diferente da do cofre, bloqueia!
        if (!usuario || usuario.senha !== senhaAtual) {
            return res.status(401).json({ error: 'Senha atual incorreta.' });
        }

        // Prepara a sacola de atualizações
        const atualizacoes = {};
        if (novaSenha) atualizacoes.senha = novaSenha;
        if (novoEmail) atualizacoes.email = novoEmail; // Guarda o E-MAIL
        
        if (novoLogin && novoLogin !== usuario.login) {
            // Verifica se alguém já está usando esse novo login
            const loginExistente = await database.collection('usuarios').findOne({ login: novoLogin, id: { $ne: userId } });
            if (loginExistente) {
                return res.status(400).json({ error: 'Este login já está em uso por outro usuário.' });
            }
            atualizacoes.login = novoLogin;
        }

        // Se não houver nada para atualizar, avisa
        if (Object.keys(atualizacoes).length === 0) {
             return res.status(400).json({ error: 'Nenhuma alteração foi solicitada.' });
        }

        // Aplica as atualizações no banco de dados
        await database.collection('usuarios').updateOne(
            { id: userId },
            { $set: atualizacoes }
        );

        res.json({ success: true, mensagem: 'Conta atualizada com sucesso!' });
    } catch (error) {
        console.error("Erro ao atualizar conta:", error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// =========================================================
// ROTAS DA ESCOLA
// =========================================================
app.get('/escola', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection('escola').findOne({}) || {};
    delete data._id;
    res.json(data);
});

app.put('/escola', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    await database.collection('escola').updateOne({}, { $set: body }, { upsert: true });
    res.json(body);
});

// =========================================================
// ROTAS GENÉRICAS (MANTIDAS NO FINAL)
// =========================================================
app.get('/:collection', async (req, res) => {
    if(req.params.collection === 'escola' || req.params.collection === 'usuarios') return;
    const database = await connectDB();
    let query = {};
    if (req.userId) query.donoId = req.userId;
    const data = await database.collection(req.params.collection).find(query).toArray();
    const formatted = data.map(item => { const { _id, ...rest } = item; return rest; });
    res.json(formatted);
});

app.get('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    const data = await database.collection(req.params.collection).findOne({ id: req.params.id });
    if(data) delete data._id;
    res.json(data || {});
});

app.post('/:collection', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    if (!body.id) body.id = Date.now().toString() + Math.floor(Math.random()*1000);
    if (req.params.collection !== 'usuarios' && req.userId) body.donoId = req.userId;
    await database.collection(req.params.collection).insertOne(body);
    delete body._id;
    res.json(body);
});

app.put('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    const body = { ...req.body };
    delete body._id;
    await database.collection(req.params.collection).updateOne({ id: req.params.id }, { $set: body }, { upsert: true });
    res.json(body);
});

app.delete('/:collection/:id', async (req, res) => {
    const database = await connectDB();
    await database.collection(req.params.collection).deleteOne({ id: req.params.id });
    res.json({ success: true });
});

// Inicialização Correta
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`API Blindada rodando na porta ${PORT} com Resend e JWT!`); });