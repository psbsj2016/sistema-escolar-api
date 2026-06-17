const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');

const rateLimit = require('express-rate-limit');
require('dotenv').config();

const connectDB = require('./src/config/db');
const { securityMiddleware } = require('./src/middlewares/security');
const { verifyJWT } = require('./src/middlewares/auth');

// Rotas Modulares
const authRoutes = require('./src/routes/authRoutes');
const publicRoutes = require('./src/routes/publicRoutes');
const masterRoutes = require('./src/routes/masterRoutes');
const escolaRoutes = require('./src/routes/escolaRoutes');
const usuariosRoutes = require('./src/routes/usuariosRoutes');
const dataRoutes = require('./src/routes/dataRoutes');
const workspaceRoutes = require('./src/routes/workspaceRoutes');

const app = express();
app.set('trust proxy', 1);

// Segurança e CORS
app.use(helmet({ crossOriginResourcePolicy: false }));

const dominiosPermitidos = ['https://www.sistemaptt.com.br', 'https://sistemaptt.com.br', 'http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5500', 'null'];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || dominiosPermitidos.includes(origin)) callback(null, true);
        else callback(new Error('Acesso negado (CORS).'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true 
}));

app.use((req, res, next) => {
    const origin = req.headers.origin;
    res.header("Access-Control-Allow-Origin", origin && dominiosPermitidos.includes(origin) ? origin : "https://www.sistemaptt.com.br");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// Middlewares (CRUCIAL: Têm de vir antes das rotas!)
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(securityMiddleware);

// Limites de Tráfego (Anti-DDoS)
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 800, message: { error: 'Tráfego excessivo.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { error: 'Tentativas excessivas.' } });

app.use((req, res, next) => {
    if (req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/escola/') || req.path === '/') return next();
    return globalLimiter(req, res, next);
});

// Aplica limite rígido nas rotas de tentativa de senha
app.use('/auth/login', authLimiter);
app.use('/master/login', authLimiter);
app.use('/auth/recuperar-senha', authLimiter);
app.use('/auth/redefinir-senha', authLimiter);

// =========================================================
// 🔓 ROTAS PÚBLICAS (Não exigem login/token)
// =========================================================
app.get('/', (req, res) => res.status(200).json({ status: "online", message: "API Sistema Escolar PTT Modular 🚀" }));

app.use('/auth', authRoutes);       // Login, Cadastro, Recuperar Senha
app.use('/public', publicRoutes);   // Matrículas Externas (Carnês/PDFs)
app.use('/master', masterRoutes);   // Login do Admin Master


// =========================================================
// 🛡️ GUARDA DE SEGURANÇA (A partir daqui, só entra logado!)
// =========================================================
app.use(verifyJWT); 


// =========================================================
// 🔒 ROTAS PROTEGIDAS (Exigem token válido)
// =========================================================
app.use('/escola', escolaRoutes);
app.use('/usuarios', usuariosRoutes); 
app.use('/workspace', workspaceRoutes); // 🔥 Corrigido: Agora sim o workspace consegue ler dados, ficheiros e sessões seguras!
app.use('/', dataRoutes); // CRUD no final para não colidir

// =========================================================
// 🚀 INICIALIZAÇÃO DO SERVIDOR
// =========================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`🚀 API Sistema Escolar Modular na porta ${PORT}`);
    await connectDB();
});