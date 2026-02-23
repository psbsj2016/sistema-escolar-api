const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const cors = require('cors');

server.use(cors());
server.use(middlewares);
server.use(jsonServer.bodyParser);

// --- LÓGICA DE SEGURANÇA E ISOLAMENTO (MULTI-TENANT) ---
server.use((req, res, next) => {
    // 1. Permite login e criação de conta sem travas
    if (req.path === '/usuarios' || req.path === '/escola') {
        next();
        return;
    }

    // 2. Verifica quem está acessando
    const userId = req.headers['x-user-id'];

    if (req.method === 'POST') {
        // Ao salvar algo novo, carimba com o ID do dono
        req.body.donoId = userId;
    }

    if (req.method === 'GET' && userId) {
        // Ao buscar dados, força o filtro para trazer só o que é do dono
        // Exceto se for buscar um ID específico
        if (req.query) {
            req.query.donoId = userId;
        }
    }
    
    next();
});

server.use(router);
server.listen(3000, () => {
    console.log('API Escolar rodando com Isolamento de Dados!');
});