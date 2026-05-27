const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const verifyJWT = (req, res, next) => {
    // Estas rotas não precisam de login para serem acedidas
    if (req.path === '/' || req.path.startsWith('/auth/') || req.path.startsWith('/master/') || req.path.startsWith('/public/')) {
        return next();
    }
    
    const token = req.cookies.token_acesso;
    if (!token) return res.status(403).json({ error: 'Sessão não encontrada.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sessão expirada.' });
        req.userId = decoded.id;
        req.escolaId = decoded.escolaId || decoded.id;
        req.userTipo = decoded.tipo;
        next();
    });
};

function filtroTenant(req) {
    const ids = [];
    if (req.escolaId) ids.push(req.escolaId);
    if (req.userId) ids.push(req.userId);
    return {
        $or: [
            { escolaId: { $in: ids } },
            { donoId: { $in: ids } }
        ]
    };
}

module.exports = { verifyJWT, filtroTenant };