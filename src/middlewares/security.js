const xss = require('xss');

// 1. A Nova Limpeza (Adeus Regex perigoso, olá xss)
const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return xss(str).trim();
};

// 2. Proteção de Objetos
const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        // Mantive a tua regra genial para proteger o 'novaSenha' e adicionei o 'token'
        sanitized[key] = (['senha', 'pin', 'novaSenha', 'token'].includes(key)) ? value : sanitizeObject(value);
    }
    return sanitized;
};

// 3. O Guarda-Costas Global
const securityMiddleware = (req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    // Bónus: Agora também limpamos os parâmetros da URL (ex: /aluno/<script>...)
    if (req.params) req.params = sanitizeObject(req.params); 
    next();
};

module.exports = { securityMiddleware, sanitizeString, sanitizeObject };