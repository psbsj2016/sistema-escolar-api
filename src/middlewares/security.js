const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/onerror\s*=/gi, '')
        .replace(/onclick\s*=/gi, '')
        .replace(/onload\s*=/gi, '')
        .replace(/onmouseover\s*=/gi, '')
        .replace(/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, '')
        .replace(/<object[\s\S]*?>[\s\S]*?<\/object>/gi, '')
        .replace(/<embed[\s\S]*?>[\s\S]*?<\/embed>/gi, '')
        .replace(/<link[\s\S]*?>/gi, '')
        .replace(/<meta[\s\S]*?>/gi, '')
        .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
        .replace(/expression\s*\(/gi, '')
        .trim();
};

const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = (['senha', 'pin', 'novaSenha'].includes(key)) ? value : sanitizeObject(value);
    }
    return sanitized;
};

const securityMiddleware = (req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    next();
};

module.exports = { securityMiddleware, sanitizeString };