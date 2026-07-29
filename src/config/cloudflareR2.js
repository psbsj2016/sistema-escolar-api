// src/config/cloudflareR2.js
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner"); // 🚀 NOVA FERRAMENTA: A Máquina de Bilhetes
const crypto = require("crypto");
const path = require("path");

const r2Client = new S3Client({
    region: "auto",
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// A Função Antiga (Mantemos para retrocompatibilidade ou ficheiros pequenos)
const enviarParaR2 = async (fileBuffer, nomeOriginal, mimetype) => {
    try {
        const hash = crypto.randomBytes(8).toString("hex");
        const extensao = path.extname(nomeOriginal);
        const nomeArquivo = `documentos/${Date.now()}-${hash}${extensao}`;

        const comando = new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: nomeArquivo,
            Body: fileBuffer,
            ContentType: mimetype,
        });

        await r2Client.send(comando);
        const baseUrl = process.env.R2_PUBLIC_URL.replace(/\/$/, "");
        return `${baseUrl}/${nomeArquivo}`;
    } catch (error) {
        throw new Error("Falha no upload para o R2.");
    }
};

// ============================================================================
// 🚀 NOVA MAGIA DO PLANO B: GERAR BILHETE VIP (PRESIGNED URL)
// ============================================================================
const gerarLinkUploadDireto = async (nomeOriginal, mimetype) => {
    try {
        // 1. Criamos um nome seguro e único para o ficheiro gigante
        const hash = crypto.randomBytes(8).toString("hex");
        const extensao = path.extname(nomeOriginal);
        const nomeArquivo = `documentos/${Date.now()}-${hash}${extensao}`;

        // 2. Preparamos as regras do bilhete (onde vai ser guardado e qual o formato)
        const comando = new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: nomeArquivo,
            ContentType: mimetype,
        });

        // 3. A Nuvem assina o bilhete! Definimos que expira em 15 minutos (900 segundos).
        // Isto dá tempo suficiente para a internet do aluno terminar um upload grande.
        const urlUpload = await getSignedUrl(r2Client, comando, { expiresIn: 900 });
        
        // 4. Preparamos o link final público (o que ficará guardado no banco de dados para leitura)
        const baseUrl = process.env.R2_PUBLIC_URL.replace(/\/$/, "");
        const urlPublica = `${baseUrl}/${nomeArquivo}`;

        return {
            urlUpload: urlUpload,   // Link secreto usado APENAS para enviar o ficheiro
            urlPublica: urlPublica, // Link final que todos vão usar para ler o ficheiro
            nomeFinal: nomeOriginal
        };
    } catch (error) {
        console.error("❌ Erro ao gerar Presigned URL:", error);
        throw new Error("Falha na geração do Bilhete VIP para o R2.");
    }
};

module.exports = { enviarParaR2, gerarLinkUploadDireto };