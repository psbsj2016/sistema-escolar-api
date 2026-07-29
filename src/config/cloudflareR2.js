// src/config/cloudflareR2.js
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const crypto = require("crypto");
const path = require("path");

// 1. Ligamos a ignição do nosso "Camião de Entregas" usando as chaves do .env
const r2Client = new S3Client({
    region: "auto",
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// 2. A função que faz a magia de enviar o ficheiro
const enviarParaR2 = async (fileBuffer, nomeOriginal, mimetype) => {
    try {
        // Criamos um nome único para o ficheiro não se misturar com outros (ex: pdfs/123456-trabalho.pdf)
        const hash = crypto.randomBytes(8).toString("hex");
        const extensao = path.extname(nomeOriginal);
        const nomeArquivo = `documentos/${Date.now()}-${hash}${extensao}`;

        // Preparamos o "pacote" para envio
        const comando = new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: nomeArquivo,
            Body: fileBuffer,
            ContentType: mimetype,
        });

        // Enviamos o pacote para a nuvem!
        await r2Client.send(comando);

        // Devolvemos o Link Público pronto para os alunos clicarem e lerem!
        // Retiramos a barra final do URL Público caso ela exista, para evitar erros
        const baseUrl = process.env.R2_PUBLIC_URL.replace(/\/$/, "");
        return `${baseUrl}/${nomeArquivo}`;

    } catch (error) {
        console.error("❌ Erro ao enviar ficheiro para o Cloudflare R2:", error);
        throw new Error("Falha no upload para o R2.");
    }
};

module.exports = { enviarParaR2 };