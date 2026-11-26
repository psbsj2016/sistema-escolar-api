const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');
const webpush = require('web-push');

const { Resend } = require('resend');

// Inicialize o Resend com a chave segura do .env
const resend = new Resend(process.env.RESEND_API_KEY); 

// 🔑 Configuração do Web Push para Alertas Instantâneos
webpush.setVapidDetails(
    'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

// ============================================================================
// 🖍️ ROTA OFICIAL DA LOUSA DIGITAL
// ============================================================================
const path = require('path');
const fs = require('fs');

router.get(['/workspace-lousa', '/workspace-lousa.html'], (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const pathDist = path.join(__dirname, '../dist/workspace-lousa.html');
    const pathFront = path.join(__dirname, '../frontend/workspace-lousa.html');
    if (fs.existsSync(pathFront)) return res.sendFile(pathFront);
    return res.sendFile(pathDist);
});

router.get(['/workspace-aulas-video', '/workspace-aulas-video.html'], (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const pathFront = path.join(__dirname, '../frontend/workspace-aulas-video.html');
    const pathDist = path.join(__dirname, '../dist/workspace-aulas-video.html');
    if (fs.existsSync(pathFront)) return res.sendFile(pathFront);
    return res.sendFile(pathDist);
});

// ============================================================================
// 📄 FUNÇÕES GERADORAS DE PDF (VIA API EXTERNA - API2PDF)
// ============================================================================

async function gerarPdfBuffer(htmlContent) {
    console.log("⏳ Solicitando PDF ultra-rápido à API2PDF...");
    
    // O fetch nativo do Node.js envia o HTML para a nuvem da API2PDF
    const response = await fetch('https://v2.api2pdf.com/chrome/pdf/html', {
        method: 'POST',
        headers: {
            'Authorization': process.env.API2PDF_KEY, // A chave que colocou no Render
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            html: htmlContent,
            inline: true,
            options: {
                printBackground: true,
                marginTop: 0.4, // Aproximadamente 10mm
                marginBottom: 0.4,
                marginLeft: 0.4,
                marginRight: 0.4
            }
        })
    });

    const data = await response.json();
    
    if (!data.FileUrl) {
        console.error("🚨 Erro da API2PDF:", data);
        throw new Error("Falha ao processar o PDF na nuvem.");
    }

    console.log("✅ PDF gerado na nuvem! Fazendo download do documento...");
    
    // Transforma o link recebido num ficheiro digital (Buffer) para o Resend
    const pdfResponse = await fetch(data.FileUrl);
    const arrayBuffer = await pdfResponse.arrayBuffer();
    return Buffer.from(arrayBuffer);
}

// 🎨 CONSTRUTOR DO HTML DO CARNÊ (Idêntico ao financeiro.js + CNPJ)
function montarHtmlCarnesOficial(parcelas, nomeAluno, escola) {
    const nomeEscola = escola.nome || 'INSTITUIÇÃO';
    const bancoNome = escola.banco || 'Não Configurado';
    const chavePix = escola.chavePix || 'Não Configurada';
    
    const imgLogo = escola.foto ? `<img src="${escola.foto}" style="max-height:30px; object-fit:contain;">` : `<div style="font-size:11px; font-weight:bold;">${nomeEscola}</div>`;
    const cnpjCanhoto = escola.cnpj ? `<div style="font-size: 8px; color: #555; margin-top: 3px; font-weight: bold;">CNPJ: ${escola.cnpj}</div>` : '';
    
    const qrCodeUrl = (escola.qrCodeImagem && escola.qrCodeImagem.length > 50 && !escola.qrCodeImagem.includes('placehold')) 
        ? escola.qrCodeImagem 
        : `https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=${encodeURIComponent(chavePix)}`;

    const estilo = `
        <style>
            body { background: white; margin: 0; padding: 0; font-family: Arial, sans-serif; }
            .carnes-container { width: 100%; max-width: 210mm; margin: 0 auto; }
            .carne-wrapper { 
                display: flex; border: 1px solid #000; margin: 0 auto 5mm auto; 
                background: #fff; color: #000; border-radius: 8px; overflow: hidden; 
                width: 100%; height: 65mm; box-sizing: border-box;
                page-break-inside: avoid;
            }
            .carne-canhoto { width: 28%; border-right: 2px dashed #999; padding: 8px; display: flex; flex-direction: column; background: #fafafa; }
            .carne-recibo { width: 72%; padding: 6px 15px; display: flex; flex-direction: column; position: relative; }
            * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
        </style>
    `;

    const carnesHTML = parcelas.map((p) => {
        const dataVenc = p.vencimento.split('-').reverse().join('/');
        const valorF = parseFloat(p.valor).toLocaleString('pt-BR', {minimumFractionDigits: 2});
        const nossoNumero = p.id.slice(-8).toUpperCase();
        const primeiroNomeAluno = nomeAluno.split(' ')[0];

        return `
        <div class="carne-wrapper">
            <div class="carne-canhoto">
                <div style="border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-bottom: 5px; text-align: center; display: flex; flex-direction: column; align-items: center;">
                    ${imgLogo}
                    ${cnpjCanhoto}
                </div>
                <div style="font-size: 10px; margin-bottom: 3px;"><b>Parcela:</b> ${p.descricao}</div>
                <div style="font-size: 10px; margin-bottom: 3px;"><b>Vencimento:</b> <span style="color: red; font-weight: bold;">${dataVenc}</span></div>
                <div style="font-size: 10px; margin-bottom: 3px;"><b>Valor:</b> R$ ${valorF}</div>
                <div style="margin-top: auto; font-size: 9px; border-top: 1px solid #ccc; padding-top: 5px;"><b>Sacado:</b> ${primeiroNomeAluno}</div>
            </div>
            <div class="carne-recibo">
                <div style="display: flex; justify-content: space-between; border-bottom: 2px solid #333; padding-bottom: 4px; margin-bottom: 6px;">
                    <div><div style="font-weight: bold; font-size: 12px;">${nomeEscola}</div><div style="font-size: 9px;">Banco: ${bancoNome}</div></div>
                    <div style="text-align: right; font-size: 10px; font-weight: bold;">RECIBO DO PAGADOR</div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px; background: #fdfdfd; border: 1px solid #ddd; padding: 4px 10px;">
                    <div><div style="font-size: 9px; color: #777;">Nosso Número</div><div style="font-weight: bold; font-size: 12px;">${nossoNumero}</div></div>
                    <div><div style="font-size: 9px; color: #777;">Vencimento</div><div style="font-weight: bold; font-size: 12px; color: #c0392b;">${dataVenc}</div></div>
                    <div><div style="font-size: 9px; color: #777;">Valor</div><div style="font-weight: bold; font-size: 12px;">R$ ${valorF}</div></div>
                </div>
                <div style="font-size: 10px; margin-bottom: 5px;"><b>Ref:</b> ${p.descricao} | <b>Pagador:</b> ${nomeAluno}</div>
                <div style="display: flex; justify-content: space-between; align-items: flex-end;">
                    <div>
                        <div style="font-size: 10px; font-weight: bold; color:#27ae60;">PAGAMENTO VIA PIX</div>
                        <div style="background: #eee; padding: 4px 6px; border-radius: 4px; font-size: 10px; word-break: break-all;">🔑 ${chavePix}</div>
                    </div>
                    <div style="display: flex; flex-direction: column; align-items: center;">
                        <img src="${qrCodeUrl}" style="width: 60px; height: 60px; object-fit: contain; border: 1px solid #ccc; border-radius: 4px; padding: 2px;">
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');

    return `<html><head><meta charset="UTF-8">${estilo}</head><body><div class="carnes-container">${carnesHTML}</div></body></html>`;
}

// 🔐 FUNÇÃO DETERMINÍSTICA DE HASH SHA-256 (PROVA DE IMUTABILIDADE)
function gerarHashContrato({ idContrato, escolaId, nome, cpf, email, planoCurso, conteudoHTML, assinaturaAluno, dataUTC }) {
    const base = [
        String(idContrato || ''),
        String(escolaId || ''),
        String(nome || '').trim().toUpperCase(),
        String(cpf || '').replace(/\D/g, ''),
        String(email || '').trim().toLowerCase(),
        String(planoCurso || '').trim(),
        String(conteudoHTML || ''),
        String(assinaturaAluno || ''),
        String(dataUTC || '')
    ].join('|');
    return crypto.createHash('sha256').update(base, 'utf8').digest('hex');
}

function mascararCPF(cpf) {
    const dig = String(cpf || '').replace(/\D/g, '');
    if (dig.length === 11) return `***.${dig.slice(3, 6)}.${dig.slice(6, 9)}-**`;
    return dig ? '***' + dig.slice(-3) : 'Não informado';
}

function mascararEmail(email) {
    const str = String(email || '').trim();
    const partes = str.split('@');
    if (partes.length !== 2) return 'Não informado';
    const inicio = partes[0].slice(0, 2);
    return `${inicio}***@${partes[1]}`;
}

function mascararIP(ip) {
    const str = String(ip || '').trim();
    if (!str) return 'Não registrado';
    if (str.includes('.')) {
        const p = str.split('.');
        return p.length === 4 ? `${p[0]}.${p[1]}.***.***` : `${str.slice(0, 6)}***`;
    }
    return `${str.slice(0, 8)}***`;
}

// 🎨 CONSTRUTOR DO HTML DO CONTRATO COMPLETO (COM ASSINATURAS, QR CODE E AUDITORIA)
function montarHtmlContratoOficial(conteudoHTML, escola, dados, metaJuridica = {}) {
    const imgLogo = escola.foto ? `<img src="${escola.foto}" style="max-height:80px; margin-bottom: 5px;">` : `<h2 style="margin:0; color:#2c3e50;">${escola.nome || 'INSTITUIÇÃO'}</h2>`;
    const cnpjDiv = escola.cnpj ? `<div style="font-size: 13px; color: #555; font-weight: bold;">CNPJ: ${escola.cnpj}</div>` : '';

    const cabecalhoEscola = `
        <div style="text-align:center; margin-bottom:20px;">
            ${imgLogo}
            ${cnpjDiv}
        </div>
    `;

    const dataNascimentoF = dados.nascimento ? dados.nascimento.split('-').reverse().join('/') : 'Não informado';
    const telefone = dados.telefone || dados.whatsapp || dados.celular || 'Não informado';
    const endereco = `${dados.rua || ''}, Nº ${dados.numero || 'S/N'} ${dados.complemento ? ' - ' + dados.complemento : ''}`;

    const fusoBR = { timeZone: 'America/Sao_Paulo' };
    const dataRef = metaJuridica.dataUTC ? new Date(metaJuridica.dataUTC) : new Date();
    const dataAtual = dataRef.toLocaleDateString('pt-BR', fusoBR);
    const horaAtual = dataRef.toLocaleTimeString('pt-BR', fusoBR);

    const idTransacao = metaJuridica.idContrato || '';
    const hashSha = metaJuridica.hashSha256 || '';
    const urlValidacao = idTransacao
        ? `https://www.sistemaptt.com.br/validar-contrato?id=${encodeURIComponent(idTransacao)}`
        : 'https://www.sistemaptt.com.br/validar-contrato';
    const qrValidacaoUrl = `https://api.qrserver.com/v1/create-qr-code/?size=130x130&data=${encodeURIComponent(urlValidacao)}`;

    const assinaturaAlunoImg = metaJuridica.assinaturaAluno
        ? `<img src="${metaJuridica.assinaturaAluno}" style="max-height:70px; max-width:230px; object-fit:contain; display:block; margin:0 auto 4px auto;">`
        : `<div style="height:55px;"></div>`;

    const assinaturaInstImg = metaJuridica.assinaturaInstituicao
        ? `<img src="${metaJuridica.assinaturaInstituicao}" style="max-height:70px; max-width:230px; object-fit:contain; display:block; margin:0 auto 4px auto;">`
        : `<div style="display:inline-block; border:1px dashed #2c3e50; padding:6px 12px; border-radius:6px; font-size:10px; color:#2c3e50; font-weight:bold; margin-bottom:6px;">
             ASSINATURA INSTITUCIONAL DIGITAL<br>${escola.nome || 'INSTITUIÇÃO'}${escola.cnpj ? ' • ' + escola.cnpj : ''}
           </div>`;

    const nomeRep = metaJuridica.representanteNome || escola.representanteNome || escola.nome || 'Instituição';
    const cargoRep = metaJuridica.representanteCargo || escola.representanteCargo || 'Representante Legal';
    const aud = metaJuridica.auditoria || {};

    return `
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 0; background: white; }
                .contrato-container { width: 100%; max-width: 800px; margin: 0 auto; }
                h1, h2, h3 { color: #2c3e50; }
                .ficha-box { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: #fcfcfc; margin-bottom: 24px; }
                .ficha-titulo { background: #2c3e50; color: white; padding: 8px 15px; border-radius: 5px; font-size: 14px; text-transform: uppercase; margin-top: 0; margin-bottom: 15px; }
                .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; font-size: 13px; }
                .linha-dado { border-bottom: 1px dashed #eee; padding-bottom: 5px; }
                .label { font-weight: bold; color: #666; font-size: 11px; text-transform: uppercase; display: block; }
                .valor { font-size: 14px; font-weight: bold; color: #222; }
                .clausulas { font-size: 12px; text-align: justify; line-height: 1.5; margin-top: 22px; }
                .assinaturas-grid { display: flex; justify-content: space-between; align-items: flex-end; gap: 25px; margin-top: 35px; text-align: center; page-break-inside: avoid; }
                .assinatura-col { flex: 1; }
                .linha-ass { border-top: 1px solid #333; padding-top: 6px; font-size: 12px; }
                .cert-box { margin-top: 26px; border: 1.5px solid #27ae60; background: #f0fdf4; border-radius: 8px; padding: 14px; display: flex; align-items: center; gap: 15px; page-break-inside: avoid; }
                .cert-dados { flex: 1; font-size: 10.5px; color: #1e293b; line-height: 1.5; word-break: break-all; }
            </style>
        </head>
        <body>
            <div class="contrato-container">
                ${cabecalhoEscola}
                <h2 style="text-align: center; margin-bottom: 5px; text-transform: uppercase;">Contrato de Prestação de Serviços Educacionais</h2>
                <div style="text-align: center; font-size: 12px; color: #666; margin-bottom: 22px;">Documento gerado e assinado eletronicamente em ${dataAtual} às ${horaAtual} (Horário de Brasília)</div>

                <div class="ficha-box">
                    <h3 class="ficha-titulo">📝 Ficha de Matrícula e Dados do Contratante</h3>
                    <div class="grid-2">
                        <div class="linha-dado"><span class="label">Nome Completo</span><span class="valor">${dados.nome || 'Não informado'}</span></div>
                        <div class="linha-dado"><span class="label">E-mail</span><span class="valor">${dados.email || 'Não informado'}</span></div>
                    </div>
                    <div class="grid-2">
                        <div class="linha-dado"><span class="label">CPF</span><span class="valor">${dados.cpf || 'Não informado'}</span></div>
                        <div class="linha-dado"><span class="label">RG</span><span class="valor">${dados.rg || 'Não informado'}</span></div>
                    </div>
                    <div class="grid-2">
                        <div class="linha-dado"><span class="label">Data de Nascimento</span><span class="valor">${dataNascimentoF}</span></div>
                        <div class="linha-dado"><span class="label">Telefone / WhatsApp</span><span class="valor">${telefone}</span></div>
                    </div>
                    <div style="margin-top: 12px;" class="linha-dado">
                        <span class="label">Endereço Completo</span>
                        <span class="valor">${endereco} - Bairro: ${dados.bairro || ''} - ${dados.cidade || ''}/${dados.estado || ''}</span>
                    </div>
                    <div class="grid-2" style="margin-top: 12px;">
                        <div class="linha-dado"><span class="label">Curso / Plano Contratado</span><span class="valor" style="color: #27ae60;">${dados.planoCurso || 'Não informado'}</span></div>
                        <div class="linha-dado"><span class="label">Dia de Vencimento</span><span class="valor">Todo dia ${dados.diaVencimento || '10'}</span></div>
                    </div>
                </div>

                <div class="clausulas">
                    ${conteudoHTML || '<p><em>Nenhuma cláusula contratual adicional foi cadastrada.</em></p>'}
                </div>

                <div class="assinaturas-grid">
                    <div class="assinatura-col">
                        ${assinaturaAlunoImg}
                        <div class="linha-ass">
                            <b>${dados.resp_nome || dados.nome || 'Contratante'}</b><br>
                            <span style="color:#555; font-size:10.5px;">Assinatura do Responsável / Aluno</span>
                        </div>
                    </div>
                    <div class="assinatura-col">
                        ${assinaturaInstImg}
                        <div class="linha-ass">
                            <b>${nomeRep}</b><br>
                            <span style="color:#555; font-size:10.5px;">${cargoRep} — Assinatura da Instituição</span>
                        </div>
                    </div>
                </div>

                <div class="cert-box">
                    <div style="text-align:center; flex-shrink:0;">
                        <img src="${qrValidacaoUrl}" style="width:105px; height:105px; border:1px solid #cbd5e1; border-radius:6px; background:#fff; padding:3px;">
                        <div style="font-size:8.5px; color:#15803d; font-weight:bold; margin-top:3px;">Validar via QR Code</div>
                    </div>
                    <div class="cert-dados">
                        <div style="font-size:12px; font-weight:bold; color:#15803d; margin-bottom:4px;">✅ CERTIFICADO DE ASSINATURA ELETRÔNICA (MP nº 2.200-2/2001 e Lei nº 14.063/2020)</div>
                        <div><b>ID da Transação:</b> ${idTransacao || 'N/A'}</div>
                        <div><b>Hash SHA-256 (Integridade):</b> <span style="font-family:monospace;">${hashSha || 'N/A'}</span></div>
                        <div><b>Data/Hora do Servidor:</b> ${dataAtual} às ${horaAtual} (UTC: ${aud.dataUTC || dataRef.toISOString()})</div>
                        <div><b>Autenticação de Autoria:</b> ${aud.otpVerificado ? '✅ Código OTP de 6 dígitos confirmado via e-mail' : 'Aceite eletrônico registrado'} • <b>IP:</b> ${aud.ip || 'Registrado'}</div>
                        <div><b>Conferência Pública:</b> ${urlValidacao}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `;
}

// ============================================================================
// 🌐 ROTAS DA API
// ============================================================================

router.get('/escola/:id', async (req, res) => {
    try {
        const database = await connectDB();
        const schoolIdClean = req.params.id ? req.params.id.trim() : '';
        const escola = await database.collection('escola').findOne({ escolaId: schoolIdClean });
        if (!escola) return res.status(404).json({ error: 'Escola não encontrada.' });

            res.json({
            escolaId: escola.escolaId,
            configMatricula: escola.configMatricula || null,
            configHub: escola.configHub || null 
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar matrícula.' });
    }
});

// ============================================================================
// 🔐 ENVIO DE CÓDIGO OTP DE 6 DÍGITOS POR E-MAIL PARA ASSINATURA DO CONTRATO
// ============================================================================
router.post('/enviar-codigo-contrato', async (req, res) => {
    try {
        const database = await connectDB();
        const { escolaId, email, nome } = req.body || {};
        const emailLimpo = String(email || '').trim().toLowerCase();

        if (!emailLimpo || !emailLimpo.includes('@')) {
            return res.status(400).json({ success: false, error: 'Informe um e-mail válido para receber o código de assinatura.' });
        }

        const escola = escolaId
            ? (await database.collection('escola').findOne({ escolaId: String(escolaId).trim() }) || {})
            : {};

        const codigo = String(Math.floor(100000 + Math.random() * 900000));
        const expiraEm = new Date(Date.now() + 15 * 60 * 1000); // Válido por 15 minutos

        await database.collection('otp_contratos').deleteMany({ email: emailLimpo, escolaId: String(escolaId || '') });
        await database.collection('otp_contratos').insertOne({
            escolaId: String(escolaId || ''),
            email: emailLimpo,
            codigo,
            usado: false,
            criadoEm: new Date(),
            expiraEm
        });

        const nomeEscola = escola.nome || 'Instituição de Ensino';
        const resp = await resend.emails.send({
            from: 'Matriculas <contato@sistemaptt.com.br>',
            to: emailLimpo,
            subject: `🔐 Código de Assinatura Eletrônica: ${codigo}`,
            html: `
                <div style="font-family:Arial,sans-serif; max-width:520px; margin:0 auto; color:#1e293b; border:1px solid #e2e8f0; border-radius:12px; padding:24px;">
                    <h2 style="margin:0 0 10px 0; color:#2c3e50;">🔐 Confirmação de Assinatura</h2>
                    <p style="font-size:14px; line-height:1.5;">Olá, <b>${nome || 'Contratante'}</b>! Use o código abaixo para confirmar a sua autoria e assinar eletronicamente o contrato com <b>${nomeEscola}</b>:</p>
                    <div style="background:#f1f5f9; border:2px dashed #2563eb; border-radius:10px; padding:18px; text-align:center; font-size:32px; font-weight:900; letter-spacing:8px; color:#1d4ed8; margin:18px 0;">
                        ${codigo}
                    </div>
                    <p style="font-size:12px; color:#64748b; margin:0;">Este código expira em 15 minutos. Se você não solicitou esta matrícula, ignore este e-mail.</p>
                </div>
            `
        });

        if (resp && resp.error) {
            console.error('Erro Resend OTP contrato:', resp.error);
            return res.status(500).json({ success: false, error: 'Não foi possível enviar o código para este e-mail.' });
        }

        res.json({ success: true, message: 'Código de 6 dígitos enviado para o seu e-mail!' });
    } catch (error) {
        console.error('Erro em /enviar-codigo-contrato:', error);
        res.status(500).json({ success: false, error: 'Erro ao gerar código de confirmação.' });
    }
});

// 🕵️ AUXILIAR: Interpreta User-Agent de forma legível (SO + Navegador)
function parseUserAgentResumo(ua = '') {
    const s = String(ua || '');
    let so = 'Desconhecido';
    if (/Android/i.test(s)) so = 'Android';
    else if (/iPhone|iPad|iPod/i.test(s)) so = 'iOS';
    else if (/Windows NT 10|Windows NT 11/i.test(s)) so = 'Windows 10/11';
    else if (/Windows/i.test(s)) so = 'Windows';
    else if (/Mac OS X/i.test(s)) so = 'macOS';
    else if (/Linux/i.test(s)) so = 'Linux';

    let nav = 'Navegador Desconhecido';
    if (/Edg\//i.test(s)) nav = 'Microsoft Edge';
    else if (/OPR\/|Opera/i.test(s)) nav = 'Opera';
    else if (/SamsungBrowser/i.test(s)) nav = 'Samsung Internet';
    else if (/Chrome\//i.test(s) && !/Edg\//i.test(s)) nav = 'Google Chrome';
    else if (/Firefox\//i.test(s)) nav = 'Mozilla Firefox';
    else if (/Safari\//i.test(s) && !/Chrome\//i.test(s)) nav = 'Safari';
    else if (/WhatsApp/i.test(s)) nav = 'WhatsApp WebView';

    return { sistemaOperacional: so, navegador: nav };
}

function ipEhPrivado(ip = '') {
    return !ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('::ffff:127.');
}

// ============================================================================
// 🔍 VALIDAÇÃO PÚBLICA DE CONTRATO POR QR CODE / ID + AUDITORIA SILENCIOSA
// ============================================================================
async function handleValidarContratoPublico(req, res) {
    try {
        const database = await connectDB();
        const idBusca = String(req.params.id || '').trim();
        if (!idBusca) {
            return res.status(400).json({ valid: false, error: 'Código de contrato não informado.' });
        }

        const contrato = await database.collection('contratos').findOne({ id: idBusca });

        // 📡 Captura invisível de rede e dispositivo (executada antes do retorno, sem atrasar a resposta)
        const xff = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || '').trim();
        const ipReal = (xff ? xff.split(',')[0].trim() : '') || String(req.headers['x-real-ip'] || req.socket?.remoteAddress || 'Não identificado').replace(/^::ffff:/, '');
        const uaBruto = String(req.headers['user-agent'] || 'Não identificado').slice(0, 320);
        const { sistemaOperacional, navegador } = parseUserAgentResumo(uaBruto);
        const telemetria = (req.body && typeof req.body === 'object') ? req.body : {};

        const cidadeHeader = req.headers['x-vercel-ip-city'] ? decodeURIComponent(String(req.headers['x-vercel-ip-city'])) : '';
        const regiaoHeader = req.headers['x-vercel-ip-country-region'] ? String(req.headers['x-vercel-ip-country-region']) : '';
        const paisHeader = req.headers['x-vercel-ip-country'] ? String(req.headers['x-vercel-ip-country']) : '';

        const dataUTC = new Date().toISOString();
        const dataBrasilia = new Date(dataUTC).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

        let statusIntegridade = 'NAO_ENCONTRADO';
        let hashConfere = null;

        if (contrato) {
            statusIntegridade = 'HISTORICO';
            if (contrato.hashSha256) {
                const recalculado = gerarHashContrato({
                    idContrato: contrato.id,
                    escolaId: contrato.escolaId,
                    nome: contrato.nomeAluno || contrato.nome,
                    cpf: contrato.cpf,
                    email: contrato.email,
                    planoCurso: contrato.planoCurso,
                    conteudoHTML: contrato.conteudoHTML,
                    assinaturaAluno: contrato.assinaturaAluno || '',
                    dataUTC: contrato.auditoria?.dataUTC || contrato.dataCriacao
                });
                hashConfere = (recalculado === contrato.hashSha256);
                statusIntegridade = hashConfere ? 'INTEGRO' : 'ADULTERADO';
            }
        }

        // 💾 Gravação silenciosa do dossiê forense no MongoDB
        const logId = 'LOGVAL_' + crypto.randomUUID();
        const registroConsulta = {
            id: logId,
            escolaId: contrato ? contrato.escolaId : null,
            contratoId: idBusca,
            nomeAluno: contrato ? (contrato.nomeAluno || contrato.nome || 'Não informado') : 'ID não localizado',
            curso: contrato ? (contrato.planoCurso || contrato.curso || 'Não informado') : '-',
            resultado: statusIntegridade,
            origem: telemetria.origem === 'qrcode' ? 'QR Code / Link Direto' : 'Busca Manual',
            ip: ipReal,
            ipCadeia: xff || ipReal,
            referer: String(req.headers['referer'] || 'Acesso direto').slice(0, 260),
            localizacao: {
                cidade: cidadeHeader || 'Identificando...',
                regiao: regiaoHeader || '',
                pais: paisHeader || '',
                isp: ''
            },
            dispositivo: {
                sistemaOperacional,
                navegador,
                userAgent: uaBruto,
                tela: String(telemetria.tela || '').slice(0, 60),
                fusoHorario: String(telemetria.fusoHorario || '').slice(0, 60),
                idioma: String(telemetria.idioma || req.headers['accept-language'] || '').slice(0, 40),
                touch: Boolean(telemetria.touch),
                nucleos: Number(telemetria.nucleos) || null,
                memoria: Number(telemetria.memoria) || null,
                plataforma: String(telemetria.plataforma || '').slice(0, 60),
                fingerprint: String(telemetria.fingerprint || '').slice(0, 64)
            },
            dataUTC,
            dataBrasilia
        };

        database.collection('logs_validacao_contratos').insertOne(registroConsulta).then(() => {
            // 🌍 Enriquecimento silencioso em segundo plano (Cidade, Estado, País e Operadora/ISP sem atrasar o visitante)
            if (!ipEhPrivado(ipReal)) {
                fetch(`https://ipwho.is/${encodeURIComponent(ipReal)}`, { signal: AbortSignal.timeout(2500) })
                    .then(r => r.json())
                    .then(geo => {
                        if (geo && geo.success) {
                            database.collection('logs_validacao_contratos').updateOne(
                                { id: logId },
                                {
                                    $set: {
                                        'localizacao.cidade': geo.city || cidadeHeader || 'Não identificada',
                                        'localizacao.regiao': geo.region || regiaoHeader || '',
                                        'localizacao.pais': geo.country || paisHeader || '',
                                        'localizacao.isp': (geo.connection && (geo.connection.isp || geo.connection.org)) || ''
                                    }
                                }
                            ).catch(() => {});
                        }
                    })
                    .catch(() => {});
            }
        }).catch(err => console.warn('Aviso ao gravar log de validação:', err.message));

        if (!contrato) {
            return res.status(404).json({ valid: false, error: 'Nenhum contrato encontrado com este ID de transação.' });
        }

        const escola = contrato.escolaId
            ? (await database.collection('escola').findOne({ escolaId: contrato.escolaId }) || {})
            : {};

        const dataRef = contrato.auditoria?.dataUTC || contrato.dataHoraRegistro || contrato.dataCriacao || null;
        const dataAssinaturaBR = dataRef
            ? new Date(dataRef).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })
            : 'Não informada';

        res.json({
            valid: statusIntegridade !== 'ADULTERADO',
            statusIntegridade,
            idTransacao: contrato.id,
            statusContrato: contrato.status || 'Assinado',
            contratante: {
                nome: contrato.nomeAluno || contrato.nome || 'Não informado',
                cpfMascarado: mascararCPF(contrato.cpf),
                emailMascarado: mascararEmail(contrato.email),
                responsavel: contrato.resp_nome || null
            },
            instituicao: {
                nome: escola.nome || 'Instituição Registrada',
                cnpj: escola.cnpj || 'Não informado',
                representante: contrato.representanteNome || escola.representanteNome || null
            },
            curso: contrato.planoCurso || contrato.curso || 'Não informado',
            modalidade: (contrato.modalidade === 'Online' || contrato.modalidade_escolhida === 'Online') ? 'Online (EAD)' : 'Presencial',
            dataAssinatura: dataAssinaturaBR,
            auditoria: {
                hashSha256: contrato.hashSha256 || null,
                hashConfere,
                ipParcial: mascararIP(contrato.auditoria?.ip),
                otpVerificado: Boolean(contrato.auditoria?.otpVerificado),
                possuiAssinaturaManuscrita: Boolean(contrato.assinaturaAluno),
                assinaturaModo: contrato.assinaturaAlunoModo || null
            }
        });
    } catch (error) {
        console.error('Erro em /validar-contrato:', error);
        res.status(500).json({ valid: false, error: 'Erro interno ao validar o contrato.' });
    }
}

router.get('/validar-contrato/:id', handleValidarContratoPublico);
router.post('/validar-contrato/:id', handleValidarContratoPublico);

router.post('/receber-matricula', async (req, res) => {
    try {
        const database = await connectDB();
        const dadosMatricula = req.body; 
        const { escolaId, nome, email, conteudoHTML, planoCurso, diaVencimento } = dadosMatricula;
        
        // 🔐 VALIDAÇÃO DO CÓDIGO OTP DE 6 DÍGITOS (PROVA DE AUTORIA PELO E-MAIL)
        const emailLimpo = String(email || '').trim().toLowerCase();
        const codigoOtp = String(dadosMatricula.codigoOtp || '').trim();
        let otpVerificado = false;

        if (!emailLimpo || !emailLimpo.includes('@')) {
            return res.status(400).json({ success: false, error: 'Informe um e-mail válido para assinar o contrato.' });
        }
        if (!codigoOtp || codigoOtp.length !== 6) {
            return res.status(400).json({ success: false, error: 'Informe o código de 6 dígitos enviado para o seu e-mail.' });
        }

        const regOtp = await database.collection('otp_contratos').findOne({
            email: emailLimpo,
            escolaId: String(escolaId || ''),
            codigo: codigoOtp,
            usado: false
        });
        if (!regOtp || new Date(regOtp.expiraEm).getTime() < Date.now()) {
            return res.status(400).json({ success: false, error: 'Código de confirmação inválido ou expirado. Solicite um novo código.' });
        }

        await database.collection('otp_contratos').updateOne(
            { _id: regOtp._id },
            { $set: { usado: true, usadoEm: new Date() } }
        );
        otpVerificado = true;

        const ipReal = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'Não identificado').split(',')[0].trim();
        const userAgentReal = String(req.headers['user-agent'] || 'Não identificado').slice(0, 260);
        const dataServidorUTC = new Date().toISOString();
        const idContratoGerado = "CONT_" + crypto.randomUUID();
        const assinaturaAlunoLimpa = typeof dadosMatricula.assinaturaAluno === 'string' ? dadosMatricula.assinaturaAluno.slice(0, 250000) : '';

        console.log("Iniciando processamento da matrícula para:", email); 

        const escola = await database.collection('escola').findOne({ escolaId: escolaId }) || {};
        const idAlunoGerado = crypto.randomUUID();
        
        // 1. Gravação do Perfil do Aluno
        const novoAluno = {
            ...dadosMatricula,
            id: idAlunoGerado,
            status: 'Ativo',
            dataMatricula: new Date().toISOString()
        };
        await database.collection('alunos').insertOne(novoAluno);

        // 2. BUSCA DO VALOR DO CURSO
        let valorMensalidade = 150.00; 
        if (planoCurso) {
            const cursoEncontrado = await database.collection('cursos').findOne({ escolaId: escolaId, nome: planoCurso });
            if (cursoEncontrado && cursoEncontrado.valor) {
                valorMensalidade = parseFloat(cursoEncontrado.valor);
            }
        }

        // 3. GERADOR DO CARNÊ AUTOMÁTICO
        const parcelas = [];
        const dataAtual = new Date();
        const diaPagar = parseInt(diaVencimento) || 10;
        const idLote = Date.now().toString(); 
        const dataGeracao = new Date().toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });

        for (let i = 1; i <= 12; i++) {
            let dataVenc = new Date(dataAtual.getFullYear(), dataAtual.getMonth() + i, diaPagar);
            if (dataVenc.getDate() !== diaPagar) dataVenc.setDate(0); 
            
            parcelas.push({
                id: idLote + "_" + i,
                idCarne: idLote,             
                escolaId: escolaId,
                dataGeracao: dataGeracao,
                idAluno: idAlunoGerado,      
                alunoNome: nome,             
                valor: valorMensalidade, 
                vencimento: dataVenc.toISOString().split('T')[0],
                status: 'Pendente',
                descricao: `Mensalidade ${i}/12`, 
                tipo: 'Receita',
                dataCriacao: new Date().toISOString()
            });
        }
        await database.collection('financeiro').insertMany(parcelas);

        // 4. Gravação Imutável no Cofre de Contratos (com Assinaturas, Hash SHA-256 e Auditoria)
        const hashSha256 = gerarHashContrato({
            idContrato: idContratoGerado,
            escolaId,
            nome,
            cpf: dadosMatricula.cpf,
            email: emailLimpo,
            planoCurso,
            conteudoHTML: conteudoHTML || '',
            assinaturaAluno: assinaturaAlunoLimpa,
            dataUTC: dataServidorUTC
        });

        const auditoriaContrato = {
            ip: ipReal,
            userAgent: userAgentReal,
            fusoCliente: String(dadosMatricula.fusoHorario || 'America/Sao_Paulo'),
            dataUTC: dataServidorUTC,
            dataBrasilia: new Date(dataServidorUTC).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
            otpVerificado,
            emailVerificado: emailLimpo
        };

        const metaJuridica = {
            idContrato: idContratoGerado,
            hashSha256,
            assinaturaAluno: assinaturaAlunoLimpa,
            assinaturaAlunoModo: dadosMatricula.assinaturaAlunoModo || 'desenho',
            assinaturaInstituicao: escola.assinaturaInstituicao || '',
            representanteNome: escola.representanteNome || '',
            representanteCargo: escola.representanteCargo || '',
            auditoria: auditoriaContrato
        };

        if (conteudoHTML) {
            const dadosLimposContrato = { ...dadosMatricula };
            delete dadosLimposContrato.codigoOtp;

            await database.collection('contratos').insertOne({
                ...dadosLimposContrato,
                id: idContratoGerado,
                alunoId: idAlunoGerado,
                nomeAluno: nome,
                enderecoCompleto: `${dadosMatricula.rua || ''}, ${dadosMatricula.numero || ''} - ${dadosMatricula.bairro || ''}, ${dadosMatricula.cidade || ''}`,
                conteudoHTML: conteudoHTML,
                assinaturaAluno: assinaturaAlunoLimpa,
                assinaturaAlunoModo: metaJuridica.assinaturaAlunoModo,
                assinaturaInstituicao: metaJuridica.assinaturaInstituicao,
                representanteNome: metaJuridica.representanteNome,
                representanteCargo: metaJuridica.representanteCargo,
                hashSha256,
                auditoria: auditoriaContrato,
                status: 'Assinado',
                dataCriacao: dataServidorUTC
            });
        }

        // 5. Notificação Interna
        await database.collection('notificacoes').insertOne({
            id: "NOTI_" + crypto.randomUUID(),
            escolaId,
            tipo: "matricula",
            titulo: "🎉 Nova Matrícula!",
            mensagem: `${nome} acabou de se matricular no curso ${planoCurso || 'Não informado'}.`,
            lida: false,
            dataCriacao: new Date().toISOString()
        });

        // ====================================================================
        // 🔥 5.1 GATILHO DE PUSH INSTANTÂNEO PARA O TELEMÓVEL DO GESTOR 🔥
        // ====================================================================
        try {
            console.log("A disparar notificação push instantânea para a escola...");
            // Filtra apenas aparelhos da equipa (exclui contas do tipo 'Aluno')
            const aparelhos = await database.collection('push_subscriptions').find({ 
                escolaId: escolaId, 
                tipo: { $ne: 'Aluno' } 
            }).toArray();
            
            if (aparelhos.length > 0) {
                const payloadPush = JSON.stringify({
                    title: '🎉 Nova Matrícula Recebida!',
                    body: `${nome} acabou de se matricular no curso ${planoCurso || 'selecionado'}.`,
                    url: '/' // Atira o gestor para o painel inicial onde a notificação vermelha estará à espera
                });

                for (let aparelho of aparelhos) {
                    try {
                        await webpush.sendNotification(aparelho.subscription, payloadPush);
                        console.log("📲 Push instantâneo enviado com sucesso!");
                    } catch (err) {
                        // Se o diretor bloqueou notificações no telemóvel, limpamos o registo
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await database.collection('push_subscriptions').deleteOne({ _id: aparelho._id });
                        }
                    }
                }
            }
        } catch (pushErr) {
            console.error("Aviso: Falha ao enviar push instantâneo (não impede a matrícula):", pushErr);
        }
        // ====================================================================

        // 6. GERAÇÃO DOS PDFS E ENVIO DE E-MAIL
        if (email) {
            try {
                console.log("Iniciando conversão de HTML para PDF via API externa...");
                
                const htmlDoContrato = montarHtmlContratoOficial(conteudoHTML, escola, dadosMatricula, metaJuridica);
                const htmlDoCarne = montarHtmlCarnesOficial(parcelas, nome, escola);
                
                // Pede os PDFs à API
                const contratoPdfBuffer = await gerarPdfBuffer(htmlDoContrato);
                const carnesPdfBuffer = await gerarPdfBuffer(htmlDoCarne);
                console.log("✅ Ficheiros PDF prontos para envio!");

                // Prepara os Anexos
                const anexos = [];
                if (contratoPdfBuffer) {
                    anexos.push({ 
                        filename: 'Contrato_Assinado.pdf', 
                        content: Buffer.from(contratoPdfBuffer).toString('base64')
                    });
                }
                anexos.push({ 
                    filename: 'Carnes_Mensalidades.pdf', 
                    content: Buffer.from(carnesPdfBuffer).toString('base64')
                });

                const corpoDoEmail = `
                    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; line-height: 1.6;">
                        <h2 style="color: #2c3e50;">Olá, ${nome}! 🎉</h2>
                        <p>É com grande alegria que lhe damos as boas-vindas à <b>${escola.nome || 'nossa instituição'}</b>!</p>
                        <p>A sua matrícula no curso <b>${planoCurso || 'selecionado'}</b> foi realizada com sucesso e já preparamos tudo para você.</p>
                        
                        <p>Em anexo a este e-mail, encontrará:</p>
                        <ul>
                            <li><b>O seu Contrato de Matrícula</b> (cópia digital);</li>
                            <li><b>O seu Carnê de Pagamento</b> (com as 12 mensalidades).</li>
                        </ul>

                        <div style="background-color: #f4f6f7; border-left: 4px solid #27ae60; padding: 15px; margin: 20px 0;">
                            <b>📱 Atenção ao seu WhatsApp!</b><br>
                            Fique de olho no seu celular. Muito em breve, a nossa equipe entrará em contato para lhe passar novas informações e tirar qualquer dúvida que você possa ter!
                        </div>

                        <p>Com os melhores cumprimentos,<br>
                        <b>Equipe ${escola.nome || 'PTT CURSOS'}</b></p>
                    </div>
                `;

                console.log("Enviando e-mail final pelo Resend...");
                const respostaResend = await resend.emails.send({
                    from: 'Matriculas <contato@sistemaptt.com.br>',
                    to: email,
                    subject: '🎉 Bem-vindo(a)! O seu Contrato e Carnês estão aqui',
                    html: corpoDoEmail,
                    attachments: anexos
                });

                if (respostaResend.error) {
                    console.error("Erro do Resend:", respostaResend.error);
                } else {
                    console.log(`✅ E-mail com PDFs enviado COM SUCESSO!`);
                }
            } catch (emailError) {
                console.error("Erro ao tentar enviar o e-mail ou gerar PDF:", emailError);
            }
        }

        res.json({ success: true, idContrato: idContratoGerado, message: 'Matrícula processada com sucesso!' });
    } catch (error) {
        console.error("Erro crítico ao processar matrícula:", error);
        res.status(500).json({ error: 'Erro ao processar matrícula.' });
    }
});

// ============================================================================
// 📡 ROTA DE TEMPO REAL (SERVER-SENT EVENTS - SSE)[cite: 6]
// ============================================================================
// Inicializamos o Mega-fone global caso o aluno acesse primeiro[cite: 6]
if (!global.escolaEmitter) {
    const EventEmitter = require('events');
    global.escolaEmitter = new EventEmitter();
}

router.get('/stream-matricula/:escolaId', (req, res) => {
    // 1. Configuramos o cabeçalho para manter a ligação aberta como uma "stream"[cite: 6]
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const escolaId = req.params.escolaId;

    // 2. Criamos o ouvinte para a escola específica que o aluno tem aberta[cite: 6]
    const enviarAtualizacao = (idDaEscolaAtualizada) => {
        if (idDaEscolaAtualizada === escolaId) {
            // O servidor envia o código 'RELOAD' para o navegador do aluno[cite: 6]
            res.write(`data: ${JSON.stringify({ type: 'RELOAD' })}\n\n`);
        }
    };

    // 3. Ligamos o ouvinte ao Mega-fone global[cite: 6]
    global.escolaEmitter.on('atualizacao-escola', enviarAtualizacao);

    // 4. Quando o aluno fecha a página, removemos o ouvinte para manter o servidor rápido e leve[cite: 6]
    req.on('close', () => {
        global.escolaEmitter.removeListener('atualizacao-escola', enviarAtualizacao);
    });
});

module.exports = router;