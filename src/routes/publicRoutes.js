const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db');

// Importação das bibliotecas
const puppeteer = require('puppeteer');
const { Resend } = require('resend');

// Inicialize o Resend com a chave segura do .env
const resend = new Resend(process.env.RESEND_API_KEY); 

// ============================================================================
// 📄 FUNÇÕES GERADORAS DE PDF (COM DESIGN OFICIAL DO SISTEMA)
// ============================================================================

async function gerarPdfBuffer(htmlContent) {
    console.log("⏳ Iniciando o gerador de PDF (Puppeteer)...");
    const browser = await puppeteer.launch({ 
        headless: "new",
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] 
    });
    
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
    
    // Margens padrão
    const pdfBuffer = await page.pdf({ 
        format: 'A4', 
        printBackground: true, 
        margin: { top: '10mm', bottom: '10mm', left: '10mm', right: '10mm' } 
    });
    
    await browser.close();
    return pdfBuffer;
}

// 🎨 CONSTRUTOR DO HTML DO CARNÊ (Idêntico ao financeiro.js + CNPJ)
function montarHtmlCarnesOficial(parcelas, nomeAluno, escola) {
    const nomeEscola = escola.nome || 'INSTITUIÇÃO';
    const bancoNome = escola.banco || 'Não Configurado';
    const chavePix = escola.chavePix || 'Não Configurada';
    
    // Configuração do Logo e CNPJ para o Canhoto
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

// 🎨 CONSTRUTOR DO HTML DO CONTRATO COMPLETO (Ficha + Cláusulas + CNPJ)
function montarHtmlContratoOficial(conteudoHTML, escola, dados) {
    // Configuração do Logo e CNPJ para o topo do Contrato
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
    const dataAtual = new Date().toLocaleDateString('pt-BR');
    const horaAtual = new Date().toLocaleTimeString('pt-BR');

    return `
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 0; background: white; }
                .contrato-container { width: 100%; max-width: 800px; margin: 0 auto; }
                h1, h2, h3 { color: #2c3e50; }
                
                /* Estilo da Ficha de Matrícula */
                .ficha-box { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: #fcfcfc; margin-bottom: 30px; }
                .ficha-titulo { background: #2c3e50; color: white; padding: 8px 15px; border-radius: 5px; font-size: 14px; text-transform: uppercase; margin-top: 0; margin-bottom: 15px; }
                .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px; font-size: 13px; }
                .linha-dado { border-bottom: 1px dashed #eee; padding-bottom: 5px; }
                .label { font-weight: bold; color: #666; font-size: 11px; text-transform: uppercase; display: block; }
                .valor { font-size: 14px; font-weight: bold; color: #222; }

                /* Estilo do Contrato */
                .clausulas { font-size: 12px; text-align: justify; line-height: 1.5; margin-top: 30px; }
                .assinatura-box { margin-top: 50px; text-align: center; page-break-inside: avoid; }
            </style>
        </head>
        <body>
            <div class="contrato-container">
                ${cabecalhoEscola}
                <h2 style="text-align: center; margin-bottom: 5px; text-transform: uppercase;">Contrato de Prestação de Serviços Educacionais</h2>
                <div style="text-align: center; font-size: 12px; color: #666; margin-bottom: 25px;">Documento gerado e aceito digitalmente em ${dataAtual} às ${horaAtual}</div>
                
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

                    <div style="margin-top: 15px;" class="linha-dado">
                        <span class="label">Endereço Completo</span>
                        <span class="valor">${endereco} - Bairro: ${dados.bairro || ''} - ${dados.cidade || ''}/${dados.estado || ''} | CEP: ${dados.cep || ''}</span>
                    </div>

                    <div class="grid-2" style="margin-top: 15px;">
                        <div class="linha-dado"><span class="label">Curso / Plano Contratado</span><span class="valor" style="color: #27ae60;">${dados.planoCurso || 'Não informado'}</span></div>
                        <div class="linha-dado"><span class="label">Dia de Vencimento</span><span class="valor">Todo dia ${dados.diaVencimento || '10'}</span></div>
                    </div>
                </div>

                <div class="clausulas">
                    ${conteudoHTML || '<p><em>Nenhuma cláusula contratual adicional foi cadastrada.</em></p>'}
                </div>

                <div class="assinatura-box">
                    <p>_______________________________________________________</p>
                    <p style="font-size: 16px; margin-bottom: 2px;"><b>${dados.nome || 'Aluno'}</b></p>
                    <p style="font-size: 12px; color: #555; margin-top: 0;">Assinatura do Aluno(a) / Contratante</p>
                    
                    <div style="margin-top: 20px; padding: 10px; background: #eafaf1; border: 1px solid #27ae60; border-radius: 5px; display: inline-block; font-size: 11px; color: #1e8449;">
                        ✅ Aceite Eletrónico Registado (IP Logado e Confirmado via Sistema)
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

// Buscar dados básicos da escola para a página de matrícula
router.get('/escola/:id', async (req, res) => {
    try {
        const database = await connectDB();
        const schoolIdClean = req.params.id ? req.params.id.trim() : '';
        const escola = await database.collection('escola').findOne({ escolaId: schoolIdClean });
        if (!escola) return res.status(404).json({ error: 'Escola não encontrada.' });

        res.json({ escolaId: escola.escolaId, configMatricula: escola.configMatricula || null });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao carregar matrícula.' });
    }
});

// Receber formulário de matrícula externa
router.post('/receber-matricula', async (req, res) => {
    console.log("Iniciando processamento da matrícula para:", email); // <--- AQUI
    try {
        const database = await connectDB();
        const dadosMatricula = req.body; 
        const { escolaId, nome, email, conteudoHTML, planoCurso, diaVencimento } = dadosMatricula;

        // 🕵️‍♂️ Busca os dados completos da escola para usar nos PDFs
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

        // 3. GERADOR DO CARNÊ AUTOMÁTICO (12 MENSALIDADES)
        const parcelas = [];
        const dataAtual = new Date();
        const diaPagar = parseInt(diaVencimento) || 10;
        const idLote = Date.now().toString(); 
        const dataGeracao = new Date().toLocaleDateString('pt-BR');

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

        // 4. Gravação no Cofre de Contratos
        if (conteudoHTML) {
            await database.collection('contratos').insertOne({
                ...dadosMatricula,
                id: "CONT_" + crypto.randomUUID(),
                alunoId: idAlunoGerado,
                nomeAluno: nome,
                enderecoCompleto: `${dadosMatricula.rua || ''}, ${dadosMatricula.numero || ''} - ${dadosMatricula.bairro || ''}, ${dadosMatricula.cidade || ''}`,
                conteudoHTML: conteudoHTML, 
                status: 'Assinado',
                dataCriacao: new Date().toISOString()
            });
        }

        // 5. Notificação Interna do Sistema
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
        // 📧 6. DISPARO DE E-MAIL (TESTE SEM PDF)
        // ====================================================================
        
        if (email) {
            try {
                console.log("Começando preparação do e-mail..."); 
                
                // Monta os HTMLs
                const htmlDoContrato = montarHtmlContratoOficial(conteudoHTML, escola, dadosMatricula);
                const htmlDoCarne = montarHtmlCarnesOficial(parcelas, nome, escola);
                
                // 🚨 O SEGREDO ESTÁ AQUI: TEM DE DESATIVAR A CHAMADA AO PUPPETEER!
                // const contratoPdfBuffer = await gerarPdfBuffer(htmlDoContrato);
                // const carnesPdfBuffer = await gerarPdfBuffer(htmlDoCarne);
                // console.log("PDFs gerados com sucesso!"); 

                const corpoDoEmail = `
                    <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; line-height: 1.6;">
                        <h2 style="color: #2c3e50;">Olá, ${nome}! 🎉</h2>
                        <p>É com grande alegria que lhe damos as boas-vindas à <b>${escola.nome || 'nossa instituição'}</b>!</p>
                        <p>A sua matrícula no curso <b>${planoCurso || 'selecionado'}</b> foi realizada com sucesso e já preparamos tudo para você.</p>
                        
                        <div style="background-color: #f4f6f7; border-left: 4px solid #27ae60; padding: 15px; margin: 20px 0;">
                            <b>📱 Atenção ao seu WhatsApp!</b><br>
                            Fique de olho no seu celular. Muito em breve, a nossa equipe entrará em contato com você para lhe passar novas informações!
                        </div>

                        <p>Com os melhores cumprimentos,<br>
                        <b>Equipe ${escola.nome || 'PTT CURSOS'}</b></p>
                    </div>
                `;

                console.log("Tentando enviar e-mail pelo Resend (SEM ANEXOS)..."); 
                
                const respostaResend = await resend.emails.send({
                    from: 'Matriculas <contato@sistemaptt.com.br>',
                    to: email,
                    subject: '🎉 Bem-vindo(a)! Sua Matrícula foi recebida',
                    html: corpoDoEmail
                    // attachments: anexos  <-- DESATIVADO
                });
                
                console.log("Resposta do Resend:", respostaResend); 
                
                if (respostaResend.error) {
                    console.error("\n🚨 ERRO EXATO DO RESEND:", respostaResend.error);
                } else {
                    console.log(`\n✅ E-mail enviado COM SUCESSO para ${email}!`);
                }
            } catch (emailError) {
                console.error("ERRO CRÍTICO NO ENVIO:", emailError); 
            }
        }

        res.json({ success: true, message: 'Matrícula processada!' });
    } catch (error) {
        console.error("Erro crítico ao processar matrícula:", error);
        res.status(500).json({ error: 'Erro ao processar matrícula.' });
    }
});

module.exports = router;