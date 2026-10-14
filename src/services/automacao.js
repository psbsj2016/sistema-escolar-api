// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

// 🔑 Configuração das chaves de segurança do Web Push (VAPID)
webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const iniciarAutomacao = () => {

    // ⚙️ PARÂMETROS AJUSTÁVEIS DE HORÁRIO (Formato Cron: 'Minuto Hora * * *')
    const HORARIO_CRON_MANHA = '0 8 * * *';  // Dispara às 08:00 da manhã
    const HORARIO_CRON_NOITE = '0 19 * * *'; // Dispara às 19:00 (Fecho do Dia)

    // Função auxiliar para obter a data atual no Fuso Horário de Brasília
    const obterDatasBrasil = () => {
        const hojeObj = new Date();
        const fusoBR = new Date(hojeObj.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
        const ano = fusoBR.getFullYear();
        const mes = String(fusoBR.getMonth() + 1).padStart(2, '0');
        const dia = String(fusoBR.getDate()).padStart(2, '0');

        return {
            hojeIso: `${ano}-${mes}-${dia}`, // Ex: "2026-10-14"
            hojeBr: `${dia}/${mes}/${ano}`,  // Ex: "14/10/2026"
            mesHoje: mes,
            diaHoje: dia
        };
    };

    // =========================================================================
    // 🌅 MOTOR 1: VARREDURA MATINAL (TODOS OS DIAS ÀS 08:00)
    // =========================================================================
    cron.schedule(HORARIO_CRON_MANHA, async () => {
        console.log('⏰ [CRON MANHÃ] A iniciar a varredura matinal do Assistente Virtual...');
        
        try {
            const db = await connectDB();
            const { hojeIso, mesHoje, diaHoje } = obterDatasBrasil();

            // 1. Busca de Alunos Ativos
            const alunosAtivos = await db.collection('alunos').find({
                $or: [ { status: 'Ativo' }, { status: {$exists: false } } ]
            }).toArray();
            
            const idsAlunosAtivos = alunosAtivos.map(a => a.id);

            // 2. Aniversariantes do Dia
            const aniversariantesPorEscola = {};
            alunosAtivos.forEach(aluno => {
                const dataNasc = aluno.nascimento || aluno.dataNascimento; 
                if (dataNasc) {
                    const partes = dataNasc.includes('/') ? dataNasc.split('/') : dataNasc.split('-');
                    const diaAluno = dataNasc.includes('/') ? partes[0] : partes[2];
                    const mesAluno = partes[1];

                    if (mesAluno === mesHoje && diaAluno === diaHoje) {
                        const escolaId = aluno.escolaId || 'padrao';
                        aniversariantesPorEscola[escolaId] = (aniversariantesPorEscola[escolaId] || 0) + 1;
                    }
                }
            });

            // 3. Mensalidades Pendentes (Vencidas ou que vencem hoje)
            const alertasPorEscola = {};
            if (idsAlunosAtivos.length > 0) {
                const pendentes = await db.collection('financeiro').find({
                    status: 'Pendente',
                    vencimento: { $lte: hojeIso },
                    idAluno: { $in: idsAlunosAtivos }
                }).toArray();

                pendentes.forEach(fatura => {
                    const escId = fatura.escolaId || 'padrao';
                    alertasPorEscola[escId] = (alertasPorEscola[escId] || 0) + 1;
                });
            }

            // 4. Eventos do Calendário de Hoje
            const eventosHoje = await db.collection('eventos').find({ data: hojeIso }).toArray();
            const eventosPorEscola = {};
            eventosHoje.forEach(ev => {
                const escId = ev.escolaId || 'padrao';
                eventosPorEscola[escId] = (eventosPorEscola[escId] || 0) + 1;
            });

            // 5. Itens com Estoque Baixo
            const todosEstoques = await db.collection('estoques').find({}).toArray();
            const estoqueBaixoPorEscola = {};
            todosEstoques.forEach(item => {
                const qtd = parseInt(item.quantidade) || 0;
                const min = parseInt(item.quantidadeMinima) || 0;
                if (qtd <= min) {
                    const escId = item.escolaId || 'padrao';
                    estoqueBaixoPorEscola[escId] = (estoqueBaixoPorEscola[escId] || 0) + 1;
                }
            });

            // 6. Compilar e Enviar os Avisos Matinais por Escola e Cargo
            const todasEscolasComNovidades = new Set([
                ...Object.keys(alertasPorEscola),
                ...Object.keys(aniversariantesPorEscola),
                ...Object.keys(eventosPorEscola),
                ...Object.keys(estoqueBaixoPorEscola)
            ]);

            for (const escolaId of todasEscolasComNovidades) {
                const qtdFaturas = alertasPorEscola[escolaId] || 0;
                const qtdAniversariantes = aniversariantesPorEscola[escolaId] || 0;
                const qtdEventos = eventosPorEscola[escolaId] || 0;
                const qtdEstoque = estoqueBaixoPorEscola[escolaId] || 0;

                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                if (aparelhos.length === 0) continue; 

                for (let aparelho of aparelhos) {
                    const isProfessor = aparelho.tipo === 'Professor';
                    let textoCorpo = '';

                    if (!isProfessor && qtdFaturas > 0) textoCorpo += `💸 ${qtdFaturas} cobrança(s) pendente(s).\n`;
                    if (qtdEventos > 0) textoCorpo += `📅 ${qtdEventos} evento(s) na agenda de hoje.\n`;
                    if (qtdAniversariantes > 0) textoCorpo += `🎂 ${qtdAniversariantes} aniversariante(s) hoje!\n`;
                    if (!isProfessor && qtdEstoque > 0) textoCorpo += `📦 ${qtdEstoque} item(ns) com estoque baixo.\n`;

                    if (!textoCorpo) continue;
                    textoCorpo += 'Toque para abrir o painel.';

                    const payload = JSON.stringify({
                        title: 'Bom dia! Resumo do Dia 🌅',
                        body: textoCorpo,
                        url: '/'
                    });

                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                    } catch (err) {
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await db.collection('push_subscriptions').deleteOne({ _id: aparelho._id });
                        }
                    }
                }
            }
        } catch (error) {
            console.error('❌ Erro crítico no Cron Matinal:', error);
        }
    }, {
        scheduled: true,
        timezone: "America/Sao_Paulo"
    });

    // =========================================================================
    // 🌙 MOTOR 2: RESUMO DE FECHO DO DIA (TODOS OS DIAS ÀS 19:00)
    // =========================================================================
    cron.schedule(HORARIO_CRON_NOITE, async () => {
        console.log('🌙 [CRON NOITE] A gerar o Resumo de Fecho do Dia...');

        try {
            const db = await connectDB();
            const { hojeIso, hojeBr } = obterDatasBrasil();

            // 1. Novas Matrículas Registadas Hoje
            const todosAlunos = await db.collection('alunos').find({
                $or: [ { status: 'Ativo' }, { status: {$exists: false } } ]
            }).toArray();

            const matriculasHojePorEscola = {};
            todosAlunos.forEach(a => {
                if (a.dataMatricula && (a.dataMatricula.startsWith(hojeIso) || a.dataMatricula.startsWith(hojeBr))) {
                    const escId = a.escolaId || 'padrao';
                    matriculasHojePorEscola[escId] = (matriculasHojePorEscola[escId] || 0) + 1;
                }
            });

            // 2. Movimento Financeiro de Hoje (Pagos Hoje vs Pendentes de Hoje)
            const lancamentosHoje = await db.collection('financeiro').find({
                $or: [
                    { vencimento: hojeIso },
                    { dataGeracao: hojeBr }
                ]
            }).toArray();

            const pagosHojePorEscola = {};
            const valorPagoHojePorEscola = {};
            const pendentesHojePorEscola = {};

            lancamentosHoje.forEach(f => {
                const escId = f.escolaId || 'padrao';
                if (f.status === 'Pago') {
                    pagosHojePorEscola[escId] = (pagosHojePorEscola[escId] || 0) + 1;
                    const val = parseFloat(f.valor) || 0;
                    valorPagoHojePorEscola[escId] = (valorPagoHojePorEscola[escId] || 0) + val;
                } else if (f.status === 'Pendente' && f.vencimento === hojeIso) {
                    pendentesHojePorEscola[escId] = (pendentesHojePorEscola[escId] || 0) + 1;
                }
            });

            // 3. Chamadas / Presenças Registadas Hoje
            const chamadasHoje = await db.collection('chamadas').find({ data: hojeIso }).toArray();
            const presencasHojePorEscola = {};
            const faltasHojePorEscola = {};

            chamadasHoje.forEach(c => {
                const escId = c.escolaId || 'padrao';
                if (c.status === 'Presença' || c.status === 'Reposição') {
                    presencasHojePorEscola[escId] = (presencasHojePorEscola[escId] || 0) + 1;
                } else if (c.status === 'Falta') {
                    faltasHojePorEscola[escId] = (faltasHojePorEscola[escId] || 0) + 1;
                }
            });

            // 4. Compilar Escolas que tiveram atividade hoje
            const escolasAtivasHoje = new Set([
                ...Object.keys(matriculasHojePorEscola),
                ...Object.keys(pagosHojePorEscola),
                ...Object.keys(pendentesHojePorEscola),
                ...Object.keys(presencasHojePorEscola),
                ...Object.keys(faltasHojePorEscola)
            ]);

            for (const escolaId of escolasAtivasHoje) {
                const qtdMatr = matriculasHojePorEscola[escolaId] || 0;
                const qtdPagos = pagosHojePorEscola[escolaId] || 0;
                const valorPago = valorPagoHojePorEscola[escolaId] || 0;
                const qtdPend = pendentesHojePorEscola[escolaId] || 0;
                const qtdPres = presencasHojePorEscola[escolaId] || 0;
                const qtdFaltas = faltasHojePorEscola[escolaId] || 0;

                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                if (aparelhos.length === 0) continue;

                for (let aparelho of aparelhos) {
                    const isProfessor = aparelho.tipo === 'Professor';
                    let textoCorpo = '';

                    if (qtdMatr > 0) {
                        textoCorpo += `🎉 ${qtdMatr} nova(s) matrícula(s) hoje!\n`;
                    }

                    if (!isProfessor && qtdPagos > 0) {
                        const valorFmt = valorPago.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
                        textoCorpo += `✅ ${qtdPagos} recebimento(s) hoje (R$ ${valorFmt}).\n`;
                    }

                    if (!isProfessor && qtdPend > 0) {
                        textoCorpo += `⏳ ${qtdPend} parcela(s) de hoje ficou(aram) pendente(s).\n`;
                    }

                    if (qtdPres > 0 || qtdFaltas > 0) {
                        textoCorpo += `📋 Chamada de hoje: ${qtdPres} presença(s) e ${qtdFaltas} falta(s).\n`;
                    }

                    if (!textoCorpo) continue;
                    textoCorpo += 'Bom descanso! 🌙';

                    const payload = JSON.stringify({
                        title: 'Fecho do Dia | Balanço PTT 📊',
                        body: textoCorpo,
                        url: '/'
                    });

                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                        console.log(`📩 [CRON NOITE] Fecho do dia enviado para a escola ${escolaId}!`);
                    } catch (err) {
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await db.collection('push_subscriptions').deleteOne({ _id: aparelho._id });
                        }
                    }
                }
            }
        } catch (error) {
            console.error('❌ Erro crítico no Cron de Fecho do Dia:', error);
        }
    }, {
        scheduled: true,
        timezone: "America/Sao_Paulo"
    });
};

module.exports = iniciarAutomacao;