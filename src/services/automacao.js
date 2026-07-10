// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

// 🔑 O crachá de autorização do nosso Carteiro (Web Push)
// Este código permite que o servidor tenha autorização da Apple/Google para enviar notificações
webpush.setVapidDetails(
    'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const iniciarAutomacao = () => {
    // ⏰ CRON JOB: Executa todos os dias às 08:00 da manhã
    // A configuração { timezone: "America/Sao_Paulo" } no final garante o horário de Brasília
    cron.schedule('0 8 * * *', async () => {
        console.log('⏰ [CRON] A iniciar a varredura matinal do Assistente Virtual...');
        
        try {
            const db = await connectDB();
            
            // Pega a data de hoje ajustada para o Fuso Horário do Brasil
            const hojeObj = new Date();
            const fusoBR = new Date(hojeObj.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
            
            // Isola as datas para facilitar as comparações
            const hojeIso = fusoBR.toISOString().split('T')[0]; // Ex: "2026-07-10"
            const mesHoje = String(fusoBR.getMonth() + 1).padStart(2, '0'); // Ex: "07"
            const diaHoje = String(fusoBR.getDate()).padStart(2, '0'); // Ex: "10"

            // 🛡️ 1. BUSCA DE ALUNOS ATIVOS
            // Não queremos mandar aviso de aniversário de alunos cancelados
            const alunosAtivos = await db.collection('alunos').find({
                $or: [ { status: 'Ativo' }, { status: { $exists: false } } ]
            }).toArray();
            
            const idsAlunosAtivos = alunosAtivos.map(a => a.id);

            if (idsAlunosAtivos.length === 0) {
                console.log('✅ [CRON] Nenhum aluno ativo encontrado. Varredura cancelada.');
                return;
            }

            // =================================================================
            // 🎈 MÓDULO 1: ANIVERSARIANTES DO DIA
            // =================================================================
            const aniversariantesPorEscola = {};
            
            alunosAtivos.forEach(aluno => {
                // Acomoda nomes de variáveis antigos e novos
                const dataNasc = aluno.nascimento || aluno.dataNascimento; 
                if (dataNasc) {
                    // O sistema é resiliente: funciona se a data for DD/MM/YYYY ou YYYY-MM-DD
                    const partes = dataNasc.includes('/') ? dataNasc.split('/') : dataNasc.split('-');
                    let mesAluno, diaAluno;
                    
                    if (dataNasc.includes('/')) {
                        diaAluno = partes[0]; mesAluno = partes[1];
                    } else {
                        // Formato padrão do seu sistema de matrículas: YYYY-MM-DD
                        mesAluno = partes[1]; diaAluno = partes[2];
                    }

                    // Verifica se é o aniversário hoje
                    if (mesAluno === mesHoje && diaAluno === diaHoje) {
                        const escolaId = aluno.escolaId || 'padrao';
                        // Inicializa o contador se for a primeira vez
                        if (!aniversariantesPorEscola[escolaId]) aniversariantesPorEscola[escolaId] = 0;
                        aniversariantesPorEscola[escolaId]++;
                    }
                }
            });

            // =================================================================
            // 💸 MÓDULO 2: MENSALIDADES PENDENTES
            // =================================================================
            const pendentes = await db.collection('financeiro').find({
                status: 'Pendente',
                vencimento: { $lte: hojeIso }, // Menor ou igual a hoje
                idAluno: { $in: idsAlunosAtivos } // Apenas de alunos ativos
            }).toArray();

            const alertasPorEscola = {};
            pendentes.forEach(fatura => {
                if (!alertasPorEscola[fatura.escolaId]) alertasPorEscola[fatura.escolaId] = 0;
                alertasPorEscola[fatura.escolaId]++;
            });

            // =================================================================
            // 🚀 MÓDULO 3: COMPILAR E ENVIAR OS AVISOS POR ESCOLA
            // =================================================================
            // O "Set" cria uma lista única fundindo as escolas que têm dívidas com as que têm aniversariantes
            const todasEscolasComNovidades = new Set([...Object.keys(alertasPorEscola), ...Object.keys(aniversariantesPorEscola)]);

            for (const escolaId of todasEscolasComNovidades) {
                const qtdFaturas = alertasPorEscola[escolaId] || 0;
                const qtdAniversariantes = aniversariantesPorEscola[escolaId] || 0;
                
                // Prevenção: Se não houver nada a avisar, salta para a próxima escola
                if (qtdFaturas === 0 && qtdAniversariantes === 0) continue;

                // Busca os telemóveis do gestor desta escola específica
                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                if (aparelhos.length === 0) continue; 

                // Monta a mensagem de texto dinamicamente
                let textoCorpo = '';
                if (qtdFaturas > 0) textoCorpo += `💸 ${qtdFaturas} cobrança(s) pendente(s).\n`;
                if (qtdAniversariantes > 0) textoCorpo += `🎈 ${qtdAniversariantes} aluno(s) faz(em) anos hoje!\n`;
                textoCorpo += 'Toque para abrir o painel.';

                const payload = JSON.stringify({
                    title: 'Bom dia! Resumo PTT 🌅',
                    body: textoCorpo,
                    url: '/' // Encaminha para a visão geral
                });

                // Dispara a notificação para cada aparelho (telemóvel ou PC) registado
                for (let aparelho of aparelhos) {
                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                        console.log(`📩 [CRON] Resumo enviado para a escola ${escolaId}!`);
                    } catch (err) {
                        // Limpeza automática: Se o telemóvel rejeitar (App desinstalada, etc), apaga da base de dados
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await db.collection('push_subscriptions').deleteOne({ _id: aparelho._id });
                        }
                    }
                }
            }
        } catch (error) {
            console.error('❌ Erro crítico no Cron de Automação:', error);
        }
    }, {
        // 🔥 Este é o parâmetro de ouro que garante a pontualidade no Brasil!
        scheduled: true,
        timezone: "America/Sao_Paulo"
    });
};

module.exports = iniciarAutomacao;