// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const iniciarAutomacao = () => {
    // ⏰ CRON JOB: Executa todos os dias às 08:00 da manhã (Horário de Brasília)
    cron.schedule('0 8 * * *', async () => {
        console.log('⏰ [CRON] A iniciar a varredura matinal do Assistente Virtual...');
        
        try {
            const db = await connectDB();
            
            const hojeObj = new Date();
            const fusoBR = new Date(hojeObj.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
            
            const hojeIso = fusoBR.toISOString().split('T')[0];
            const mesHoje = String(fusoBR.getMonth() + 1).padStart(2, '0');
            const diaHoje = String(fusoBR.getDate()).padStart(2, '0');

            // 🛡️ 1. BUSCA DE ALUNOS ATIVOS
            const alunosAtivos = await db.collection('alunos').find({
                $or: [ { status: 'Ativo' }, { status: {$exists: false } } ]
            }).toArray();
            
            const idsAlunosAtivos = alunosAtivos.map(a => a.id);

            // 🎈 MÓDULO 1: ANIVERSARIANTES DO DIA
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

            // 💸 MÓDULO 2: MENSALIDADES PENDENTES (Vencidas ou que vencem hoje)
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

            // 📅 MÓDULO 3: EVENTOS DO CALENDÁRIO DE HOJE
            const eventosHoje = await db.collection('eventos').find({ data: hojeIso }).toArray();
            const eventosPorEscola = {};
            eventosHoje.forEach(ev => {
                const escId = ev.escolaId || 'padrao';
                eventosPorEscola[escId] = (eventosPorEscola[escId] || 0) + 1;
            });

            // 📦 MÓDULO 4: ITENS COM ESTOQUE BAIXO
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

            // 🚀 MÓDULO 5: COMPILAR E ENVIAR OS AVISOS POR ESCOLA E CARGO
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
            console.error('❌ Erro crítico no Cron de Automação:', error);
        }
    }, {
        scheduled: true,
        timezone: "America/Sao_Paulo"
    });
};

module.exports = iniciarAutomacao;