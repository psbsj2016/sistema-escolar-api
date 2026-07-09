// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

webpush.setVapidDetails(
    'mailto:contato@sistemaptt.com.br',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const iniciarAutomacao = () => {
    // ⏰ CRON JOB: Relógio oficial definido para Todos os dias às 08:00 da manhã
    cron.schedule('0 8 * * *', async () => {
        console.log('⏰ [CRON] A iniciar a varredura matinal de mensalidades...');
        
        try {
            const db = await connectDB();
            const hoje = new Date().toISOString().split('T')[0];

            // 🛡️ 1. O FILTRO INTELIGENTE: Procurar primeiro os alunos ATIVOS
            // ($exists: false garante que alunos antigos que não tinham a variável "status" sejam considerados ativos)
            const alunosAtivos = await db.collection('alunos').find({
                $or: [ { status: 'Ativo' }, { status: { $exists: false } } ]
            }).toArray();
            
            // Extrai apenas os IDs dos alunos para uma lista rápida
            const idsAlunosAtivos = alunosAtivos.map(a => a.id);

            if (idsAlunosAtivos.length === 0) {
                console.log('✅ [CRON] Nenhum aluno ativo encontrado. Varredura cancelada.');
                return;
            }

            // 2. Busca mensalidades Pendentes APENAS dos alunos ativos! (A Mágica)
            const pendentes = await db.collection('financeiro').find({
                status: 'Pendente',
                vencimento: { $lte: hoje },
                idAluno: { $in: idsAlunosAtivos } // 👈 Filtra cruzando com a lista do passo 1
            }).toArray();

            if (pendentes.length === 0) {
                console.log('✅ [CRON] Nenhuma cobrança pendente hoje para os alunos ativos.');
                return;
            }

            // 3. Agrupa por Escola
            const alertasPorEscola = {};
            pendentes.forEach(fatura => {
                if (!alertasPorEscola[fatura.escolaId]) {
                    alertasPorEscola[fatura.escolaId] = 0;
                }
                alertasPorEscola[fatura.escolaId]++;
            });

            // 4. Dispara a Notificação Push para cada escola
            for (const escolaId of Object.keys(alertasPorEscola)) {
                const quantidadeFaturas = alertasPorEscola[escolaId];
                
                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                
                if (aparelhos.length === 0) continue; 

                const payload = JSON.stringify({
                    title: '💸 Lembrete de Cobrança PTT',
                    body: `Existem ${quantidadeFaturas} mensalidades vencendo hoje ou atrasadas (Alunos Ativos). Toque aqui para enviar os WhatsApps.`,
                    url: '/#financeiro' 
                });

                for (let aparelho of aparelhos) {
                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                        console.log(`📩 [CRON] Notificação enviada com sucesso para o telemóvel da escola ${escolaId}!`);
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
    });
};

module.exports = iniciarAutomacao;