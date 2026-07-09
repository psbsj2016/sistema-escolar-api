// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

// 🔑 A CORREÇÃO: Damos as chaves de acesso ao Web Push neste ficheiro isolado
webpush.setVapidDetails(
    'mailto:contato@sistemaptt.com.br', // Substitua pelo seu e-mail real se quiser
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const iniciarAutomacao = () => {
    // ⏰ CRON JOB: Para testarmos AGORA, vamos deixar a cada minuto ('* * * * *')
    // Depois do teste dar certo, troque para '0 8 * * *' (Todo dia às 8h)
    cron.schedule('* * * * *', async () => {
        console.log('⏰ [CRON] A iniciar a varredura matinal de mensalidades...');
        
        try {
            const db = await connectDB();
            const hoje = new Date().toISOString().split('T')[0];

            // 1. Busca mensalidades Pendentes que vencem hoje ou atrasadas
            const pendentes = await db.collection('financeiro').find({
                status: 'Pendente',
                vencimento: { $lte: hoje }
            }).toArray();

            if (pendentes.length === 0) {
                console.log('✅ [CRON] Nenhuma cobrança pendente para hoje.');
                return;
            }

            // 2. Agrupa por Escola
            const alertasPorEscola = {};
            pendentes.forEach(fatura => {
                if (!alertasPorEscola[fatura.escolaId]) {
                    alertasPorEscola[fatura.escolaId] = 0;
                }
                alertasPorEscola[fatura.escolaId]++;
            });

            // 3. Dispara a Notificação Push para cada escola
            for (const escolaId of Object.keys(alertasPorEscola)) {
                const quantidadeFaturas = alertasPorEscola[escolaId];
                
                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                
                if (aparelhos.length === 0) {
                    console.log(`⚠️ [CRON] Escola ${escolaId} tem pendências, mas nenhum aparelho registou notificações.`);
                    continue; 
                }

                const payload = JSON.stringify({
                    title: '💸 Lembrete de Cobrança PTT',
                    body: `Existem ${quantidadeFaturas} mensalidades vencendo hoje ou atrasadas. Toque aqui para enviar os WhatsApps.`,
                    url: '/#financeiro' 
                });

                for (let aparelho of aparelhos) {
                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                        console.log(`📩 [CRON] Notificação enviada com sucesso para o telemóvel!`);
                    } catch (err) {
                        console.error(`❌ [CRON] Erro ao enviar para um aparelho:`, err.statusCode);
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