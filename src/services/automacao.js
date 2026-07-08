// src/services/automacao.js
const cron = require('node-cron');
const connectDB = require('../config/db');
const webpush = require('web-push');

const iniciarAutomacao = () => {
    // ⏰ O CRON JOB: '0 8 * * *' significa "Todos os dias às 08:00 da manhã"
    // (Dica: Para testar agora mesmo, mude para '* * * * *' que significa "A cada minuto")
    cron.schedule('* * * * *', async () => {
        console.log('⏰ [CRON] A iniciar a varredura matinal de mensalidades...');
        
        try {
            const db = await connectDB();
            
            // Pega a data de hoje no formato YYYY-MM-DD
            const hoje = new Date().toISOString().split('T')[0];

            // 1. Busca TODAS as mensalidades Pendentes que vencem hoje ou que já passaram (atrasadas)
            const pendentes = await db.collection('financeiro').find({
                status: 'Pendente',
                vencimento: { $lte: hoje } // $lte significa "Menor ou igual a hoje"
            }).toArray();

            if (pendentes.length === 0) {
                console.log('✅ [CRON] Nenhuma cobrança pendente para hoje.');
                return;
            }

            // 2. Agrupa a contagem por Escola (para não enviar dados da Escola A para a Escola B)
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
                
                // Vai buscar os telemóveis/PCs registados desta escola específica
                const aparelhos = await db.collection('push_subscriptions').find({ escolaId: escolaId }).toArray();
                
                if (aparelhos.length === 0) continue; // Se o diretor não ativou as notificações, saltamos

                // A mensagem que vai aparecer no ecrã bloqueado do Diretor
                const payload = JSON.stringify({
                    title: '💸 Lembrete de Cobrança',
                    body: `Existem ${quantidadeFaturas} mensalidades vencendo hoje ou atrasadas. Toque aqui para enviar os WhatsApps.`,
                    url: '/#financeiro' // Quando ele clicar, a app abre direto na aba financeira!
                });

                // Envia o sinal para os aparelhos
                for (let aparelho of aparelhos) {
                    try {
                        await webpush.sendNotification(aparelho.subscription, payload);
                    } catch (err) {
                        // Limpa o aparelho se a pessoa desinstalou a app
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await db.collection('push_subscriptions').deleteOne({ _id: aparelho._id });
                        }
                    }
                }
            }
            
            console.log('📩 [CRON] Varredura concluída. Alertas enviados!');

        } catch (error) {
            console.error('❌ Erro no Cron de Automação:', error);
        }
    });
};

module.exports = iniciarAutomacao;