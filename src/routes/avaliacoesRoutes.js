// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();
const connectDB = require('../config/db'); // 🚀 LIGAÇÃO À BD REAL

// 1. CRIAR NOVA AVALIAÇÃO (E AVISAR ALUNOS)
router.post('/', async (req, res) => {
    try {
        const db = await connectDB();
        // 🚀 CORREÇÃO 1: Capturamos a variável 'dataAgendada' que vem do formulário
        const { titulo, tipo, tempo, dataAgendada, questoes, instrucoes, escolaId, autorNome, destino, destinoNome, tentativas } = req.body;
        
        const novaAvaliacao = {
            id: 'av_' + Date.now(), 
            titulo, 
            tipo, 
            tempo: tempo || null, 
            dataAgendada: dataAgendada || null, // 🚀 Guardamos a data da aula online
            questoes: questoes || [], 
            instrucoes: instrucoes || '', 
            escolaId, 
            autorNome, 
            destino: destino || 'global', 
            destinoNome: destinoNome || 'Todas as Turmas', 
            tentativas: tentativas || 1, 
            dataCriacao: new Date().toISOString(), 
            ultimaAtualizacao: new Date().toISOString(), 
            status: 'ativa'
        };
        await db.collection('workspace_avaliacoes').insertOne(novaAvaliacao);

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES (PROFESSOR -> ALUNOS)
        // ====================================================================
        try {
            const escola = novaAvaliacao.escolaId || 'DEFAULT';
            
            // Descobre o Roteiro exato para a cápsula (para o 'lerEIr')
            let origemNoti = 'tarefa';
            if (tipo === 'escrita') origemNoti = 'avaliacao_escrita';
            if (tipo === 'oral') origemNoti = 'avaliacao_oral';
            if (tipo === 'online' || tipo === 'sessao_ao_vivo' || tipo === 'sessao') origemNoti = 'online';

            const alunos = await db.collection('alunos').find({ escolaId: escola }).toArray();
            
            let alunosAlvo = [];
            if (novaAvaliacao.destino === 'global') {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(novaAvaliacao.destino).toLowerCase() || String(t).toLowerCase() === String(novaAvaliacao.destinoNome).toLowerCase());
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    // 🚀 MAGIA DA DISTINÇÃO: Texto dinâmico conforme o tipo!
                    let textoAviso = '';
                    if (tipo === 'escrita' || tipo === 'oral') {
                        textoAviso = `publicou uma nova avaliação ${tipo === 'escrita' ? 'escrita' : 'oral'}: "${titulo}"`;
                    } else {
                        textoAviso = `agendou o link da aula online: "${titulo}"`;
                    }

                    return {
                        id: 'notif_' + Date.now() + Math.random().toString(36).substring(7),
                        escolaId: escola,
                        destinatarioNome: nomeAluno,
                        remetenteNome: autorNome,
                        mensagem: textoAviso, // 🚀 Texto aplicado aqui!
                        origem: origemNoti,
                        origemId: novaAvaliacao.id,
                        destinoNome: novaAvaliacao.destinoNome || 'Geral',
                        dataEvento: novaAvaliacao.dataAgendada || novaAvaliacao.tempo,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);
                    
                    // 🚀 O GRITO GLOBAL DE TEMPO REAL
                    if (global.workspaceStream) {
                        global.workspaceStream.emit('evento_realtime', { 
                            type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escola 
                        });
                    }
                }
            }
        } catch (erroNotificacao) {
            console.error("Aviso: Avaliação salva, mas falha ao gerar notificações.", erroNotificacao);
        }
        // ====================================================================

        res.json({ success: true, avaliacao: novaAvaliacao });
    } catch (error) { res.status(500).json({ success: false }); }
});
// 2. LISTAR AVALIAÇÕES DISPONÍVEIS
router.get('/', async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId } = req.query;
        const query = escolaId ? { escolaId } : {};
        const avaliacoes = await db.collection('workspace_avaliacoes').find(query).toArray();
        res.json({ success: true, avaliacoes });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 3. EDITAR AVALIAÇÃO EXISTENTE (COM AVISOS E ATUALIZAÇÃO NO BAÚ)
router.put('/:id', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        
        // Captura a prova antiga para sabermos o que mudou (importante para o Baú)
        const provaOriginal = await db.collection('workspace_avaliacoes').findOne({ id: id });
        if (!provaOriginal) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        const temEntregas = await db.collection('workspace_entregas_provas').findOne({ avaliacaoId: id });
        if (temEntregas) return res.json({ success: false, error: "Esta avaliação possui entregas e não pode ser editada." });
        
        const updateData = { ...req.body, ultimaAtualizacao: new Date().toISOString() };
        delete updateData._id; 
        delete updateData.id;

        const result = await db.collection('workspace_avaliacoes').findOneAndUpdate(
            { id: id },
            { $set: updateData },
            { returnDocument: 'after' }
        );
        
        const provaAtualizada = result.value || result;

        // ====================================================================
        // 🚀 MAGIA 1 E 2: NOTIFICAR ALUNOS SOBRE A EDIÇÃO COM DISTINÇÃO CLARA
        // ====================================================================
        try {
            const escola = provaAtualizada.escolaId || 'DEFAULT';
            const tipo = provaAtualizada.tipo;
            const tituloAntigo = provaOriginal.titulo;
            const tituloNovo = provaAtualizada.titulo;

            let origemNoti = 'tarefa';
            let textoAviso = '';

            // Distinção Clara do Texto de Edição
            if (tipo === 'escrita' || tipo === 'oral') {
                origemNoti = tipo === 'escrita' ? 'avaliacao_escrita' : 'avaliacao_oral';
                textoAviso = `alterou os dados da avaliação ${tipo}: "${tituloNovo}". Fique atento aos prazos!`;
            } else {
                origemNoti = 'online_edit';
                textoAviso = `alterou a data/hora ou link da aula online: "${tituloNovo}". Fique atento!`;
            }

            const alunos = await db.collection('alunos').find({ escolaId: escola }).toArray();

            let alunosAlvo = [];
            if (provaAtualizada.destino === 'global') {
                alunosAlvo = alunos;
            } else {
                alunosAlvo = alunos.filter(a => {
                    const minhasTurmas = Array.isArray(a.turmas) ? a.turmas : [a.turmas, a.turma, a.turmaId];
                    return minhasTurmas.some(t => String(t).toLowerCase() === String(provaAtualizada.destino).toLowerCase() || String(t).toLowerCase() === String(provaAtualizada.destinoNome).toLowerCase());
                });
            }

            if (alunosAlvo.length > 0) {
                const nomesDestinatarios = [];
                const notificacoesArray = alunosAlvo.map(aluno => {
                    const nomeAluno = aluno.nome || aluno.login;
                    if (nomeAluno) nomesDestinatarios.push(nomeAluno);
                    return {
                        id: 'notif_edit_' + Date.now() + Math.random().toString(36).substring(7),
                        escolaId: escola,
                        destinatarioNome: nomeAluno,
                        remetenteNome: provaAtualizada.autorNome || 'Professor',
                        mensagem: textoAviso,
                        origem: origemNoti,
                        origemId: provaAtualizada.id,
                        destinoNome: provaAtualizada.destinoNome || 'Geral',
                        dataEvento: provaAtualizada.dataAgendada || provaAtualizada.tempo,
                        lida: false,
                        data: new Date().toISOString()
                    };
                }).filter(n => n.destinatarioNome);

                if (notificacoesArray.length > 0) {
                    await db.collection('workspace_notificacoes').insertMany(notificacoesArray);

                    // Toca o sininho de todos os alunos instantaneamente!
                    if (global.workspaceStream) {
                        global.workspaceStream.emit('evento_realtime', {
                            type: 'NOVA_NOTIFICACAO', destinatarios: nomesDestinatarios, escolaId: escola
                        });
                    }
                }
            }

            // ====================================================================
            // 🚀 MAGIA 3: ATUALIZAR O CALENDÁRIO DO BAÚ DOS ALUNOS SILENCIOSAMENTE
            // ====================================================================
            if (tipo === 'online') {
                let dataMs;
                const stringData = provaAtualizada.dataAgendada || provaAtualizada.tempo;
                
                // 🚀 O SEGREDO DO FUSO HORÁRIO (BACKEND): O servidor na nuvem usa UTC (Londres).
                // Ao forçar ':00-03:00' na string, obrigamos o servidor a gerar o Timestamp exato do Brasil!
                if (stringData && stringData.includes('T')) {
                    const dataFixada = stringData.length === 16 ? stringData + ':00-03:00' : stringData;
                    dataMs = new Date(dataFixada).getTime();
                } else {
                    dataMs = new Date(stringData).getTime();
                }
                
                // Busca os alarmes na base de dados que tinham o título antigo
                const mensagemAntigaRegex = new RegExp(`Aula Online: ${tituloAntigo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`);
                
                await db.collection('workspace_bau_alarmes').updateMany(
                    { mensagem: { $regex: mensagemAntigaRegex } },
                    { $set: { 
                        mensagem: `Aula Online: ${tituloNovo} (com ${provaAtualizada.autorNome || 'Professor'})`,
                        tempoDisparo: dataMs 
                      } 
                    }
                );
                
                // Grito SSE para forçar o Baú dos alunos online a recarregar o calendário
                if (global.workspaceStream) {
                    global.workspaceStream.emit('evento_realtime', {
                        type: 'BAU_UPDATE', escolaId: escola
                    });
                }
            }

        } catch (errNoti) {
            console.error("Aviso: Falha ao notificar/atualizar edição", errNoti);
        }

        res.json({ success: true, avaliacao: provaAtualizada });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 4. MUDAR STATUS
router.patch('/:id/status', async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_avaliacoes').updateOne(
            { id: req.params.id },
            { $set: { status: req.body.status, ultimaAtualizacao: new Date().toISOString() } }
        );
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 5. EXCLUIR AVALIAÇÃO DEFINITIVAMENTE
router.delete('/:id', async (req, res) => {
    try {
        const db = await connectDB();
        await db.collection('workspace_avaliacoes').deleteOne({ id: req.params.id });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

// ==========================================
// 🚀 ETAPA C: ROTAS DO BANCO DE QUESTÕES
// ==========================================
router.post('/banco-questoes', async (req, res) => {
    try {
        const db = await connectDB();
        const { questao, escolaId } = req.body;
        const novaQuestaoBanco = {
            id: 'qbank_' + Date.now() + Math.floor(Math.random() * 1000),
            escolaId: escolaId || 'DEFAULT',
            tipo: questao.tipo,
            pergunta: questao.pergunta,
            opcoes: questao.opcoes || null,
            respostaCorreta: questao.respostaCorreta || null,
            dataGuardado: new Date().toISOString()
        };
        await db.collection('workspace_banco_questoes').insertOne(novaQuestaoBanco);
        res.json({ success: true, questao: novaQuestaoBanco });
    } catch (error) { res.status(500).json({ success: false }); }
});

router.get('/banco-questoes', async (req, res) => {
    try {
        const db = await connectDB();
        const { escolaId } = req.query;
        const query = escolaId ? { escolaId } : {};
        const questoes = await db.collection('workspace_banco_questoes').find(query).toArray();
        res.json({ success: true, questoes });
    } catch (error) { res.status(500).json({ success: false }); }
});
// ==========================================

// 6. ALUNO INICIA AVALIAÇÃO
router.post('/:id/iniciar', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { alunoId, alunoNome } = req.body;
        
        const prova = await db.collection('workspace_avaliacoes').findOne({ id: id });
        if (!prova) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        const tentativasFeitas = await db.collection('workspace_entregas_provas').countDocuments({ avaliacaoId: id, alunoId: alunoId });
        
        if (tentativasFeitas >= (prova.tentativas || 1)) {
            return res.json({ success: false, error: "Limite de tentativas esgotado." });
        }

        const novaEntrega = {
            id: 'ent_' + Date.now(),
            avaliacaoId: id,
            alunoId,
            alunoNome,
            status: 'em_curso', 
            dataInicio: new Date().toISOString()
        };
        await db.collection('workspace_entregas_provas').insertOne(novaEntrega);

        res.json({ success: true, entregaId: novaEntrega.id });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 7. ALUNO ENTREGA AVALIAÇÃO (E AVISA O PROFESSOR)
router.post('/:id/entregar', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, relatorioFraude, entregaId } = req.body;
        
        let entrega = await db.collection('workspace_entregas_provas').findOne({ id: entregaId, alunoId: alunoId });
        
        if (!entrega) {
            entrega = { id: 'ent_' + Date.now(), avaliacaoId: id, alunoId, alunoNome: req.body.alunoNome };
            await db.collection('workspace_entregas_provas').insertOne(entrega);
        }

        await db.collection('workspace_entregas_provas').updateOne(
            { id: entrega.id },
            { $set: { 
                respostas: respostas || null,
                audioUrl: audioUrl || null,
                relatorioFraude: relatorioFraude || { fugas: 0, tempoFora: 0 },
                status: 'concluida',
                dataEntrega: new Date().toISOString()
            }}
        );

        // ====================================================================
        // 🚀 O GATILHO DE NOTIFICAÇÕES (ALUNO -> PROFESSOR CRIADOR DA PROVA)
        // ====================================================================
        try {
            const provaOriginal = await db.collection('workspace_avaliacoes').findOne({ id: id });
            
            if (provaOriginal && provaOriginal.autorNome) {
                const escola = provaOriginal.escolaId || 'DEFAULT';
                const autorDaProva = provaOriginal.autorNome; 
                const nomeDoAluno = req.body.alunoNome || 'Um aluno';

                const novaNotificacao = {
                    id: 'notif_' + Date.now() + Math.random().toString(36).substring(7),
                    escolaId: escola,
                    destinatarioNome: autorDaProva,
                    remetenteNome: nomeDoAluno,
                    mensagem: `entregou a atividade: "${provaOriginal.titulo}".`,
                    origem: 'tarefa', 
                    origemId: provaOriginal.id,
                    destinoNome: 'Avaliação',
                    lida: false,
                    data: new Date().toISOString()
                };

                await db.collection('workspace_notificacoes').insertOne(novaNotificacao);

                // 🚀 Grito em Tempo Real apenas para o Professor!
                if (global.workspaceStream) {
                    global.workspaceStream.emit('evento_realtime', { 
                        type: 'NOVA_NOTIFICACAO', destinatarios: [autorDaProva], escolaId: escola 
                    });
                }
            }
        } catch (erroNoti) {
            console.error("Falha ao notificar professor sobre a entrega da prova.", erroNoti);
        }
        // ====================================================================

        res.json({ success: true, entrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro na entrega." }); }
});

// 8. PROFESSOR BUSCA TODAS AS ENTREGAS
router.get('/entregas', async (req, res) => {
    try { 
        const db = await connectDB();
        const entregas = await db.collection('workspace_entregas_provas').find({ status: 'concluida' }).toArray();
        res.json({ success: true, entregas });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 9. ALUNO BUSCA AS SUAS PRÓPRIAS ENTREGAS
router.get('/minhas-entregas/:alunoId', async (req, res) => {
    try {
        const db = await connectDB();
        const entregas = await db.collection('workspace_entregas_provas').find({ alunoId: req.params.alunoId }).toArray();
        res.json({ success: true, entregas });
    } catch (error) { res.status(500).json({ success: false }); }
});

// ============================================================================
// 🚀 ETAPA D: REATIVAÇÃO DE ACESSOS (SESSÕES E AVALIAÇÕES)
// ============================================================================

// 10. REATIVAR ACESSO INDIVIDUAL (Apaga a presença de 1 aluno específico)
// Rota acionada no frontend via: DELETE /workspace/avaliacoes/entregas/:entregaId
router.delete('/entregas/:entregaId', async (req, res) => {
    try {
        const db = await connectDB();
        
        // 🚀 O SEGREDO: Fomos à gaveta exata onde a presença foi criada!
        const result = await db.collection('workspace_entregas_provas').deleteOne({ 
            id: req.params.entregaId 
        });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, error: "Registo não encontrado na base de dados." });
        }
        
        res.json({ success: true, message: "Acesso reativado com sucesso!" });
    } catch (error) { 
        console.error("Erro ao reativar aluno:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

// 11. REATIVAR SALA PARA TODOS (Apaga todas as presenças daquela sala)
// Rota acionada no frontend via: DELETE /workspace/avaliacoes/:id/entregas
router.delete('/:id/entregas', async (req, res) => {
    try {
        const db = await connectDB();
        
        // 🚀 O SEGREDO: Limpa todos os documentos da gaveta correspondentes a esta sala
        await db.collection('workspace_entregas_provas').deleteMany({ 
            avaliacaoId: req.params.id 
        });
        
        res.json({ success: true, message: "Sala reativada para todos!" });
    } catch (error) { 
        console.error("Erro ao limpar sala:", error);
        res.status(500).json({ success: false, error: "Erro interno no servidor." }); 
    }
});

module.exports = router;