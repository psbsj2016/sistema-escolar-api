// src/routes/avaliacoesRoutes.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const connectDB = require('../config/db'); // 🚀 LIGAÇÃO À BD REAL
const { filtroTenant } = require('../middlewares/auth'); // 🚀 IMPORTAR O CADEADO AQUI!

// 1. CRIAR NOVA AVALIAÇÃO (E AVISAR ALUNOS)
router.post('/', async (req, res) => {
    try {
        const db = await connectDB();
        // 🚀 CORREÇÃO 1: Capturamos a variável 'dataAgendada' E O 'linkSala' que vêm do formulário
        const { titulo, tipo, tempo, dataAgendada, linkSala, questoes, instrucoes, escolaId, autorNome, destino, destinoNome, tentativas } = req.body;
        
        const novaAvaliacao = {
                id: 'av_' + crypto.randomUUID(), 
            titulo, 
            tipo, 
            tempo: tempo || null, 
            dataAgendada: dataAgendada || null, // 🚀 Guardamos a data da aula online
            linkSala: linkSala || null,         // 🚀 AGORA ELE LEMBRA-SE DO LINK LOGO NA CRIAÇÃO!
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
                           id: 'notif_' + crypto.randomUUID(),
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
        if (temEntregas) return res.json({ success: false, error: "Esta sessão já foi encerrada há muito tempo e não pode ser mais editada." });
        
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
                textoAviso = `fez algumas alterações no acesso da sessão "${tituloNovo}". Confira o que mudou em <strong>Sala de Acessos</strong>.`;
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
        const { alunoId, alunoRefId, alunoNome } = req.body;
        
        const prova = await db.collection('workspace_avaliacoes').findOne({ id: id });
        if (!prova) return res.status(404).json({ success: false, error: "Prova não encontrada." });

        // Se já existir uma tentativa 'em_curso' para este aluno, reaproveita-a sem bloquear!
        const tentativaEmCurso = await db.collection('workspace_entregas_provas').findOne({
            avaliacaoId: id,
            $or: [{ alunoId: String(alunoId) }, ...(alunoRefId ? [{ alunoRefId: String(alunoRefId) }] : [])],
            status: 'em_curso'
        });

        if (tentativaEmCurso) {
            return res.json({ success: true, entregaId: tentativaEmCurso.id });
        }

        // Conta apenas as entregas realmente CONCLUÍDAS
        const tentativasFeitas = await db.collection('workspace_entregas_provas').countDocuments({
            avaliacaoId: id,
            $or: [{ alunoId: String(alunoId) }, ...(alunoRefId ? [{ alunoRefId: String(alunoRefId) }] : [])],
            status: 'concluida'
        });
        
        if (prova.tipo !== 'online' && tentativasFeitas >= (prova.tentativas || 1)) {
            return res.json({ success: false, error: "Limite de tentativas esgotado." });
        }

        const novaEntrega = {
            id: 'ent_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
            avaliacaoId: id,
            alunoId: String(alunoId),
            alunoRefId: alunoRefId ? String(alunoRefId) : null,
            alunoNome,
            status: 'em_curso', 
            dataInicio: new Date().toISOString()
        };
        await db.collection('workspace_entregas_provas').insertOne(novaEntrega);

        res.json({ success: true, entregaId: novaEntrega.id });
    } catch (error) { res.status(500).json({ success: false }); }
});

// 7. ALUNO ENTREGA AVALIAÇÃO OU REGISTA ACESSO ONLINE (USA O NOME ESCOLHIDO E A FOTO DO PERFIL NO SININHO)
router.post('/:id/entregar', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { respostas, audioUrl, alunoId, alunoRefId, alunoNome, relatorioFraude, entregaId } = req.body;

        // 1. Procura a conta do aluno na coleção 'usuarios' para obter o Nome Escolhido no Perfil e a Foto!
        let contaUser = null;
        if (alunoId) {
            contaUser = await db.collection('usuarios').findOne({
                $or: [{ id: String(alunoId) }, { alunoRefId: String(alunoId) }]
            });
        }
        if (!contaUser && alunoRefId) {
            contaUser = await db.collection('usuarios').findOne({
                $or: [{ alunoRefId: String(alunoRefId) }, { id: String(alunoRefId) }]
            });
        }

        let refIdFinal = alunoRefId ? String(alunoRefId) : (contaUser && contaUser.alunoRefId ? String(contaUser.alunoRefId) : null);
        let fichaAluno = null;
        if (refIdFinal) {
            fichaAluno = await db.collection('alunos').findOne({ id: refIdFinal });
        }

        // Nome escolhido pelo aluno no WorkSpace e a sua fotografia atual
        const nomeEscolhidoNoPerfil = (contaUser && contaUser.nome)
            ? String(contaUser.nome).trim()
            : String(alunoNome || (fichaAluno && fichaAluno.nome) || 'Aluno').trim();

        const fotoDoAluno = (contaUser && contaUser.avatar)
            ? contaUser.avatar
            : (fichaAluno && fichaAluno.avatar ? fichaAluno.avatar : null);

        let filtroBusca = entregaId 
            ? { id: entregaId } 
            : { avaliacaoId: id, $or: [{ alunoId: String(alunoId) }, ...(refIdFinal ? [{ alunoId: refIdFinal }, { alunoRefId: refIdFinal }] : [])] };

        let entrega = await db.collection('workspace_entregas_provas').findOne(filtroBusca);
        
        if (!entrega) {
            entrega = {
                id: 'ent_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                avaliacaoId: id,
                alunoId: String(alunoId),
                alunoRefId: refIdFinal,
                alunoNome: nomeEscolhidoNoPerfil
            };
            await db.collection('workspace_entregas_provas').insertOne(entrega);
        }

        const agoraIso = new Date().toISOString();
        await db.collection('workspace_entregas_provas').updateOne(
            { id: entrega.id },
            { 
                $set: { 
                    alunoId: String(alunoId),
                    alunoRefId: refIdFinal,
                    alunoNome: nomeEscolhidoNoPerfil,
                    respostas: respostas || null,
                    audioUrl: audioUrl || null,
                    relatorioFraude: relatorioFraude || { fugas: 0, tempoFora: 0 },
                    status: 'concluida',
                    dataEntrega: agoraIso
                }
            }
        );

        // 2. Gatilho de Notificações para o Professor com o Nome Escolhido e a Foto do Aluno!
        try {
            const provaOriginal = await db.collection('workspace_avaliacoes').findOne({ id: id });
            
            if (provaOriginal && provaOriginal.autorNome) {
                const escola = provaOriginal.escolaId || 'DEFAULT';
                const autorDaProva = provaOriginal.autorNome; 

                const ehOnline = provaOriginal.tipo === 'online';
                const msgNoti = ehOnline
                    ? `acessou o link da sessão: <strong>"${provaOriginal.titulo}"</strong>.`
                    : `concluiu e entregou a avaliação: <strong>"${provaOriginal.titulo}"</strong>.`;

                const novaNotificacao = {
                    id: 'notif_conv_' + crypto.randomUUID(),
                    escolaId: escola,
                    destinatarioNome: autorDaProva,
                    remetenteNome: nomeEscolhidoNoPerfil,
                    remetenteId: contaUser ? String(contaUser.id) : String(alunoId || ''),
                    remetenteAvatar: fotoDoAluno,
                    mensagem: msgNoti,
                    origem: ehOnline ? 'acesso_online' : (provaOriginal.tipo === 'oral' ? 'avaliacao_oral' : 'avaliacao_escrita'), 
                    origemId: provaOriginal.id,
                    destinoNome: 'Avaliação',
                    lida: false,
                    data: agoraIso
                };

                await db.collection('workspace_notificacoes').insertOne(novaNotificacao);

                if (global.workspaceStream) {
                    global.workspaceStream.emit('evento_realtime', { 
                        type: 'NOVA_NOTIFICACAO', destinatarios: [autorDaProva], escolaId: escola 
                    });
                    global.workspaceStream.emit('evento_realtime', { 
                        type: 'SALA_UPDATE', turmaId: provaOriginal.id, escolaId: escola 
                    });
                }
            }
        } catch (erroNoti) {
            console.error("Falha ao notificar professor sobre a entrada na sessão ao vivo.", erroNoti);
        }

        res.json({ success: true, entrega });
    } catch (error) { res.status(500).json({ success: false, error: "Erro no acesso." }); }
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
// 🚀 CORREÇÃO: Retiramos o 'filtroTenant' para impedir o crash 502 do Node.js
router.delete('/entregas/:entregaId', async (req, res) => { 
    try {
        const db = await connectDB();
        const result = await db.collection('workspace_entregas_provas').deleteOne({
            id: req.params.entregaId
        });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Não encontrado.' });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro interno.' }); }
});

// 11. REATIVAR SALA PARA TODOS (Apaga todas as presenças daquela sala)
router.delete('/:id/entregas', async (req, res) => { 
    try {
        const db = await connectDB();
        await db.collection('workspace_entregas_provas').deleteMany({
            avaliacaoId: req.params.id
        });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Erro interno.' }); }
});

// ============================================================================
// 🎫 ADICIONAR CONVIDADO VIP A UMA SESSÃO (COM NOTIFICAÇÃO)
// ============================================================================
router.post('/:id/convidados', async (req, res) => {
    try {
        const db = await connectDB();
        const { alunoId, alunoNome } = req.body;
        
        const prova = await db.collection('workspace_avaliacoes').findOne({ id: req.params.id });
        if (!prova) return res.status(404).json({ error: 'Sessão não encontrada.' });

        // Descobre se o aluno tem conta no Workspace com nome social diferente para garantir que o sininho dele toca
        const contaUser = await db.collection('usuarios').findOne({
            $or: [{ alunoRefId: String(alunoId) }, { id: String(alunoId) }]
        });
        const nomeDestinoWorkspace = (contaUser && (contaUser.nome || contaUser.login)) ? (contaUser.nome || contaUser.login) : alunoNome;

        // 1. Adiciona o aluno à lista de convidados guardando tanto o ID da matrícula quanto o ID do login
        await db.collection('workspace_avaliacoes').updateOne(
            { id: req.params.id },
            { 
                $addToSet: { 
                    convidados: { 
                        id: String(alunoId), 
                        userId: contaUser ? String(contaUser.id) : String(alunoId),
                        nome: alunoNome 
                    } 
                } 
            }
        );

        // 2. Dispara a notificação para o telemóvel/computador do aluno convidado
        const escolaId = prova.escolaId || 'DEFAULT';
        const novaNoti = {
            id: 'notif_conv_' + Date.now(),
            escolaId: escolaId,
            destinatarioNome: nomeDestinoWorkspace,
            loginDestino: contaUser ? contaUser.login : alunoNome,
            remetenteNome: prova.autorNome || 'Professor',
            mensagem: `convidou você para a sessão ao vivo: "${prova.titulo}".`,
            origem: 'online',
            origemId: prova.id,
            destinoNome: 'Sessão Privada',
            dataEvento: prova.dataAgendada,
            lida: false,
            data: new Date().toISOString()
        };
        await db.collection('workspace_notificacoes').insertOne(novaNoti);

        // 3. Grito em Tempo Real
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'NOVA_NOTIFICACAO', destinatarios: [nomeDestinoWorkspace, alunoNome], escolaId: escolaId });
            global.workspaceStream.emit('evento_realtime', { type: 'SALA_UPDATE', turmaId: req.params.id, escolaId: escolaId });
        }

        res.json({ success: true });
    } catch(e) { 
        res.status(500).json({ error: 'Erro ao adicionar convidado.' }); 
    }
});

// 🔔 PROPOSTA B: CHAMAR ALUNOS ATRASADOS QUE AINDA NÃO ENTRARAM NA SESSÃO
router.post('/:id/chamar-atrasados', async (req, res) => {
    try {
        const db = await connectDB();
        const { alunosPendentes, professorNome } = req.body;
        if (!Array.isArray(alunosPendentes) || alunosPendentes.length === 0) {
            return res.status(400).json({ error: 'Nenhum aluno pendente para chamar.' });
        }

        const prova = await db.collection('workspace_avaliacoes').findOne({ id: req.params.id });
        if (!prova) return res.status(404).json({ error: 'Sessão não encontrada.' });

        const escolaId = prova.escolaId || 'DEFAULT';
        const usuariosEscola = await db.collection('usuarios').find({ escolaId: escolaId }).toArray();

        const notificacoesParaInserir = [];
        const destinatariosSSE = [];
        const agoraIso = new Date().toISOString();

        alunosPendentes.forEach((al, idx) => {
            // Procura a conta de login do aluno pelo alunoRefId para entregar mesmo que ele tenha mudado o nome no Workspace
            const conta = usuariosEscola.find(u => 
                (u.alunoRefId && String(u.alunoRefId) === String(al.id)) ||
                (u.id && String(u.id) === String(al.id)) ||
                (u.nome && al.nome && String(u.nome).toLowerCase().trim() === String(al.nome).toLowerCase().trim())
            );

            const nomeAlvo = (conta && (conta.nome || conta.login)) ? (conta.nome || conta.login) : al.nome;
            if (!nomeAlvo) return;

            destinatariosSSE.push(nomeAlvo);
            if (al.nome && al.nome !== nomeAlvo) destinatariosSSE.push(al.nome);

            notificacoesParaInserir.push({
                id: `notif_atraso_${Date.now()}_${idx}`,
                escolaId: escolaId,
                destinatarioNome: nomeAlvo,
                loginDestino: conta ? conta.login : '',
                remetenteNome: professorNome || prova.autorNome || 'Professor',
                mensagem: `está aguardando você agora na aula ao vivo: "${prova.titulo}"! Clique para entrar.`,
                origem: 'online',
                origemId: prova.id,
                destinoNome: prova.destinoNome || 'Sala de Acessos',
                dataEvento: prova.dataAgendada,
                lida: false,
                data: agoraIso
            });
        });

        if (notificacoesParaInserir.length > 0) {
            await db.collection('workspace_notificacoes').insertMany(notificacoesParaInserir);
            if (global.workspaceStream) {
                global.workspaceStream.emit('evento_realtime', {
                    type: 'NOVA_NOTIFICACAO',
                    destinatarios: destinatariosSSE,
                    escolaId: escolaId
                });
            }
        }

        res.json({ success: true, enviados: notificacoesParaInserir.length });
    } catch (error) {
        console.error('Erro ao chamar atrasados:', error);
        res.status(500).json({ error: 'Erro interno ao enviar alerta aos alunos.' });
    }
});

// ============================================================================
// 👁️ ROTAS DE VISIBILIDADE DE ACESSO (MICRO E MACRO GESTÃO)
// ============================================================================

// 1. MICRO-GESTÃO: Ocultar/Desocultar acesso de um aluno específico
router.put('/:id/ocultar-acesso', async (req, res) => {
    try {
        const db = await connectDB();
        const { alunoId, acao } = req.body; 
        
        if (acao === 'ocultar') {
            await db.collection('workspace_avaliacoes').updateOne(
                { id: req.params.id },
                { $addToSet: { ocultos: String(alunoId) } }
            );
        } else {
            await db.collection('workspace_avaliacoes').updateOne(
                { id: req.params.id },
                { $pull: { ocultos: String(alunoId) } }
            );
        }
        
        // Grito SSE para a tela do aluno atualizar na mesma hora sem recarregar a página
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'SALA_UPDATE', turmaId: req.params.id, escolaId: 'DEFAULT' });
        }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao alterar visibilidade.' }); }
});

// 2. MACRO-GESTÃO: Ocultar/Desocultar acesso de todos os alunos ativos de uma vez
router.put('/:id/ocultar-massa', async (req, res) => {
    try {
        const db = await connectDB();
        const { alunoIds, acao } = req.body;
        
        // Garante de forma blindada que são todos strings
        const idsSeguros = alunoIds.map(id => String(id));

        if (acao === 'ocultar') {
            await db.collection('workspace_avaliacoes').updateOne(
                { id: req.params.id },
                { $addToSet: { ocultos: { $each: idsSeguros } } }
            );
        } else {
            await db.collection('workspace_avaliacoes').updateOne(
                { id: req.params.id },
                { $pull: { ocultos: { $in: idsSeguros } } }
            );
        }
        
        if (global.workspaceStream) {
            global.workspaceStream.emit('evento_realtime', { type: 'SALA_UPDATE', turmaId: req.params.id, escolaId: 'DEFAULT' });
        }
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao alterar visibilidade em massa.' }); }
});

module.exports = router;