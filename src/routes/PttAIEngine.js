// ============================================================================
// 🧠 PTT AI ENGINE 2.5 - CÉREBRO HÍBRIDO COM MEMÓRIA ETERNA EM NUVEM (MONGODB)
// ============================================================================
const natural = require('natural');
const fs = require('fs');
const path = require('path');
const Groq = require('groq-sdk');
const connectDB = require('../config/db');

const BRAIN_PATH = path.join(__dirname, 'ptt_brain.json');
const RESPONSES_PATH = path.join(__dirname, 'ptt_responses.json');
const CORRECTIONS_PATH = path.join(__dirname, 'ptt_corrections.json');
const DOC_MEMORIA_ID = 'PTT_AI_MEMORIA_MESTRA';

class PttAIEngine {
    constructor() {
        this.classifier = new natural.BayesClassifier();
        this.isTrained = false;
        this.respostas = {}; 
        this.correcoes = {}; 
        this.exemplosTreino = [];
    }

    obterPadroesIniciais() {
        return {
            respostas: {
                'saudacao': ["Greetings! I am the Ptt AI. I am ready to test your English skills. What is on your mind today?"],
                'concordar': ["It is good that we are in harmony about [TEMA]. But we must always question things. Can you think of an exception?"],
                'discordar': ["A rebellious mind! I like that you disagree about [TEMA]. Can you give me one solid example to prove your point?"],
                'pergunta': ["A very wise question about [TEMA]. Seeking knowledge is the first step to fluency. How would you try to answer that yourself first?"]
            },
            correcoes: {
                "teatcher": "teacher",
                "confortable": "comfortable",
                "he dont": "he doesn't",
                "she dont": "she doesn't",
                "i is": "I am",
                "more better": "better",
                "informations": "information"
            },
            exemplosTreino: [
                { frase: 'hello good morning', categoria: 'saudacao' },
                { frase: 'hi there how are you', categoria: 'saudacao' },
                { frase: 'i agree with you', categoria: 'concordar' },
                { frase: 'yes that is completely true', categoria: 'concordar' },
                { frase: 'i disagree with that', categoria: 'discordar' },
                { frase: 'no that is wrong and false', categoria: 'discordar' },
                { frase: 'why is that happening?', categoria: 'pergunta' },
                { frase: 'how can i do this?', categoria: 'pergunta' }
            ]
        };
    }

    async init() {
        const padroes = this.obterPadroesIniciais();
        this.respostas = { ...padroes.respostas };
        this.correcoes = { ...padroes.correcoes };
        this.exemplosTreino = [...padroes.exemplosTreino];

        // 1. Tenta carregar primeiro dos ficheiros locais (se existirem)
        if (fs.existsSync(RESPONSES_PATH)) {
            try { this.respostas = { ...this.respostas, ...JSON.parse(fs.readFileSync(RESPONSES_PATH, 'utf8')) }; } catch(e) {}
        }
        if (fs.existsSync(CORRECTIONS_PATH)) {
            try { this.correcoes = { ...this.correcoes, ...JSON.parse(fs.readFileSync(CORRECTIONS_PATH, 'utf8')) }; } catch(e) {}
        }

        // 2. Carrega e sincroniza com a Memória Eterna no MongoDB (sobrevive a deploys no Render!)
        try {
            const db = await connectDB();
            const docNuvem = await db.collection('workspace_ingles_data').findOne({ escolaId: DOC_MEMORIA_ID });
            if (docNuvem) {
                if (docNuvem.respostas) this.respostas = { ...this.respostas, ...docNuvem.respostas };
                if (docNuvem.correcoes) this.correcoes = { ...this.correcoes, ...docNuvem.correcoes };
                if (Array.isArray(docNuvem.exemplosTreino) && docNuvem.exemplosTreino.length > 0) {
                    this.exemplosTreino = docNuvem.exemplosTreino;
                }
            } else {
                await this.salvarNaNuvem();
            }
        } catch (errDB) {
            console.warn("⚠️ Ptt AI: A usar memória local (MongoDB ainda a conectar).");
        }

        // 3. Reconstrói e treina o classificador Bayesiano com todos os exemplos
        this.classifier = new natural.BayesClassifier();
        this.exemplosTreino.forEach(item => {
            if (item && item.frase && item.categoria) {
                this.classifier.addDocument(item.frase.toLowerCase(), item.categoria);
            }
        });

        await this.treinar();
        console.log("🧠 Ptt AI 2.5: Cérebro Híbrido + Memória na Nuvem inicializados!");
    }

    async salvarNaNuvem() {
        try {
            const db = await connectDB();
            await db.collection('workspace_ingles_data').updateOne(
                { escolaId: DOC_MEMORIA_ID },
                { 
                    $set: { 
                        respostas: this.respostas, 
                        correcoes: this.correcoes, 
                        exemplosTreino: this.exemplosTreino,
                        ultimaAtualizacao: new Date().toISOString()
                    } 
                },
                { upsert: true }
            );
        } catch (e) {
            console.error("🚨 Erro ao guardar cérebro da Ptt AI no MongoDB:", e);
        }
    }

    async treinar() {
        return new Promise((resolve) => {
            try {
                this.classifier.train();
                this.isTrained = true;
                this.classifier.save(BRAIN_PATH, () => {
                    try {
                        fs.writeFileSync(RESPONSES_PATH, JSON.stringify(this.respostas, null, 2));
                        fs.writeFileSync(CORRECTIONS_PATH, JSON.stringify(this.correcoes, null, 2));
                    } catch (e) {}
                    resolve();
                });
            } catch (e) {
                this.isTrained = true;
                resolve();
            }
        });
    }

    async ensinarNovaFrase(frase, categoria, respostaDesejada) {
        const fraseLimpa = String(frase).toLowerCase().trim();
        const catLimpa = String(categoria).toLowerCase().trim();

        this.classifier.addDocument(fraseLimpa, catLimpa);
        const jaExiste = this.exemplosTreino.some(e => e.frase === fraseLimpa && e.categoria === catLimpa);
        if (!jaExiste) {
            this.exemplosTreino.push({ frase: fraseLimpa, categoria: catLimpa });
        }

        if (respostaDesejada && respostaDesejada.trim() !== '') {
            if (!this.respostas[catLimpa]) this.respostas[catLimpa] = [];
            if (!this.respostas[catLimpa].includes(respostaDesejada.trim())) {
                this.respostas[catLimpa].push(respostaDesejada.trim());
            }
        }

        await this.treinar();
        await this.salvarNaNuvem();
        return `A Ptt AI aprendeu permanentemente que "${frase}" significa "${catLimpa}".`;
    }

    async ensinarCorrecao(erro, certo) {
        const erroLimpo = String(erro).toLowerCase().replace(/[^a-z0-9 ]/g, '').trim();
        this.correcoes[erroLimpo] = String(certo).trim();
        try {
            fs.writeFileSync(CORRECTIONS_PATH, JSON.stringify(this.correcoes, null, 2));
        } catch (e) {}
        await this.salvarNaNuvem();
        return `A Ptt AI agora vai bloquear permanentemente "${erro}" e exigir "${certo}".`;
    }

    extrairTema(frase) {
        let limpa = frase.toLowerCase();
        const ruido = [
            'i think that', 'i believe that', 'i agree with', 'i completely agree that', 
            'i disagree with', 'i dont think', 'because', 'yes', 'no', 'absolutely', 
            'in my opinion', 'to me', 'i love', 'i like', 'i hate'
        ];
        ruido.forEach(termo => { limpa = limpa.replace(new RegExp(`\\b${termo}\\b`, 'gi'), ''); });
        limpa = limpa.replace(/[^a-z0-9 ]/g, '').trim();
        return limpa.length > 2 ? limpa : "this topic";
    }

    async pensar(fraseDoAluno, historico = []) {
        if (!this.isTrained) return { intencaoDetetada: 'unknown', resposta: "I am still learning..." };

        const textoNormalizado = fraseDoAluno.toLowerCase();
        const textoSemPontuacao = textoNormalizado.replace(/[^a-z0-9 ]/g, '');

        // 🛡️ CAMADA 1: O OLHEIRO ORTOGRÁFICO (REGRAS DO PROFESSOR)
        for (const [erro, certo] of Object.entries(this.correcoes)) {
            const regexErro = new RegExp(`\\b${erro}\\b`, 'i');
            
            if (regexErro.test(textoSemPontuacao)) {
                return {
                    intencaoDetetada: 'correcao_pedagogica',
                    bastidoresAviso: `Erro grave detetado e travado: [${erro} -> ${certo}]`,
                    resposta: `Wait a second, wizard! 🧙‍♂️ I noticed a small mistake. You wrote "${erro}", but the correct form is "${certo}". Please, rewrite your sentence correctly so we can continue!`
                };
            }
        }

        // 🧠 CAMADA 2: O CÉREBRO GERATIVO (GROQ + MEMÓRIA)
        try {
            const chaveApi = process.env.GROQ_API_KEY;
            if (!chaveApi) throw new Error("Chave Groq Ausente");

            const groq = new Groq({ apiKey: chaveApi.trim() });

            const systemPrompt = `
            Você é a 'PTT AI', uma professora de inglês hiper-inteligente, paciente e motivadora da Ptt Cursos.
            
            Regras de Ouro:
            1. Responda de forma natural, coloquial e imersiva em INGLÊS.
            2. Se o aluno cometer erros gramaticais leves, corrija-o gentilmente antes de continuar o assunto.
            3. Se o aluno pedir uma explicação complexa sobre gramática, PODE USAR O PORTUGUÊS para explicar, mas dê os exemplos em Inglês.
            4. Seja direta e concisa (máximo 4 frases).
            5. Termine SEMPRE a sua mensagem com uma pergunta relacionada para manter a conversa ativa.
            `;

            const mensagensFormatadas = [
                { role: 'system', content: systemPrompt },
                ...historico,
                { role: 'user', content: fraseDoAluno }
            ];

            const completion = await groq.chat.completions.create({
                messages: mensagensFormatadas,
                model: 'openai/gpt-oss-120b',
                temperature: 0.7 
            });

            return { 
                intencaoDetetada: 'conversacao_fluida_groq', 
                resposta: completion.choices[0].message.content.trim() 
            };

        } catch (error) {
            console.error("🚨 Groq falhou ou limitou. Acionando Cérebro Local de Emergência...");

            // ⚙️ CAMADA 3: CÉREBRO DE EMERGÊNCIA (BAYESIANO)
            const intencao = this.classifier.classify(textoNormalizado);
            const temaExtraido = this.extrairTema(fraseDoAluno);

            let respostaGerada = "That's an interesting point about " + temaExtraido + ". Tell me more!";
            if (this.respostas[intencao] && this.respostas[intencao].length > 0) {
                const arrayDeRespostas = this.respostas[intencao];
                respostaGerada = arrayDeRespostas[Math.floor(Math.random() * arrayDeRespostas.length)];
            }
            respostaGerada = respostaGerada.replace(/[TEMA]/g, temaExtraido);

            return { 
                intencaoDetetada: `emergencia_${intencao}`, 
                resposta: respostaGerada 
            };
        }
    }
}

const motorPtt = new PttAIEngine();
module.exports = motorPtt;