// ============================================================================
// 🧠 PTT AI ENGINE 2.0 - O CÉREBRO HÍBRIDO (LOCAL + GROQ)
// ============================================================================
const natural = require('natural');
const fs = require('fs');
const path = require('path');
const Groq = require('groq-sdk'); // 🚀 NOVO: Adicionado SDK do Groq

const BRAIN_PATH = path.join(__dirname, 'ptt_brain.json');
const RESPONSES_PATH = path.join(__dirname, 'ptt_responses.json');
const CORRECTIONS_PATH = path.join(__dirname, 'ptt_corrections.json');

class PttAIEngine {
    constructor() {
        this.classifier = new natural.BayesClassifier();
        this.isTrained = false;
        this.respostas = {}; 
        this.correcoes = {}; 
    }

    async init() {
        // 1. Carrega as Respostas Locais (Camada de Emergência)
        if (fs.existsSync(RESPONSES_PATH)) {
            try { this.respostas = JSON.parse(fs.readFileSync(RESPONSES_PATH, 'utf8')); } 
            catch(e) { this.respostas = {}; }
        } else {
            this.respostas = {
                'saudacao': ["Greetings! I am the Ptt AI. I am ready to test your English skills. What is on your mind today?"],
                'concordar': ["It is good that we are in harmony about [TEMA]. But we must always question things. Can you think of an exception?"],
                'discordar': ["A rebellious mind! I like that you disagree about [TEMA]. Can you give me one solid example to prove your point?"],
                'pergunta': ["A very wise question about [TEMA]. Seeking knowledge is the first step to fluency. How would you try to answer that yourself first?"]
            };
            fs.writeFileSync(RESPONSES_PATH, JSON.stringify(this.respostas, null, 2));
        }

        // 2. Carrega o Olheiro Ortográfico (Camada de Ferro)
        if (fs.existsSync(CORRECTIONS_PATH)) {
            try { this.correcoes = JSON.parse(fs.readFileSync(CORRECTIONS_PATH, 'utf8')); } 
            catch(e) { this.correcoes = {}; }
        } else {
            this.correcoes = {
                "teatcher": "teacher",
                "confortable": "comfortable",
                "he dont": "he doesn't",
                "she dont": "she doesn't",
                "i is": "I am",
                "more better": "better",
                "informations": "information"
            };
            fs.writeFileSync(CORRECTIONS_PATH, JSON.stringify(this.correcoes, null, 2));
        }

        return new Promise((resolve) => {
            if (fs.existsSync(BRAIN_PATH)) {
                natural.BayesClassifier.load(BRAIN_PATH, null, (err, classifier) => {
                    if (!err && classifier) {
                        this.classifier = classifier;
                        this.isTrained = true;
                        console.log("🧠 Ptt AI 2.0: Cérebro Híbrido inicializado!");
                    }
                    resolve();
                });
            } else {
                this.ensinarBasico();
                this.treinar().then(resolve);
            }
        });
    }

    ensinarBasico() {
        this.classifier.addDocument('hello good morning', 'saudacao');
        this.classifier.addDocument('hi there how are you', 'saudacao');
        this.classifier.addDocument('i agree with you', 'concordar');
        this.classifier.addDocument('yes that is completely true', 'concordar');
        this.classifier.addDocument('i disagree with that', 'discordar');
        this.classifier.addDocument('no that is wrong and false', 'discordar');
        this.classifier.addDocument('why is that happening?', 'pergunta');
        this.classifier.addDocument('how can i do this?', 'pergunta');
    }

    async treinar() {
        return new Promise((resolve) => {
            this.classifier.train();
            this.isTrained = true;
            this.classifier.save(BRAIN_PATH, (err) => {
                if (err) console.error("🚨 Erro ao gravar o cérebro:", err);
                fs.writeFileSync(RESPONSES_PATH, JSON.stringify(this.respostas, null, 2));
                resolve();
            });
        });
    }

    async ensinarNovaFrase(frase, categoria, respostaDesejada) {
        this.classifier.addDocument(frase.toLowerCase(), categoria);
        if (respostaDesejada && respostaDesejada.trim() !== '') {
            if (!this.respostas[categoria]) this.respostas[categoria] = [];
            if (!this.respostas[categoria].includes(respostaDesejada)) {
                this.respostas[categoria].push(respostaDesejada);
            }
        }
        await this.treinar();
        return `A Ptt AI aprendeu que "${frase}" significa "${categoria}".`;
    }

    async ensinarCorrecao(erro, certo) {
        const erroLimpo = erro.toLowerCase().replace(/[^a-z0-9 ]/g, '').trim();
        this.correcoes[erroLimpo] = certo;
        fs.writeFileSync(CORRECTIONS_PATH, JSON.stringify(this.correcoes, null, 2));
        return `A Ptt AI agora vai bloquear "${erro}" e exigir "${certo}".`;
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

    // ====================================================================
    // 🚀 O NOVO PENSAMENTO HÍBRIDO (AGORA É ASSÍNCRONO)
    // ====================================================================
    async pensar(fraseDoAluno, historico = []) {
        if (!this.isTrained) return { intencaoDetetada: 'unknown', resposta: "I am still learning..." };

        const textoNormalizado = fraseDoAluno.toLowerCase();
        const textoSemPontuacao = textoNormalizado.replace(/[^a-z0-9 ]/g, '');

        // 🛡️ CAMADA 1: O OLHEIRO ORTOGRÁFICO (REGRAS LOCAIS)
        for (const [erro, certo] of Object.entries(this.correcoes)) {
            const regexErro = new RegExp(`\\b${erro}\\b`, 'i');
            
            if (regexErro.test(textoSemPontuacao)) {
                return {
                    intencaoDetetada: 'correcao_pedagogica',
                    bastidoresAviso: `Erro grave detetado e travado: [${erro}]`,
                    resposta: `Wait a second, wizard! 🧙‍♂️ I noticed a small mistake. You wrote "**${erro}**", but the correct form is "**${certo}**". Please, rewrite your sentence correctly so we can continue!`
                };
            }
        }

        // 🧠 CAMADA 2: O CÉREBRO GERATIVO (GROQ + MEMÓRIA)
        try {
            const chaveApi = process.env.GROQ_API_KEY;
            if (!chaveApi) throw new Error("Chave Groq Ausente");

            const groq = new Groq({ apiKey: chaveApi.trim() });

            // A Personalidade da sua IA ganha vida aqui!
            const systemPrompt = `
            Você é a 'PTT AI', uma professora de inglês hiper-inteligente, paciente e motivadora da Ptt Cursos.
            
            Regras de Ouro:
            1. Responda de forma natural, coloquial e imersiva em INGLÊS.
            2. Se o aluno cometer erros gramaticais leves, corrija-o gentilmente antes de continuar o assunto.
            3. Se o aluno pedir uma explicação complexa sobre gramática, PODE USAR O PORTUGUÊS para explicar, mas dê os exemplos em Inglês.
            4. Seja direta e concisa (máximo 4 frases).
            5. Termine SEMPRE a sua mensagem com uma pergunta relacionada para manter a conversa ativa.
            `;

            // Junta a personalidade, o que eles conversaram antes, e a nova pergunta!
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

            // ⚙️ CAMADA 3: CÉREBRO DE EMERGÊNCIA (Baseado no seu código antigo)
            const intencao = this.classifier.classify(textoNormalizado);
            const temaExtraido = this.extrairTema(fraseDoAluno);

            let respostaGerada = "That's an interesting point about " + temaExtraido + ". Tell me more!";
            if (this.respostas[intencao] && this.respostas[intencao].length > 0) {
                const arrayDeRespostas = this.respostas[intencao];
                respostaGerada = arrayDeRespostas[Math.floor(Math.random() * arrayDeRespostas.length)];
            }
            respostaGerada = respostaGerada.replace(/\[TEMA\]/g, temaExtraido);

            return { 
                intencaoDetetada: `emergencia_${intencao}`, 
                resposta: respostaGerada 
            };
        }
    }
}

const motorPtt = new PttAIEngine();
module.exports = motorPtt;