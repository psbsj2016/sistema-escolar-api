// ============================================================================
// 🧠 PTT AI ENGINE - O CÉREBRO DINÂMICO E ESCALÁVEL DA PTT CURSOS
// ============================================================================
const natural = require('natural');
const fs = require('fs');
const path = require('path');

const BRAIN_PATH = path.join(__dirname, 'ptt_brain.json');
const RESPONSES_PATH = path.join(__dirname, 'ptt_responses.json');
const CORRECTIONS_PATH = path.join(__dirname, 'ptt_corrections.json'); // 🚀 NOVO: O Cofre de Correções

class PttAIEngine {
    constructor() {
        this.classifier = new natural.BayesClassifier();
        this.isTrained = false;
        this.respostas = {}; 
        this.correcoes = {}; // 🚀 O Olheiro Ortográfico
    }

    async init() {
        // 1. Carrega as Respostas
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

        // 2. 🚀 Carrega o Olheiro Ortográfico
        if (fs.existsSync(CORRECTIONS_PATH)) {
            try { this.correcoes = JSON.parse(fs.readFileSync(CORRECTIONS_PATH, 'utf8')); } 
            catch(e) { this.correcoes = {}; }
        } else {
            // Alguns erros clássicos para a máquina já nascer inteligente
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
                        console.log("🧠 Ptt AI: Cérebro, Respostas e Correções carregados!");
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

    // 🚀 NOVO: O Professor dita uma nova regra gramatical
    async ensinarCorrecao(erro, certo) {
        // Limpa o erro para o formato padrão, sem símbolos
        const erroLimpo = erro.toLowerCase().replace(/[^a-z0-9 ]/g, '').trim();
        this.correcoes[erroLimpo] = certo;
        
        // Grava no cofre de correções
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

    pensar(fraseDoAluno) {
        if (!this.isTrained) return { intencaoDetetada: 'unknown', resposta: "I am still learning..." };

        const textoNormalizado = fraseDoAluno.toLowerCase();
        
        // ====================================================================
        // 🚀 O INTERCETOR: Olheiro Ortográfico entra em ação!
        // ====================================================================
        // A máquina limpa pontos de interrogação para analisar só as palavras
        const textoSemPontuacao = textoNormalizado.replace(/[^a-z0-9 ]/g, '');
        
        for (const [erro, certo] of Object.entries(this.correcoes)) {
            // Procura o erro exato no meio da frase do aluno
            const regexErro = new RegExp(`\\b${erro}\\b`, 'i');
            
            if (regexErro.test(textoSemPontuacao)) {
                // Se encontrar o erro, ELA PARA TUDO! E exige que o aluno escreva de novo.
                return {
                    intencaoDetetada: 'correcao_pedagogica',
                    bastidoresAviso: `Erro detetado: [${erro}] -> [${certo}]`,
                    resposta: `Wait a second, wizard! 🧙‍♂️ I noticed a small mistake. You wrote "**${erro}**", but the correct form is "**${certo}**". Please, rewrite your sentence correctly so we can continue!`
                };
            }
        }
        // ====================================================================

        // Se a ortografia estiver perfeita, a máquina prossegue normalmente
        const intencao = this.classifier.classify(textoNormalizado);
        const temaExtraido = this.extrairTema(fraseDoAluno);

        let respostaGerada = "That's an interesting point about " + temaExtraido + ". Tell me more!";
        if (this.respostas[intencao] && this.respostas[intencao].length > 0) {
            const arrayDeRespostas = this.respostas[intencao];
            respostaGerada = arrayDeRespostas[Math.floor(Math.random() * arrayDeRespostas.length)];
        }
        respostaGerada = respostaGerada.replace(/\[TEMA\]/g, temaExtraido);

        return { intencaoDetetada: intencao, resposta: respostaGerada };
    }
}

const motorPtt = new PttAIEngine();
module.exports = motorPtt;