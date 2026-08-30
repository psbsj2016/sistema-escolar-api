// ============================================================================
// 🧠 PTT AI ENGINE - O CÉREBRO DINÂMICO E ESCALÁVEL DA PTT CURSOS
// ============================================================================
const natural = require('natural');
const fs = require('fs');
const path = require('path');

const BRAIN_PATH = path.join(__dirname, 'ptt_brain.json');
const RESPONSES_PATH = path.join(__dirname, 'ptt_responses.json');

class PttAIEngine {
    constructor() {
        this.classifier = new natural.BayesClassifier();
        this.isTrained = false;
        this.respostas = {}; 
    }

    async init() {
        if (fs.existsSync(RESPONSES_PATH)) {
            try { this.respostas = JSON.parse(fs.readFileSync(RESPONSES_PATH, 'utf8')); } 
            catch(e) { this.respostas = {}; }
        } else {
            // Respostas padrão agora usam a Tag Mágica [TEMA] para naturalidade!
            this.respostas = {
                'saudacao': ["Greetings! I am the Ptt AI. I am ready to test your English skills. What is on your mind today?"],
                'concordar': ["It is good that we are in harmony about [TEMA]. But we must always question things. Can you think of an exception?"],
                'discordar': ["A rebellious mind! I like that you disagree about [TEMA]. Can you give me one solid example to prove your point?"],
                'pergunta': ["A very wise question about [TEMA]. Seeking knowledge is the first step to fluency. How would you try to answer that yourself first?"]
            };
            fs.writeFileSync(RESPONSES_PATH, JSON.stringify(this.respostas, null, 2));
        }

        return new Promise((resolve) => {
            if (fs.existsSync(BRAIN_PATH)) {
                natural.BayesClassifier.load(BRAIN_PATH, null, (err, classifier) => {
                    if (!err && classifier) {
                        this.classifier = classifier;
                        this.isTrained = true;
                        console.log("🧠 Ptt AI: Memórias e Caderno de Respostas carregados com sucesso!");
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

    // 🚀 NOVA FUNÇÃO DE INTELIGÊNCIA: Extrai o assunto principal da frase
    extrairTema(frase) {
        let limpa = frase.toLowerCase();
        
        // Removemos o "ruído" (expressões comuns que os alunos usam para iniciar frases)
        const ruido = [
            'i think that', 'i believe that', 'i agree with', 'i completely agree that', 
            'i disagree with', 'i dont think', 'because', 'yes', 'no', 'absolutely', 
            'in my opinion', 'to me', 'i love', 'i like', 'i hate'
        ];
        
        ruido.forEach(termo => {
            // Substitui as expressões de ruído por vazio
            limpa = limpa.replace(new RegExp(`\\b${termo}\\b`, 'gi'), '');
        });

        // Limpa pontuações que sobraram no início ou fim
        limpa = limpa.replace(/[^a-z0-9 ]/g, '').trim();

        // Se sobrou alguma palavra com sentido, devolve. Se não, usa um termo neutro.
        return limpa.length > 2 ? limpa : "this topic";
    }

    // 5. Interpretar e Responder (AGORA COM ESPELHAMENTO DE TEMA)
    pensar(fraseDoAluno) {
        if (!this.isTrained) return { intencaoDetetada: 'unknown', resposta: "I am still learning..." };

        const textoNormalizado = fraseDoAluno.toLowerCase();
        
        // 1. Adivinha a intenção
        const intencao = this.classifier.classify(textoNormalizado);
        
        // 2. 🚀 Extrai o TEMA (O assunto de que o aluno está a falar)
        const temaExtraido = this.extrairTema(fraseDoAluno);

        let respostaGerada = "That's an interesting point about " + temaExtraido + ". Tell me more!";
        
        // 3. Escolhe a resposta da Base de Dados
        if (this.respostas[intencao] && this.respostas[intencao].length > 0) {
            const arrayDeRespostas = this.respostas[intencao];
            respostaGerada = arrayDeRespostas[Math.floor(Math.random() * arrayDeRespostas.length)];
        }

        // 4. 🚀 A MAGIA FINAL: Substitui a tag [TEMA] pelas palavras do aluno!
        respostaGerada = respostaGerada.replace(/\[TEMA\]/g, temaExtraido);

        return { intencaoDetetada: intencao, resposta: respostaGerada };
    }
}

const motorPtt = new PttAIEngine();
module.exports = motorPtt;