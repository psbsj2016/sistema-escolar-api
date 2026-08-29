// ============================================================================
// 🧠 PTT AI ENGINE - O CÉREBRO DE MACHINE LEARNING EXCLUSIVO PTT CURSOS
// ============================================================================
const natural = require('natural');
const fs = require('fs');
const path = require('path');

// Caminho onde o "cérebro" vai gravar as memórias (ficheiro JSON local)
const BRAIN_PATH = path.join(__dirname, 'ptt_brain.json');

class PttAIEngine {
    constructor() {
        this.classifier = new natural.BayesClassifier();
        this.isTrained = false;
    }

    // 1. Iniciar ou Carregar o Cérebro
    async init() {
        return new Promise((resolve) => {
            if (fs.existsSync(BRAIN_PATH)) {
                // Se já existe um cérebro gravado, ele carrega as memórias!
                natural.BayesClassifier.load(BRAIN_PATH, null, (err, classifier) => {
                    if (!err && classifier) {
                        this.classifier = classifier;
                        this.isTrained = true;
                        console.log("🧠 Ptt AI: Memórias carregadas com sucesso!");
                    }
                    resolve();
                });
            } else {
                // Se for um bebé recém-nascido, damos-lhe os conhecimentos básicos de Inglês
                console.log("🧠 Ptt AI: Criando um cérebro novo...");
                this.ensinarBasico();
                this.treinar().then(resolve);
            }
        });
    }

    // 2. Conhecimentos Base (A "Semente" de Inteligência)
    ensinarBasico() {
        // Ensinar Saudações
        this.classifier.addDocument('hello good morning', 'saudacao');
        this.classifier.addDocument('hi there how are you', 'saudacao');
        
        // Ensinar Concordância
        this.classifier.addDocument('i agree with you', 'concordar');
        this.classifier.addDocument('yes that is completely true', 'concordar');
        
        // Ensinar Discordância
        this.classifier.addDocument('i disagree with that', 'discordar');
        this.classifier.addDocument('no that is wrong and false', 'discordar');
        
        // Ensinar Dúvidas
        this.classifier.addDocument('why is that happening?', 'pergunta');
        this.classifier.addDocument('how can i do this?', 'pergunta');
    }

    // 3. Treinar e Guardar no Disco
    async treinar() {
        return new Promise((resolve) => {
            this.classifier.train();
            this.isTrained = true;
            this.classifier.save(BRAIN_PATH, (err) => {
                if (err) console.error("🚨 Erro ao gravar o cérebro da Ptt AI:", err);
                else console.log("🧠 Ptt AI: Nova sinapse gravada no disco!");
                resolve();
            });
        });
    }

    // 4. Injetar Nova Aprendizagem Manualmente
    async ensinarNovaFrase(frase, categoria) {
        this.classifier.addDocument(frase.toLowerCase(), categoria);
        await this.treinar(); // Retreina e salva
        return `A Ptt AI aprendeu que "${frase}" significa "${categoria}".`;
    }

    // 5. Interpretar e Responder (A Lógica Principal)
    pensar(fraseDoAluno) {
        if (!this.isTrained) return "I am still learning to speak...";

        const textoNormalizado = fraseDoAluno.toLowerCase();
        
        // A IA classifica o que o aluno disse usando estatística matemática
        const intencao = this.classifier.classify(textoNormalizado);
        
        // A IA escolhe a resposta com base na intenção detetada
        let respostaGerada = "";
        
        switch (intencao) {
            case 'saudacao':
                respostaGerada = "Greetings! I am the Ptt AI. I am ready to test your English skills. What is on your mind today?";
                break;
            case 'concordar':
                respostaGerada = "It is good that we are in harmony. But we must always question things. Can you think of an exception?";
                break;
            case 'discordar':
                respostaGerada = "A rebellious mind! I like that. You disagree, but can you give me one solid example to prove your point?";
                break;
            case 'pergunta':
                respostaGerada = "A very wise question. Seeking knowledge is the first step to fluency. How would you try to answer that yourself first?";
                break;
            default:
                respostaGerada = "Fascinating... I am still learning human language, but I hear you clearly. Continue your thoughts!";
        }

        return {
            intencaoDetetada: intencao,
            resposta: respostaGerada
        };
    }
}

// Exportamos uma única instância (Singleton) para ser usada em toda a plataforma
const motorPtt = new PttAIEngine();
module.exports = motorPtt;