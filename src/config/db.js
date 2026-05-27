const { MongoClient } = require('mongodb');

let dbInstance = null;

async function connectDB() {
    if (dbInstance) return dbInstance;

    const uri = process.env.MONGODB_URI;

    try {
        const client = new MongoClient(uri, { 
            connectTimeoutMS: 10000,
            socketTimeoutMS: 45000
        });
        
        await client.connect();
        dbInstance = client.db('sistema-escolar');
        console.log("📦 MongoDB Conectado com Sucesso! 🚀");
        return dbInstance;
    } catch (error) {
        console.error("❌ Erro de Ligação:", error.message);
        throw error;
    }
}

module.exports = connectDB;