// src/routes/bibliotecaRoutes.js
const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');

// 🚀 ROTA INTELIGENTE: Busca local + Open Library API
router.get('/pesquisar', async (req, res) => {
    try {
        const db = await connectDB();
        const termo = req.query.termo || '';

        let livros = [];

        if (termo) {
            // 1. Busca Local (No nosso MongoDB)
            livros = await db.collection('workspace_biblioteca')
                .find({ 
                    $or: [
                        { titulo: new RegExp(termo, 'i') },
                        { autor: new RegExp(termo, 'i') }
                    ]
                })
                .toArray();

            // 2. A MÁGICA: Se não achar nada localmente, vai à Internet!
            if (livros.length === 0) {
                // Conecta-se à API mundial Open Library
                const resposta = await fetch(`https://openlibrary.org/search.json?q=${encodeURIComponent(termo)}`);
                const dados = await resposta.json();

                // Filtra apenas os que têm leitura gratuita e pega os 12 primeiros
                const livrosGratuitos = dados.docs.filter(livro => livro.ebook_access === 'public').slice(0, 12);

                // Formata os dados da internet para o NOSSO padrão visual
                const livrosExternos = livrosGratuitos.map(livro => ({
                    id: 'ext_' + livro.key.replace('/works/', ''),
                    titulo: livro.title,
                    autor: livro.author_name ? livro.author_name[0] : 'Desconhecido',
                    capa: livro.cover_i ? `https://covers.openlibrary.org/b/id/${livro.cover_i}-M.jpg` : 'https://via.placeholder.com/150x220?text=Sem+Capa',
                    linkExterno: true,
                    // Redireciona para o leitor oficial da Open Library
                    urlLeitura: `https://openlibrary.org${livro.key}` 
                }));

                livros = livrosExternos;
            }
        }

        res.json({ success: true, livros });
    } catch (error) {
        console.error("Erro na biblioteca inteligente:", error);
        res.status(500).json({ success: false, error: "Erro ao buscar livros." });
    }
});

module.exports = router;