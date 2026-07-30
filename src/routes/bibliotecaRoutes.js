// src/routes/bibliotecaRoutes.js
const express = require('express');
const router = express.Router();
const connectDB = require('../config/db');

// 🚀 ROTA INTELIGENTE: Agregador de APIs (Local + Open Library + Gutenberg)
router.get('/pesquisar', async (req, res) => {
    try {
        const db = await connectDB();
        const termo = req.query.termo || '';
        
        if (!termo) return res.json({ success: true, livros: [] });

        // 1. Busca Local (No nosso MongoDB) - Limitado a 10 resultados
        const promessaLocal = db.collection('workspace_biblioteca')
            .find({ 
                $or: [
                    { titulo: new RegExp(termo, 'i') },
                    { autor: new RegExp(termo, 'i') }
                ]
            })
            .limit(10)
            .toArray()
            .then(livros => livros.map(l => ({ ...l, origem: 'Acervo Local', linkExterno: false })));

        // 2. Busca na Open Library (API Mundial)
        const promessaOpenLibrary = fetch(`https://openlibrary.org/search.json?q=${encodeURIComponent(termo)}`)
            .then(res => res.json())
            .then(dados => dados.docs.filter(livro => livro.ebook_access === 'public').slice(0, 8).map(livro => ({
                id: 'ol_' + livro.key.replace('/works/', ''),
                titulo: livro.title,
                autor: livro.author_name ? livro.author_name[0] : 'Desconhecido',
                capa: livro.cover_i ? `https://covers.openlibrary.org/b/id/${livro.cover_i}-M.jpg` : 'https://via.placeholder.com/150x220?text=Sem+Capa',
                linkExterno: true,
                urlLeitura: `https://openlibrary.org${livro.key}`,
                origem: 'Open Library'
            })));

        // 3. Busca no Project Gutenberg (via Gutendex API)
        const promessaGutenberg = fetch(`https://gutendex.com/books/?search=${encodeURIComponent(termo)}`)
            .then(res => res.json())
            .then(dados => dados.results.slice(0, 8).map(livro => {
                // Tenta encontrar o link HTML para leitura direta, senão manda para a página do livro
                const linkLeitura = livro.formats['text/html'] || livro.formats['text/html.images'] || `https://www.gutenberg.org/ebooks/${livro.id}`;
                return {
                    id: 'gut_' + livro.id,
                    titulo: livro.title,
                    autor: livro.authors.length > 0 ? livro.authors[0].name : 'Desconhecido',
                    capa: livro.formats['image/jpeg'] || 'https://via.placeholder.com/150x220?text=Gutenberg',
                    linkExterno: true,
                    urlLeitura: linkLeitura,
                    origem: 'Gutenberg'
                };
            }));

        // 🚀 O MOTOR DE AGREGAÇÃO: Dispara as 3 pesquisas ao mesmo tempo!
        // allSettled garante que, se uma API externa falhar, não derruba as outras.
        const resultados = await Promise.allSettled([promessaLocal, promessaOpenLibrary, promessaGutenberg]);

        let livrosMisturados = [];
        
        resultados.forEach(resultado => {
            if (resultado.status === 'fulfilled' && resultado.value) {
                livrosMisturados = livrosMisturados.concat(resultado.value);
            }
        });

        res.json({ success: true, livros: livrosMisturados });
    } catch (error) {
        console.error("Erro no Agregador da Biblioteca:", error);
        res.status(500).json({ success: false, error: "Erro ao buscar livros." });
    }
});

module.exports = router;