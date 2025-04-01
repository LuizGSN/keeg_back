const express = require("express");
const cors = require("cors");
const db = require("./database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3001;

// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadPath = path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(uploadPath)) {
        fs.mkdirSync(uploadPath, { recursive: true });
      }
      cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    },
  });
  
  const upload = multer({ storage });

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// Rota para upload de imagens
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
      return res.status(400).json({ erro: "Nenhum arquivo enviado" });
    }
  
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.json({ location: imageUrl });
  });
  

// Rota de autenticação Middleware
const verificaToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
      return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
          if (err.name === 'TokenExpiredError') {
              return res.status(401).json({ 
                  erro: "Token expirado",
                  code: "TOKEN_EXPIRED" // Código para o frontend identificar
              });
          }
          return res.status(401).json({ erro: "Token inválido" });
      }
      req.userId = decoded.id;
      next();
  });
};

// Rota para verificar se o token ainda é válido
app.get("/auth/verify", verificaToken, (req, res) => {
    res.json({ autenticado: true });
});

// Rota protegida do painel admin
app.get("/admin", verificaToken, (req, res) => {
    res.json({ mensagem: "Painel administrativo acessado com sucesso!" });
});

// Rota para criar comentário
app.post("/posts/:id/comments", (req, res) => {
    const { id } = req.params;
    const { text, author_name } = req.body;
  
    if (!text) {
      return res.status(400).json({ erro: "Texto do comentário é obrigatório" });
    }
  
    db.get("SELECT * FROM posts WHERE id = ?", [id], (err, post) => {
      if (!post) {
        return res.status(404).json({ erro: "Post não encontrado" });
      }
  
      const author = author_name ? author_name : "Anônimo";
      const date = new Date().toISOString();
  
      db.run(
        "INSERT INTO comments (post_id, author_name, text, date) VALUES (?, ?, ?, ?)",
        [id, author, text, date],
        function (err) {
          if (err) {
            return res.status(500).json({ erro: err.message });
          }
          res.status(201).json({
            id: this.lastID,
            post_id: id,
            author_name: author,
            text,
            date,
          });
        }
      );
    });
});

  // Rota para listar comentários de um post
  app.get("/posts/:id/comments", (req, res) => {
    const { id } = req.params;  // ID do post
    
    // Buscar todos os comentários do post
    db.all("SELECT * FROM comments WHERE post_id = ? ORDER BY date DESC", [id], (err, rows) => {
      if (err) {
        return res.status(500).json({ erro: err.message });
      }
      res.json(rows);
    });
});

// Rota de teste
app.get("/", (req, res) => {
  res.send("API do blog funcionando! 🚀");
});

// Rota para listar posts com busca
app.get("/posts", (req, res) => {
  const { page = 1, limit = 6, categoria, q } = req.query; // Adiciona o parâmetro de busca (q)
  const offset = (page - 1) * limit;

  // Monta a query SQL com base nos filtros
  let query = "SELECT * FROM posts";
  let params = [];
  let conditions = [];

  if (categoria) {
    conditions.push("categoria = ?");
    params.push(categoria);
  }

  if (q) {
    conditions.push("(titulo LIKE ? OR resumo LIKE ? OR categoria LIKE ?)");
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }

  query += " ORDER BY data DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  // Conta o total de posts (com ou sem filtro)
  db.get("SELECT COUNT(*) AS total FROM posts" + (conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : ""), params.slice(0, conditions.length), (err, row) => {
    if (err) {
      return res.status(500).json({ erro: err.message });
    }

    const totalPosts = row.total;
    const totalPages = Math.ceil(totalPosts / limit);

    // Busca os posts com base na query
    db.all(query, params, (err, rows) => {
      if (err) {
        return res.status(500).json({ erro: err.message });
      }

      res.json({
        totalPosts,
        totalPages,
        currentPage: parseInt(page),
        posts: rows.map(post => ({
          id: post.id,
          titulo: post.titulo,
          conteudo: post.conteudo,
          categoria: post.categoria,
          resumo: post.resumo,
          imagem: post.imagem,
          data: post.data,
          tags: post.tags ? JSON.parse(post.tags) : [], // Converte a string de tags para array
        })),
      });
    });
  });
});

// Rota para obter um post específico
app.get("/posts/:id", (req, res) => {
    const { id } = req.params;

    db.get(
        `SELECT 
            id, 
            titulo, 
            conteudo, 
            categoria, 
            resumo, 
            imagem, 
            data 
        FROM posts 
        WHERE id = ?`, 
        [id], 
        async (err, post) => {
            if (err) {
                return res.status(500).json({ erro: "Erro ao buscar o post" });
            }

            if (!post) {
                return res.status(404).json({ erro: "Post não encontrado" });
            }

            // Busca as tags do post
            const tags = await new Promise((resolve, reject) => {
                db.all(
                    `SELECT t.nome 
                     FROM tags t
                     INNER JOIN posts_tags pt ON t.id = pt.tag_id
                     WHERE pt.post_id = ?`, 
                    [id], 
                    (err, tags) => {
                        if (err) reject(err);
                        else resolve(tags.map(tag => tag.nome));
                    }
                );
            });

            res.json({ ...post, tags });
        }
    );
});

// Rota para criar post
app.post("/posts", verificaToken, upload.single("imagem"), async (req, res) => {
  console.log("Corpo da requisição:", req.body); // Depuração: Exibe o corpo da requisição
  console.log("Arquivo recebido:", req.file); // Depuração: Exibe o arquivo recebido

  const { titulo, conteudo, categoria, resumo, tags } = req.body;
  const imagem = req.file ? `/uploads/${req.file.filename}` : null; // Caminho da imagem

  if (!titulo || !conteudo || !categoria || !resumo || !imagem) {
    return res.status(400).json({ erro: "Todos os campos (titulo, conteudo, categoria, resumo e imagem) são obrigatórios" });
  }

  try {
    // Insere o post
    const { lastID: postId } = await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO posts (titulo, conteudo, categoria, resumo, imagem) VALUES (?, ?, ?, ?, ?)",
        [titulo, conteudo, categoria, resumo, imagem],
        function (err) {
          if (err) reject(err);
          else resolve(this);
        }
      );
    });

    // Inicializa tagsArray como um array vazio
    let tagsArray = [];

    // Insere as tags (se houver)
    if (tags) {
      try {
        // Tenta converter as tags de JSON para array
        tagsArray = JSON.parse(tags);
      } catch (err) {
        // Se falhar, assume que as tags são uma string separada por vírgulas
        tagsArray = tags.split(",").map(tag => tag.trim());
      }

      for (const tagNome of tagsArray) {
        // Verifica se a tag já existe
        let tagId = await new Promise((resolve, reject) => {
          db.get("SELECT id FROM tags WHERE nome = ?", [tagNome], (err, row) => {
            if (err) reject(err);
            else resolve(row ? row.id : null);
          });
        });

        // Se a tag não existe, cria
        if (!tagId) {
          tagId = await new Promise((resolve, reject) => {
            db.run("INSERT INTO tags (nome) VALUES (?)", [tagNome], function (err) {
              if (err) reject(err);
              else resolve(this.lastID);
            });
          });
        }

        // Associa a tag ao post
        await new Promise((resolve, reject) => {
          db.run("INSERT INTO posts_tags (post_id, tag_id) VALUES (?, ?)", [postId, tagId], (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      }
    }

    res.json({
      id: postId,
      titulo,
      conteudo,
      categoria,
      resumo,
      imagem,
      tags: tagsArray, // Usa tagsArray diretamente
    });
  } catch (error) {
    console.error("Erro ao criar post:", error); // Depuração: Exibe o erro no console
    res.status(500).json({ erro: error.message });
  }
});

// Rota para cadastro
app.post("/register", async (req, res) => { 
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({ erro: "Todos os campos são obrigatórios" });
    }

    db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ erro: "Erro ao verificar o email" });
        }

        if (user) {
            return res.status(400).json({ erro: "Email já cadastrado" });
        }

        try {
            const senhaHash = await bcrypt.hash(senha, 10);
            db.run(
                "INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)",
                [nome, email, senhaHash],
                function (err) {
                    if (err) {
                        return res.status(500).json({ erro: err.message });
                    }
                    res.json({ id: this.lastID, nome, email });
                }
            );
        } catch (error) {
            return res.status(500).json({ erro: "Erro ao processar a senha" });
        }
    });
});

// Rota de login
app.post("/login", (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
      return res.status(400).json({ erro: "Email e senha são obrigatórios" });
  }

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
      if (!user) {
          return res.status(400).json({ erro: "Usuário não encontrado" });
      }

      const senhaValida = await bcrypt.compare(senha, user.senha);
      if (!senhaValida) {
          return res.status(400).json({ erro: "Senha incorreta" });
      }

      // Gerar access token (15 minutos)
      const accessToken = jwt.sign(
          { id: user.id, email: user.email }, 
          process.env.JWT_SECRET, 
          { expiresIn: '15m' } // Formato correto
      );

      // Gerar refresh token (7 dias)
      const refreshToken = jwt.sign(
          { id: user.id }, 
          process.env.JWT_REFRESH_SECRET, 
          { expiresIn: '7d' } // Formato correto
      );

      // Armazenar o refresh token no banco de dados
      db.run(
          "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
          [refreshToken, user.id],
          function(err) {
              if (err) {
                  return res.status(500).json({ erro: "Erro ao armazenar refresh token" });
              }

              res.json({ 
                  accessToken, 
                  refreshToken,
                  nome: user.nome, 
                  email: user.email,
                  expiresIn: 900 // 15 minutos em segundos (para o frontend)
              });
          }
      );
  });
});

// Rota para obter novo access token usando refresh token
app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
      return res.status(400).json({ erro: "Refresh token é obrigatório" });
  }

  // Verificar se o refresh token existe e é válido
  db.get(
      "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime('now')",
      [refreshToken],
      (err, tokenRecord) => {
          if (err || !tokenRecord) {
              return res.status(401).json({ erro: "Refresh token inválido ou expirado" });
          }

          jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
              if (err) {
                  return res.status(401).json({ erro: "Refresh token inválido" });
              }

              // Gerar novo access token
              const newAccessToken = jwt.sign(
                  { id: decoded.id }, 
                  process.env.JWT_SECRET, 
                  { expiresIn: '15m' }
              );

              res.json({ 
                  accessToken: newAccessToken,
                  expiresIn: 900
              });
          });
      }
  );
});

// Rota para logout (invalidar refresh token)
app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
      return res.status(400).json({ erro: "Refresh token é obrigatório" });
  }

  db.run(
      "DELETE FROM refresh_tokens WHERE token = ?",
      [refreshToken],
      function(err) {
          if (err) {
              return res.status(500).json({ erro: "Erro ao invalidar refresh token" });
          }
          
          if (this.changes === 0) {
              return res.status(404).json({ erro: "Refresh token não encontrado" });
          }

          res.json({ mensagem: "Logout realizado com sucesso" });
      }
  );
});

// Rota para atualização do post
app.put("/posts/:id", verificaToken, upload.single("imagem"), async (req, res) => {
  const { id } = req.params;
  const { titulo, conteudo, categoria, resumo, tags } = req.body;
  const imagem = req.file ? `/uploads/${req.file.filename}` : null; // Caminho da nova imagem

  console.log("Corpo da requisição:", req.body); // Depuração: Exibe o corpo da requisição
  console.log("Arquivo recebido:", req.file); // Depuração: Exibe o arquivo recebido

  if (!titulo || !conteudo || !categoria || !resumo) {
    return res.status(400).json({ erro: "Todos os campos são obrigatórios: título, conteúdo, categoria e resumo" });
  }

  try {
    // Busca o post atual para obter a imagem antiga (caso nenhuma nova imagem seja enviada)
    const postAtual = await new Promise((resolve, reject) => {
      db.get("SELECT imagem FROM posts WHERE id = ?", [id], (err, row) => {
        if (err) {
          console.error("Erro ao buscar post atual:", err); // Depuração: Exibe o erro
          reject(err);
        } else {
          console.log("Post atual encontrado:", row); // Depuração: Exibe o post atual
          resolve(row);
        }
      });
    });

    // Define o caminho da imagem (nova ou antiga)
    const caminhoImagem = imagem || postAtual.imagem;

    // Atualiza o post
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE posts SET titulo = ?, conteudo = ?, categoria = ?, resumo = ?, imagem = ? WHERE id = ?",
        [titulo, conteudo, categoria, resumo, caminhoImagem, id],
        function (err) {
          if (err) {
            console.error("Erro ao atualizar post:", err); // Depuração: Exibe o erro
            reject(err);
          } else {
            console.log("Post atualizado com sucesso"); // Depuração: Confirma a atualização
            resolve();
          }
        }
      );
    });

    // Remove as tags antigas
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM posts_tags WHERE post_id = ?", [id], (err) => {
        if (err) {
          console.error("Erro ao remover tags antigas:", err); // Depuração: Exibe o erro
          reject(err);
        } else {
          console.log("Tags antigas removidas com sucesso"); // Depuração: Confirma a remoção
          resolve();
        }
      });
    });

    // Inicializa tagsArray como um array vazio
    let tagsArray = [];

    // Insere as novas tags (se houver)
    if (tags && tags.length > 0) {
      tagsArray = JSON.parse(tags); // Converte as tags de JSON para array
      for (const tagNome of tagsArray) {
        let tagId = await new Promise((resolve, reject) => {
          db.get("SELECT id FROM tags WHERE nome = ?", [tagNome], (err, row) => {
            if (err) {
              console.error("Erro ao buscar tag:", err); // Depuração: Exibe o erro
              reject(err);
            } else {
              console.log("Tag encontrada:", row); // Depuração: Exibe a tag encontrada
              resolve(row ? row.id : null);
            }
          });
        });

        if (!tagId) {
          tagId = await new Promise((resolve, reject) => {
            db.run("INSERT INTO tags (nome) VALUES (?)", [tagNome], function (err) {
              if (err) {
                console.error("Erro ao criar tag:", err); // Depuração: Exibe o erro
                reject(err);
              } else {
                console.log("Tag criada com sucesso:", this.lastID); // Depuração: Confirma a criação
                resolve(this.lastID);
              }
            });
          });
        }

        await new Promise((resolve, reject) => {
          db.run("INSERT INTO posts_tags (post_id, tag_id) VALUES (?, ?)", [id, tagId], (err) => {
            if (err) {
              console.error("Erro ao associar tag ao post:", err); // Depuração: Exibe o erro
              reject(err);
            } else {
              console.log("Tag associada ao post com sucesso"); // Depuração: Confirma a associação
              resolve();
            }
          });
        });
      }
    }

    res.json({ id, titulo, conteudo, categoria, resumo, imagem: caminhoImagem, tags: tagsArray });
  } catch (error) {
    console.error("Erro ao atualizar post:", error); // Depuração: Exibe o erro
    res.status(500).json({ erro: error.message });
  }
});


// Rota para excluir post
app.delete("/posts/:id", verificaToken, (req, res) => {
    const { id } = req.params;

    db.get("SELECT * FROM posts WHERE id = ?", [id], (err, post) => {
        if (!post) {
            return res.status(404).json({ erro: "Post não encontrado" });
        }

        db.run("DELETE FROM posts WHERE id = ?", [id], function (err) {
            if (err) {
                return res.status(500).json({ erro: err.message });
            }
            res.json({ mensagem: "Post excluído com sucesso" });
        });
    });
});

// Rota para buscar categorias únicas
app.get("/categories", (req, res) => {
    db.all("SELECT DISTINCT categoria FROM posts", (err, rows) => {
      if (err) {
        return res.status(500).json({ erro: "Erro ao buscar categorias" });
      }
      const categories = rows.map((row) => row.categoria);
      res.json(categories);
    });
  });

// Rota para o Newsletter
app.post("/newsletter", (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json({ erro: "Email é obrigatório" });
    }
  
    db.run(
      "INSERT INTO newsletter (email) VALUES (?)",
      [email],
      function (err) {
        if (err) {
          return res.status(500).json({ erro: "Erro ao salvar email" });
        }
        res.json({ mensagem: "Inscrição realizada com sucesso!" });
      }
    );
  });

// Rota para listar e-mails da newsletter
app.get("/newsletter", (req, res) => {
    db.all("SELECT * FROM newsletter", (err, rows) => {
      if (err) {
        return res.status(500).json({ erro: "Erro ao buscar e-mails" });
      }
      res.json(rows);
    });
  });

// Rota para envio de e-mails do formulário
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'keegclub60@gmail.com', // Seu e-mail
    pass: 'hjue ephl ujcv puyv', // Sua senha ou senha de app
  },
});

// Rota para receber os dados do formulário
app.post('/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;

  try {
    // Envia um e-mail de confirmação
    await transporter.sendMail({
      from: 'keegclub60@gmail.com',
      to: email, // E-mail do usuário
      subject: 'Confirmação de contato - Keeg Club',
      text: `Olá ${name},\n\nObrigado por entrar em contato! Recebemos sua mensagem sobre "${subject}" e responderemos em breve.\n\nAtenciosamente,\nEquipe Keeg Club`,
    });

    // Envia um e-mail para você com a mensagem do usuário
    await transporter.sendMail({
      from: 'keegclub60@gmail.com',
      to: 'keegclub60@gmail.com', // Seu e-mail
      subject: `Nova mensagem de ${name}: ${subject}`,
      text: `De: ${name} (${email})\n\nMensagem:\n${message}`,
    });

    res.status(200).json({ message: 'Mensagem enviada com sucesso!' });
  } catch (error) {
    console.error('Erro ao enviar e-mail:', error);
    res.status(500).json({ message: 'Erro ao enviar a mensagem.' });
  }
});

// Rota para listar todos os comentários (admin)
app.get("/comments", verificaToken, (req, res) => {
  const { page = 1, limit = 10, q: searchTerm } = req.query;
  const offset = (page - 1) * limit;

  let query = "SELECT * FROM comments";
  let countQuery = "SELECT COUNT(*) AS total FROM comments";
  let params = [];
  let conditions = [];

  if (searchTerm) {
    conditions.push("(author_name LIKE ? OR text LIKE ?)");
    params.push(`%${searchTerm}%`, `%${searchTerm}%`);
  }

  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
    countQuery += " WHERE " + conditions.join(" AND ");
  }

  query += " ORDER BY date DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  db.get(countQuery, params.slice(0, conditions.length), (err, countRow) => {
    if (err) {
      return res.status(500).json({ erro: err.message });
    }

    db.all(query, params, (err, rows) => {
      if (err) {
        return res.status(500).json({ erro: err.message });
      }

      res.json({
        comments: rows,
        totalPages: Math.ceil(countRow.total / limit),
        currentPage: parseInt(page),
      });
    });
  });
});

// Rota para excluir comentário (apenas admin)
app.delete("/comments/:id", verificaToken, (req, res) => {
  const { id } = req.params;

  db.run("DELETE FROM comments WHERE id = ?", [id], function (err) {
      if (err) {
          return res.status(500).json({ erro: err.message });
      }
      if (this.changes === 0) {
          return res.status(404).json({ erro: "Comentário não encontrado" });
      }
      res.json({ mensagem: "Comentário excluído com sucesso" });
  });
});

  // Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
  });