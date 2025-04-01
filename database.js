const sqlite3 = require("sqlite3").verbose();

// Criar conexão com o banco de dados
const db = new sqlite3.Database("./blog.db", (err) => {
  if (err) {
    console.error("Erro ao abrir o banco de dados", err);
  } else {
    console.log("Banco de dados conectado!");

    // Criar as tabelas no banco (apenas se não existirem)
    db.serialize(() => {
      // Tabela de posts
      db.run(`
        CREATE TABLE IF NOT EXISTS posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          titulo TEXT NOT NULL,
          conteudo TEXT NOT NULL,
          data TEXT DEFAULT CURRENT_TIMESTAMP,
          categoria TEXT,
          resumo TEXT,
          imagem TEXT 
        )
      `);

      // Tabela de usuários
      db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          nome TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          senha TEXT NOT NULL
        )
      `);

      // Tabela de comentários
      db.run(`
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          post_id INTEGER,
          author_name TEXT,
          text TEXT NOT NULL,
          date TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
        )
      `);

      // Tabela de tags
      db.run(`
        CREATE TABLE IF NOT EXISTS tags (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          nome TEXT NOT NULL UNIQUE
        )
      `);

      // Tabela de relacionamento posts_tags
      db.run(`
        CREATE TABLE IF NOT EXISTS posts_tags (
          post_id INTEGER,
          tag_id INTEGER,
          FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
          FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE,
          PRIMARY KEY(post_id, tag_id)
        )
      `);

      // Tabela para Newsletter
      db.run(`
        CREATE TABLE IF NOT EXISTS newsletter (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL
        )
      `);

      // Nova tabela para refresh tokens (adicionada para a implementação do refresh token)
      db.run(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT NOT NULL UNIQUE,
          user_id INTEGER NOT NULL,
          expires_at DATETIME NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES usuarios(id) ON DELETE CASCADE
        )
      `);

      // Adicionando índices para melhorar performance
      db.run("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)");
      db.run("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)");
      db.run("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)");
      db.run("CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)");
      db.run("CREATE INDEX IF NOT EXISTS idx_posts_tags_post ON posts_tags(post_id)");
      db.run("CREATE INDEX IF NOT EXISTS idx_posts_tags_tag ON posts_tags(tag_id)");

      console.log("Tabelas criadas/verificadas com sucesso!");
    });
  }
});

// Habilitar chaves estrangeiras (importante para integridade referencial)
db.get("PRAGMA foreign_keys = ON");

module.exports = db;