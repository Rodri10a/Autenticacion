const Database = require('better-sqlite3')
const path = require('path')

const db = new Database(path.join(__dirname, '../../data.db'))
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

db.exec(`
  CREATE TABLE IF NOT EXISTS topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    votes INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    votes INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    success INTEGER NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`)

const count = db.prepare('SELECT COUNT(*) AS c FROM topics').get().c
if (count === 0) {
  const insertTopic = db.prepare('INSERT INTO topics (title, description, votes) VALUES (?, ?, ?)')
  insertTopic.run('JavaScript', 'Lenguaje de programacion de la web', 7)
  insertTopic.run('Node.js', 'JavaScript del lado del servidor', 4)
  insertTopic.run('Python', 'Lenguaje versatil para backend y data science', 1)

  const insertLink = db.prepare('INSERT INTO links (topic_id, title, url, votes) VALUES (?, ?, ?, ?)')
  insertLink.run(1, 'MDN Web Docs', 'https://developer.mozilla.org', 3)
  insertLink.run(1, 'JavaScript.info', 'https://javascript.info', 5)
  insertLink.run(2, 'Documentacion oficial', 'https://nodejs.org/docs', 2)
}

module.exports = db
