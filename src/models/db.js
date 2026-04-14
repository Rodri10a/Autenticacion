// ═══════════════════════════════════════════════════════════
// Conexion a la base de datos SQLite usando better-sqlite3
// (API sincrona: no hace falta async/await en las queries)
// ═══════════════════════════════════════════════════════════

const Database = require('better-sqlite3')
const path = require('path')

// Abre (o crea si no existe) el archivo data.db en la raiz del proyecto
const db = new Database(path.join(__dirname, '../../data.db'))

// Crea las tablas si no existen (idempotente: se ejecuta en cada arranque sin romper)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,       -- email debe ser unico, lanza error si se duplica
    password_hash TEXT NOT NULL       -- hash bcrypt (nunca texto plano)
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    success INTEGER NOT NULL,         -- 1 = login exitoso, 0 = fallido
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`)

module.exports = db
