// ═══════════════════════════════════════════════════════════
// Controller de autenticacion: signup, login, logout, dashboard
// ═══════════════════════════════════════════════════════════

const bcrypt = require('bcrypt')          // hashing de contraseñas
const jwt = require('jsonwebtoken')        // firma y verificacion de tokens JWT
const db = require('../models/db')

// Clave secreta para firmar JWTs (en produccion va en .env, NUNCA hardcoded)
const JWT_SECRET = 'super-secret-jwt-change-in-prod'

// ─── HANDLERS GET (renderizan las vistas) ───

const showLogin = (req, res) => res.render('login', { error: null })
const showSignup = (req, res) => res.render('signup', { error: null })
const showDashboard = (req, res) => res.render('dashboard')

// ─── SIGNUP: registro de nuevo usuario ───

const signup = async (req, res) => {
  try {
    // bcrypt.hash genera un hash con salt aleatorio, irreversible
    // 10 = cost factor (2^10 rondas). A mas alto, mas seguro pero mas lento
    const hash = await bcrypt.hash(req.body.password, 10)

    // Guarda el usuario. Si el email ya existe, el UNIQUE lanza error y cae al catch
    const role = req.body.role === 'admin' ? 'admin' : 'user'
    db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run(req.body.email, hash, role)

    res.redirect('/login')
  } catch {
    // Email duplicado o formato invalido
    res.render('signup', { error: 'Email ya registrado o invalido' })
  }
}

// ─── LOGIN: autenticacion con eleccion de estrategia (session o jwt) ───

const login = async (req, res) => {
  const { email, password, mode } = req.body

  // Busca el usuario por email
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)

  // bcrypt.compare vuelve a hashear la contraseña dada y la compara con el hash guardado
  // Devuelve true/false (ademas es timing-safe, previene ataques de timing)
  const ok = user && await bcrypt.compare(password, user.password_hash)

  // Si no coincide, vuelve al login con mensaje de error
  if (!ok) return res.render('login', { error: 'Credenciales invalidas' })

  // Payload = datos del user que viajaran en la sesion o dentro del token
  const payload = { id: user.id, email: user.email, role: user.role }

  if (mode === 'jwt') {
    // OPCION B: JWT (stateless)
    // Firma un token que contiene el payload + expiracion, con JWT_SECRET
    // El server NO guarda el token, solo lo verifica cuando llega
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })

    // Manda el token al cliente en una cookie segura
    res.cookie('jwt', token, {
      httpOnly: true,        // el JS del navegador no la puede leer (anti XSS)
      secure: process.env.NODE_ENV === 'production',  // true solo con HTTPS en produccion
      sameSite: 'strict'     // no viaja en requests cross-origin (anti CSRF)
      // Sin maxAge → "session cookie" del browser → se borra al cerrar el browser
    })

    // Flag legible por JS para que el script detecte el inicio de sesion JWT
    res.cookie('jwt_new', '1', { httpOnly: false, sameSite: 'strict' })
  } else {
    // OPCION A: Sesion del lado del server (stateful)
    // express-session guarda el payload en memoria y manda solo un ID firmado en connect.sid
    req.session.user = payload
  }

  res.redirect('/')
}

// ─── LOGOUT: limpia sesion y cookies ───

const logout = (req, res) => {
  // Destruye la sesion en el store del server (si existia)
  req.session?.destroy?.(() => {})

  // Borra las dos cookies posibles (no sabemos cual estaba usando el usuario)
  res.clearCookie('jwt')
  res.clearCookie('jwt_new')
  res.clearCookie('connect.sid')

  res.redirect('/login')
}

// ─── ADMIN PANEL: lista de usuarios (solo accesible por admins) ───

const showAdmin = (req, res) => {
  const users = db.prepare('SELECT id, email, role FROM users').all()
  res.render('admin', { users })
}

module.exports = { JWT_SECRET, showLogin, showSignup, showDashboard, showAdmin, signup, login, logout }
