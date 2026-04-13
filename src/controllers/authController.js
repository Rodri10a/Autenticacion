const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('../models/db')

const JWT_SECRET = 'super-secret-jwt-change-in-prod'

const showLogin = (req, res) => res.render('login', { error: null })
const showSignup = (req, res) => res.render('signup', { error: null })

const signup = async (req, res) => {
  const { email, password } = req.body
  try {
    const hash = await bcrypt.hash(password, 10)
    const { c: count } = db.prepare('SELECT COUNT(*) AS c FROM users').get()
    const role = count === 0 ? 'admin' : 'user'
    db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run(email, hash, role)
    res.redirect('/login')
  } catch (e) {
    res.render('signup', { error: 'Email ya registrado o invalido' })
  }
}

const login = async (req, res) => {
  const { email, password, mode } = req.body
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  const ok = user && await bcrypt.compare(password, user.password_hash)
  db.prepare('INSERT INTO login_attempts (email, success) VALUES (?, ?)').run(email, ok ? 1 : 0)
  if (!ok) return res.render('login', { error: 'Credenciales invalidas' })

  const payload = { id: user.id, email: user.email, role: user.role }
  if (mode === 'jwt') {
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })
    res.cookie('jwt', token, { httpOnly: true, secure: false, sameSite: 'strict', maxAge: 3600000 })
  } else {
    req.session.user = payload
  }
  res.redirect('/')
}

const logout = (req, res) => {
  req.session?.destroy?.(() => {})
  res.clearCookie('jwt')
  res.clearCookie('connect.sid')
  res.redirect('/login')
}

const showAdmin = (req, res) => {
  const attempts = db.prepare('SELECT email, success, attempted_at FROM login_attempts ORDER BY attempted_at DESC LIMIT 50').all()
  res.render('admin', { attempts })
}

module.exports = { JWT_SECRET, showLogin, showSignup, signup, login, logout, showAdmin }
