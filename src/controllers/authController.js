const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('../models/db')

const JWT_SECRET = 'super-secret-jwt-change-in-prod'

const showLogin = (req, res) => res.render('login', { error: null })
const showSignup = (req, res) => res.render('signup', { error: null })
const showDashboard = (req, res) => res.render('dashboard')

const signup = async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 10)
    db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(req.body.email, hash)
    res.redirect('/login')
  } catch {
    res.render('signup', { error: 'Email ya registrado o invalido' })
  }
}

const login = async (req, res) => {
  const { email, password, mode } = req.body
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  const ok = user && await bcrypt.compare(password, user.password_hash)
  if (!ok) return res.render('login', { error: 'Credenciales invalidas' })

  const payload = { id: user.id, email: user.email }
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

module.exports = { JWT_SECRET, showLogin, showSignup, showDashboard, signup, login, logout }
