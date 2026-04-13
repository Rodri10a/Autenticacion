const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const pool = require('../models/db')

const JWT_SECRET = 'super-secret-jwt-change-in-prod'

const showLogin = (req, res) => res.render('login', { error: null })
const showSignup = (req, res) => res.render('signup', { error: null })

const signup = async (req, res) => {
  const { email, password } = req.body
  try {
    const hash = await bcrypt.hash(password, 10)
    const { rows: [{ count }] } = await pool.query('SELECT COUNT(*)::int FROM users')
    const role = count === 0 ? 'admin' : 'user'
    await pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', [email, hash, role])
    res.redirect('/login')
  } catch (e) {
    res.render('signup', { error: 'Email ya registrado o invalido' })
  }
}

const login = async (req, res) => {
  const { email, password, mode } = req.body
  const { rows: [user] } = await pool.query('SELECT * FROM users WHERE email = $1', [email])
  const ok = user && await bcrypt.compare(password, user.password_hash)
  await pool.query('INSERT INTO login_attempts (email, success) VALUES ($1, $2)', [email, !!ok])
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

module.exports = { JWT_SECRET, showLogin, showSignup, signup, login, logout }
