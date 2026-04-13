const express = require('express')
const rateLimit = require('express-rate-limit')
const router = express.Router()
const { showLogin, showSignup, signup, login, logout } = require('../controllers/authController')

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiados intentos de inicio de sesion, espera 15 minutos',
  standardHeaders: true,
  legacyHeaders: false
})

router.get('/login', showLogin)
router.post('/login', loginLimiter, login)
router.get('/signup', showSignup)
router.post('/signup', signup)
router.post('/logout', logout)

module.exports = router
