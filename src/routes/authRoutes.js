// ═══════════════════════════════════════════════════════════
// Rutas de autenticacion: todas las URLs de la app
// ═══════════════════════════════════════════════════════════

const express = require('express')
const rateLimit = require('express-rate-limit')
const router = express.Router()

// Handlers importados del controller
const { showLogin, showSignup, showDashboard, signup, login, logout } = require('../controllers/authController')

// Middleware para proteger rutas
const { requireLogin } = require('../middlewares/auth')

// Dashboard (unica ruta protegida). Aplica requireLogin antes del handler
router.get('/', requireLogin, showDashboard)

// Formulario de login (publico)
router.get('/login', showLogin)

// Procesar login. Rate limit inline: max 5 intentos por IP cada 15 minutos
// Previene ataques de fuerza bruta
router.post('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Demasiados intentos, espera 15 minutos' }), login)

// Formulario de registro (publico)
router.get('/signup', showSignup)

// Procesar registro
router.post('/signup', signup)

// Logout (POST porque necesita validar CSRF token)
router.post('/logout', logout)

module.exports = router
