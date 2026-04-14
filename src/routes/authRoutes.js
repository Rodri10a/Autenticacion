// ═══════════════════════════════════════════════════════════
// Rutas de autenticacion: todas las URLs de la app
// ═══════════════════════════════════════════════════════════

const express = require('express')
const rateLimit = require('express-rate-limit')
const router = express.Router()

// Handlers importados del controller
const { showLogin, showSignup, showDashboard, showAdmin, signup, login, logout } = require('../controllers/authController')

// Middlewares para proteger rutas
const { requireLogin, requireRole } = require('../middlewares/auth')

// Dashboard (ruta protegida). Aplica requireLogin antes del handler
router.get('/', requireLogin, showDashboard)

// Panel de admin (solo admins pueden acceder)
router.get('/admin', requireLogin, requireRole('admin'), showAdmin)

// Formulario de login (publico)
router.get('/login', showLogin)

// Procesar login. Rate limit inline: max 5 intentos por IP cada 15 minutos
// Previene ataques de fuerza bruta
router.post('/login', rateLimit({ windowMs: 2 * 60 * 1000, max: 5, message: 'Demasiados intentos, espera 15 minutos' }), login)

// Formulario de registro (publico)
router.get('/signup', showSignup)

// Procesar registro
router.post('/signup', signup)

// Limpia JWT cuando la pestaña se cerro (sessionStorage vacio)
router.get('/jwt-expire', (req, res) => {
  res.clearCookie('jwt')
  res.clearCookie('jwt_new')
  res.redirect('/login')
})

// Logout (POST porque necesita validar CSRF token)
router.post('/logout', logout)

module.exports = router
