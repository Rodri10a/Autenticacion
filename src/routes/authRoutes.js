const express = require('express')
const rateLimit = require('express-rate-limit')
const router = express.Router()
const { showLogin, showSignup, showDashboard, signup, login, logout } = require('../controllers/authController')
const { requireLogin } = require('../middlewares/auth')

router.get('/', requireLogin, showDashboard)
router.get('/login', showLogin)
router.post('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Demasiados intentos, espera 15 minutos' }), login)
router.get('/signup', showSignup)
router.post('/signup', signup)
router.post('/logout', logout)

module.exports = router
