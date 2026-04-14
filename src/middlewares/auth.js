// ═══════════════════════════════════════════════════════════
// Middlewares de autenticacion:
// - attachUser: popula req.user desde sesion o JWT
// - requireLogin: bloquea rutas protegidas
// ═══════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../controllers/authController')

// getUser: intenta resolver quien es el usuario actual en la request
// Devuelve { user, method } donde method indica COMO se autentico
const getUser = (req) => {
  // 1. Primero mira si hay una sesion activa (modo cookie)
  if (req.session?.user) return { user: req.session.user, method: 'session' }

  // 2. Si no, intenta leer la cookie JWT
  const token = req.cookies?.jwt
  if (!token) return { user: null, method: null }

  // 3. Verifica la firma del token con el mismo secret con el que se firmo
  //    Si es invalido o expirado, jwt.verify lanza y devolvemos null
  try { return { user: jwt.verify(token, JWT_SECRET), method: 'jwt' } } catch { return { user: null, method: null } }
}

// attachUser: middleware global que corre en TODAS las requests
// Popula req.user + res.locals.user para que vistas y rutas sepan quien esta logueado
const attachUser = (req, res, next) => {
  const { user, method } = getUser(req)
  if (user && !user.role) user.role = 'user'  // default para sesiones creadas antes de roles
  req.user = user                      // disponible en los handlers
  req.authMethod = method
  res.locals.user = user               // disponible en las vistas EJS como "user"
  res.locals.authMethod = method       // disponible en las vistas como "authMethod"
  next()
}

// requireLogin: middleware para proteger rutas que requieren sesion
// Si no hay usuario, redirige al login
const requireLogin = (req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
}

// requireRole: restringe acceso por rol
// Uso: requireRole('admin') → solo deja pasar admins
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) return res.status(403).send('Acceso denegado')
  next()
}

module.exports = { attachUser, requireLogin, requireRole }
