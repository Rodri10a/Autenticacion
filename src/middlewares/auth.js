const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../controllers/authController')

const getUser = (req) => {
  if (req.session?.user) return { user: req.session.user, method: 'session' }
  const token = req.cookies?.jwt
  if (!token) return { user: null, method: null }
  try { return { user: jwt.verify(token, JWT_SECRET), method: 'jwt' } } catch { return { user: null, method: null } }
}

const attachUser = (req, res, next) => {
  const { user, method } = getUser(req)
  req.user = user
  req.authMethod = method
  res.locals.user = user
  res.locals.authMethod = method
  next()
}

const requireLogin = (req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
}

module.exports = { attachUser, requireLogin }
