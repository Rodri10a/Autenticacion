const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../controllers/authController')

const getUser = (req) => {
  if (req.session?.user) return req.session.user
  const token = req.cookies?.jwt
  if (!token) return null
  try { return jwt.verify(token, JWT_SECRET) } catch { return null }
}

const attachUser = (req, res, next) => {
  const user = getUser(req)
  req.user = user
  res.locals.user = user
  next()
}

const requireLogin = (req, res, next) => {
  if (!req.user) return res.redirect('/login')
  next()
}

module.exports = { attachUser, requireLogin }
