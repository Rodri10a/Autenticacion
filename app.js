const express = require('express')
const path = require('path')
const session = require('express-session')
const cookieParser = require('cookie-parser')
const csrf = require('csurf')
const helmet = require('helmet')

const app = express()
const authRoutes = require('./src/routes/authRoutes')
const { attachUser } = require('./src/middlewares/auth')

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'src/views'))

app.use(helmet({ contentSecurityPolicy: false }))
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'src/public')))
app.use(cookieParser())
app.use(session({
  secret: 'session-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 }
}))
app.use(csrf())
app.use(attachUser)
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken()
  next()
})

app.use('/', authRoutes)

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') return res.status(403).send('Token CSRF invalido')
  res.status(500).send('Error del servidor')
})

app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000')
})
