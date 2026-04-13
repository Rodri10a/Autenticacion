const express = require('express')
const path = require('path')
const session = require('express-session')
const cookieParser = require('cookie-parser')

const app = express()
const routes = require('./src/routes/routes')
const authRoutes = require('./src/routes/authRoutes')
const { attachUser } = require('./src/middlewares/auth')

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'src/views'))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'src/public')))
app.use(cookieParser())
app.use(session({
  secret: 'session-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 }
}))
app.use(attachUser)

app.use('/', authRoutes)
app.use('/', routes)

app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000')
})
