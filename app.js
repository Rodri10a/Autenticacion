// ═══════════════════════════════════════════════════════════
// Punto de entrada del servidor Express
// ═══════════════════════════════════════════════════════════

// Framework web + utilidad de paths para ubicar vistas y estaticos
const express = require('express')
const path = require('path')

// Middlewares de sesion y seguridad
const session = require('express-session')       // gestiona sesiones con cookie firmada
const cookieParser = require('cookie-parser')    // parsea req.cookies
const csrf = require('csurf')                    // protege contra Cross-Site Request Forgery
const helmet = require('helmet')                 // agrega headers HTTP de seguridad

// Instancia de la app y modulos propios
const app = express()
const authRoutes = require('./src/routes/authRoutes')
const { attachUser } = require('./src/middlewares/auth')

// Configura EJS como motor de plantillas y la carpeta de vistas
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'src/views'))

// ─── MIDDLEWARES (el ORDEN importa) ───

// Helmet: agrega headers tipo X-Frame-Options, X-Content-Type-Options, etc.
// Desactivamos CSP para que los estilos inline funcionen sin trabas en desarrollo
app.use(helmet({ contentSecurityPolicy: false }))

// Parsea bodies de formularios HTML (req.body.email, req.body.password, etc.)
app.use(express.urlencoded({ extended: true }))

// Sirve archivos estaticos (CSS, imagenes) desde src/public
app.use(express.static(path.join(__dirname, 'src/public')))

// Lee cookies entrantes y las deja disponibles en req.cookies
app.use(cookieParser())

// Configura sesiones del lado del servidor usando cookies firmadas
app.use(session({
  secret: 'session-secret-change-in-prod',   // clave para firmar la cookie (en prod va en .env)
  resave: false,                              // no re-escribe la sesion si no cambio
  saveUninitialized: false,                   // no crea sesion vacia hasta que haya datos
  cookie: {
    httpOnly: true,        // JS del navegador NO puede leerla  → protege XSS
    secure: process.env.NODE_ENV === 'production',  // true solo con HTTPS en produccion
    sameSite: 'strict',    // solo se envia en requests del mismo origen → protege CSRF
    maxAge: 24 * 60 * 60 * 1000  // 1 dia en milisegundos
  }
}))

// Activa validacion CSRF: genera/verifica un token en cada POST de formularios
app.use(csrf())

// Middleware propio: resuelve req.user desde la sesion o desde el JWT
app.use(attachUser)

// Expone el csrfToken a TODAS las vistas EJS como variable local
// Asi los forms pueden incluirlo con <%= csrfToken %>
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken()
  next()
})

// Todas las rutas (login, signup, dashboard, logout) estan en authRoutes
app.use('/', authRoutes)

// Handler de errores: atrapa los tokens CSRF invalidos y devuelve 403
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') return res.status(403).send('Token CSRF invalido')
  res.status(500).send('Error del servidor')
})

// Arranca el servidor en el puerto 3000
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000')
})
