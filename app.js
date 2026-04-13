const express = require('express')
const path = require('path')

const app = express()
const routes = require('./src/routes/routes')

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'src/views'))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'src/public')))

app.use('/', routes)

app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000')
})
