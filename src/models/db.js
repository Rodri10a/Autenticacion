const { Pool } = require('pg')

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'devlearn_hub',
  password: 'postgres123',
  port: 5432
})

module.exports = pool
