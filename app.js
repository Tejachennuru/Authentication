const express = require('express')
const bcrypt = require('bcrypt')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')

const app = express()
app.use(express.json())

let db = null

// Initialize Database
const initializeDB = async () => {
  try {
    db = await open({
      filename: 'usersData.db',
      driver: sqlite3.Database,
    })

    await db.run(`
      CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        name TEXT,
        password TEXT,
        gender TEXT,
        location TEXT
      )
    `)
  } catch (error) {
    console.error(`DB Error: ${error.message}`)
    process.exit(1)
  }
}

initializeDB()

// REGISTER API
app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser !== undefined) {
    response.status(400).send('User already exists')
  } else {
    if (password.length < 5) {
      response.status(400).send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)

      const createUserQuery = `
        INSERT INTO user (username, name, password, gender, location)
        VALUES (?, ?, ?, ?, ?)
      `
      await db.run(createUserQuery, [
        username,
        name,
        hashedPassword,
        gender,
        location,
      ])
      response.status(200).send('User created successfully')
    }
  }
})

// LOGIN API
app.post('/login', async (request, response) => {
  const {username, password} = request.body

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser === undefined) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched) {
      response.status(200).send('Login success!')
    } else {
      response.status(400).send('Invalid password')
    }
  }
})

// CHANGE PASSWORD API
app.put('/change-password', async (request, response) => {
  const {username, oldPassword, newPassword} = request.body

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser === undefined) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(oldPassword, dbUser.password)

    if (!isPasswordMatched) {
      response.status(400).send('Invalid current password')
    } else {
      if (newPassword.length < 5) {
        response.status(400).send('Password is too short')
      } else {
        const hashedNewPassword = await bcrypt.hash(newPassword, 10)
        const updatePasswordQuery = `
          UPDATE user
          SET password = ?
          WHERE username = ?
        `
        await db.run(updatePasswordQuery, [hashedNewPassword, username])
        response.status(200).send('Password updated')
      }
    }
  }
})

module.exports = app
