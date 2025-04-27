const express = require('express')
const bcrypt = require('bcrypt')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')

const app = express()
app.use(express.json())

let db = null

// Initialize database and server
const initializeDBAndServer = async () => {
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

    app.listen(3000, () => {
      console.log('Server running at http://localhost:3000/')
    })
  } catch (error) {
    console.error(`DB Error: ${error.message}`)
    process.exit(1)
  }
}

initializeDBAndServer()

// Register API
app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body

  if (!username || !name || !password || !gender || !location) {
    response.status(400).send('Missing required fields')
    return
  }

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser !== undefined) {
    response.status(400).send('User already exists')
  } else if (password.length < 5) {
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
    response.send('User created successfully')
  }
})

// Login API
app.post('/login', async (request, response) => {
  const {username, password} = request.body

  if (!username || !password) {
    response.status(400).send('Missing required fields')
    return
  }

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser === undefined) {
    response.status(400).send('Invalid User')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched) {
      response.send('Login Success!')
    } else {
      response.status(400).send('Invalid Password')
    }
  }
})

// Change Password API
app.put('/change-password', async (request, response) => {
  const {username, oldPassword, newPassword} = request.body

  if (!username || !oldPassword || !newPassword) {
    response.status(400).send('Missing required fields')
    return
  }

  const selectUserQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectUserQuery, [username])

  if (dbUser === undefined) {
    response.status(400).send('User not found')
  } else {
    const isPasswordMatched = await bcrypt.compare(oldPassword, dbUser.password)

    if (!isPasswordMatched) {
      response.status(400).send('Invalid current password')
    } else if (newPassword.length < 5) {
      response.status(400).send('Password is too short')
    } else {
      const hashedNewPassword = await bcrypt.hash(newPassword, 10)

      const updatePasswordQuery = `
        UPDATE user
        SET password = ?
        WHERE username = ?
      `
      await db.run(updatePasswordQuery, [hashedNewPassword, username])
      response.send('Password updated')
    }
  }
})
