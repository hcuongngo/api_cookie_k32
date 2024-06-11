const http = require('http')
const url = require('url')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const _ = require('lodash')
const moment = require('moment')

const saltRound = 10;

const users = [
  { id: 1, email: "user1@gmail.com", password: bcrypt.hashSync("user1", saltRound), role: "admin" },
  { id: 2, email: "user2@gmail.com", password: bcrypt.hashSync("user2", saltRound), role: "user" },
]

const items = [
  { id: 1, name: 'item 1', description: 'item 1 description' },
  { id: 2, name: 'item 2', description: 'item 2 description' },
  { id: 3, name: 'item 3', description: 'item 3 description' },
  { id: 4, name: 'item 4', description: 'item 4 description' },
  { id: 5, name: 'item 5', description: 'item 5 description' },
  { id: 6, name: 'item 6', description: 'item 6 description' },
  { id: 7, name: 'item 7', description: 'item 7 description' },
  { id: 8, name: 'item 8', description: 'item 8 description' },
  { id: 9, name: 'item 9', description: 'item 9 description' },
  { id: 10, name: 'item 10', description: 'item 10 description' },
  { id: 12, name: 'item 12', description: 'item 12 description' },
  { id: 13, name: 'item 13', description: 'item 13 description' },
]

const hashPassword = async (password) => {
  return await bcrypt.hash(password, saltRound)
}

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword)
}

const sessionObj = {}

const generateSessionId = () => {
  // uuidv4
  return crypto.randomBytes(16).toString('hex')
}

const handleApiRegister = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const params = JSON.parse(body)
    const { email, password } = params
    const hashedPassword = await hashPassword(password)
    const newUser = { id: users.length + 1, email: email, password: hashedPassword, role: 'user' }
    users.push(newUser)
    const cloneNewUser = { ...newUser }
    delete cloneNewUser.password
    res.writeHead(201, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Register successfully",
      data: {
        ...cloneNewUser
      }
    }))
  })
}

const handleApiLogin = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const params = JSON.parse(body)
    const { email, password } = params
    const checkEmailUser = users.find(user => user.email === email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Email is incorrect")
      return
    }
    const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
    if (!checkPasswordUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Password is incorrect")
      return
    }
    const existingSession = Object.values(sessionObj).find(session => session.email === email)
    // 1h = 60p * 60s = 3600s = 3600000ms
    const expiredTime = moment(Date.now() + 3600000).unix()
    console.log({ expiredTime })
    console.log("type", typeof (expiredTime))
    if (existingSession) {
      for (const sessionId in sessionObj) {
        const session = sessionObj[sessionId]
        if (session.email === email) {
          res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expiredTime}`)
        }
      }
    } else {
      const sessionId = generateSessionId()
      sessionObj[sessionId] = checkEmailUser
      res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expiredTime}`)
    }
    const cloneUser = { ...checkEmailUser }
    delete cloneUser.password
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Login successfully",
      data: {
       ...cloneUser
      }
    }))
  })
}

const checkSessionId = (req, res, sessionObj) => {
  // sessionId=4c0c3de69513a18c48cccf102a01d556; Expires=1718112089
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]

  if (!sessionId || !sessionObj[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return false
  }
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessionObj[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return false
  }
  return true
}

const handleApiChangePassword = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const { email, password, newPassword } = JSON.parse(body)
    const checkEmailUser = users.find(user => user.email === email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Email is incorrect")
      return
    }
    const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
    if (!checkPasswordUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Password is incorrect")
      return
    }
    const hashedNewPassword = await hashPassword(newPassword)
    checkEmailUser.password = hashedNewPassword
    console.log("users", users)
    console.log("sessionObj", sessionObj)
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Change password successfully",
      data: {}
    }))
  })
}

const handleApiForgotPassword = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const { email, newPassword } = JSON.parse(body)
    const checkEmailUser = users.find(user => user.email === email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Email is incorrect")
      return
    }
    const hashedNewPassword = await hashPassword(newPassword)
    checkEmailUser.password = hashedNewPassword
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Reset password successfully",
      data: {}
    }))
  })
}

const handleRequest = (req, res) => {
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const method = req.method
  const itemId = parseInt(_.last(path.split('/')))
  //    /api/v1/items/1   ["", "api","items", "1"]
  if (method === "POST" && path === "/api/v1/auth/register") {
    handleApiRegister(req, res)
  } else if (method === "POST" && path === "/api/v1/auth/login") {
    handleApiLogin(req, res)
  } else if (method === "POST" && path === "/api/v1/auth/change-password") {
    handleApiChangePassword(req, res)
  } else if (method === "POST" && path === "/api/v1/auth/forgot-password") {
    handleApiForgotPassword(req, res)
  } else if (method === "POST" && path === "/api/v1/auth/logout") {
    handleApiLogout(req, res)
  } else if (method === "GET" && path === "/api/v1/items") {
    handleGetItems(req, res)
  } else if (method === "GET" && path.startsWith("/api/v1/items/") && itemId) {
    handleGetItemDetail(req, res)
  } else if (method === "GET" && path === "/api/v1/items/pagination") {
    handleApiGetPagination(req, res)
  } else if (method === "POST" && path === "/api/v1/items") {
    handleApiCreateNewItem(req, res)
  } else if (method === "PUT" && path.startsWith("/api/v1/items/") && itemId) {
    handleApiUpdateItem(req, res)
  } else if (method === "DELETE" && path.startsWith("/api/v1/items/") && itemId) {
    handleApiDeleteItem(req, res)
  } else {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Not found")
  }
}

const server = http.createServer(handleRequest)

const PORT = 3000
server.listen(PORT, () => {
  console.log("Running on port 3000")
})
