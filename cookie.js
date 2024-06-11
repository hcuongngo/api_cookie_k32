const http = require('http')
const url = require('url')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const _ = require('lodash')

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
    const { email, password } = JSON.parse(body)
    if (!email) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Email is required")
      return
    }
    if (!password) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Password is required")
      return
    }
    const newUser = { id: users.length + 1, email, password, role: "user" }
    newUser.password = await hashPassword(password)
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
    const { email, password } = JSON.parse(body)
    if (!email) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Email is required")
      return
    }
    if (!password) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Password is required")
      return
    }
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
    const existingSession = Object.values(sessionObj).find(userInfo => userInfo.email === email)
    if (existingSession) {
      for (const sessionId in sessionObj) {
        const userInfo = sessionObj[sessionId]
        if (userInfo.email === email) {
          res.setHeader('Set-Cookie', `sessionId=${sessionId}`)
        }
      }
    } else {
      const sessionId = generateSessionId()
      console.log({ sessionId })
      sessionObj[sessionId] = checkEmailUser
      res.setHeader('Set-Cookie', `sessionId=${sessionId}`)
    }
    console.log({ sessionObj })
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

const handleApiChangePassword = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    console.log("req.headers.cookie", req.headers.cookie)
    const sessionId = req.headers.cookie && _.last(req.headers.cookie.split("="))
    console.log("sessionId", sessionId)
    if (!sessionId || !sessionObj[sessionId]) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const { email, password, newPassword } = JSON.parse(body)
    if (!email) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Email is required")
      return
    }
    if (!password) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Password is required")
      return
    }
    if (!newPassword) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("New password is required")
      return
    }
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
      "Content-Type": "text/plain"
    })
    res.end("Change password successfully")
  })
}

// the same logic with node jwt
const handleApiForgotPassword = () => { }

const handleApiLogout = (req, res) => {
  const sessionId = req.headers.cookie && _.last(req.headers.cookie.split("="))
  if (!sessionId || !sessionObj[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  delete sessionObj[sessionId]
  res.writeHead(200, {
    "Content-Type": "text/plain"
  })
  res.end("Logout successfully")
}

const checkSessionId = (req, res, sessionObj) => {
  const sessionId = req.headers.cookie && _.last(req.headers.cookie.split("="))
  if (!sessionId || !sessionObj[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return false
  }
  return true
}

const handleGetItems = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get all items successfully",
    data: items
  }))
}

const handleGetItemDetail = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(_.last(path.split('/')))
  const checkItem = items.find(item => item.id === itemId)
  if (!checkItem) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item id not found")
    return
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get item detail successfully",
    data: checkItem
  }))
}

const handleApiGetPagination = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  const reqUrl = url.parse(req.url, true)
  const pageIndex = parseInt(reqUrl.query.pageIndex) || 1
  const limit = parseInt(reqUrl.query.limit) || 10
  const startIndex = (pageIndex - 1) * limit
  const endIndex = startIndex + limit - 1
  let result = {
    data: items.slice(startIndex, endIndex + 1),
    itemsPerPage: limit,
    currentPageIndex: pageIndex,
    totalPages: Math.ceil(items.length / limit)
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get pagination successfully",
    data: result
  }))
}

const checkRoleAdmin = (req, res, sessionObj) => {
  const sessionId = req.headers.cookie && _.last(req.headers.cookie.split("="))
  if (sessionObj[sessionId].role !== "admin") {
    res.writeHead(403, {
      "Content-Type": "text/plain"
    })
    res.end("Forbidden")
    return false
  } else {
    return true
  }
}
const handleApiCreateNewItem = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  const isCorrectRoleAdmin = checkRoleAdmin(req, res, sessionObj)
  if (!isCorrectRoleAdmin) {
    return
  }
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', () => {
    let newItem = JSON.parse(body)
    const { name, description } = newItem
    if (!name) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Name is required")
      return
    }
    if (!description) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Description is required")
      return
    }
    newItem = { id: items.length + 1, ...newItem }
    items.push(newItem)
    res.writeHead(201, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Create new item successfully",
      data: newItem
    }))
  })
}

const handleApiUpdateItem = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  const isCorrectRoleAdmin = checkRoleAdmin(req, res, sessionObj)
  if (!isCorrectRoleAdmin) {
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(_.last(path.split('/')))
  let checkItem = items.find(item => item.id === itemId)
  if (!checkItem) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item id not found")
    return
  }
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', () => {
    let itemUpdate = JSON.parse(body)
    if (Object.keys(itemUpdate).length === 0) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("At least one field name or description must be provided")
      return
    }
    const itemIndex = items.findIndex(item => item.id === itemId)
    items[itemIndex] = { ...items[itemIndex], ...itemUpdate }
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Update item successfully",
      data: items[itemIndex]
    }))
  })
}

const handleApiDeleteItem = (req, res) => {
  const isCorrectSessionId = checkSessionId(req, res, sessionObj)
  if (!isCorrectSessionId) {
    return
  }
  const isCorrectRoleAdmin = checkRoleAdmin(req, res, sessionObj)
  if (!isCorrectRoleAdmin) {
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(_.last(path.split('/')))
  let itemIndex = items.findIndex(item => item.id === itemId)
  if (itemIndex === -1) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item id not found")
    return
  }
  items.splice(itemIndex, 1)
  res.writeHead(200, {
    "Content-Type": "text/plain"
  })
  res.end("Delete item successfully")
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
