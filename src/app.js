import express from "express";
import users from "./database"
import { v4 as uuidv4 } from "uuid"
import { compare, hash } from "bcryptjs"
import jwt from "jsonwebtoken"
import "dotenv/config"

const app = express()
app.use(express.json())

const ensureAuthMiddleware = (request, response, next) => {
    let authorization = request.headers.authorization

    if(!authorization) {
        return response.status(401).json({
            message: "Invalid token"
        })
    }

    authorization = authorization.split(' ')[1]

    return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
        if(error) {
            return response.status(401).json({
                message: "Invalid token"
            })
        }

        request.user = {
            id: decoded.sub,
        }

        return next()
    })
}

const ensureUserIsAdm = (request, response, next) => {
    const userAdmin =  users.find((el) => el.uuid === request.user.id)
    const userIsAdm = userAdmin.isAdm

    if(!userIsAdm) {
        return response.status(403).json({
            message: "Missing admin permissions"
        })
    }

    return next()
}

const ensureUserAlreadyExistMiddleware = (request, response, next) => {
    const userAlreadyExist = users.find((user) => user.email === request.body.email)

    if(userAlreadyExist) {
        return response.status(409).json({
            message: "E-mail already registered"
        })
    }

    return next()
}

const createUserService = async (userData) => {
    const user = {
        uuid: uuidv4(),
        ...userData,
        password: await hash(userData.password, 10),
        createdOn: new Date(),
        updatedOn: new Date() 
    }
    users.push(user)
    const newUser =  {...user}
    delete newUser.password

    return [201, newUser]
}

const createSessionService =  async ({email, password}) => {

    const user = users.find(el => el.email === email)

    if(!user) {
        return [401, {
            message: "Wrong email/password"
        }]
    }

    const passwordMatch = await compare(password, user.password)

    if(!passwordMatch){
        return [401, {
            message: "Wrong email/password"
        }]
    }

    const token = jwt.sign(
        {},
        process.env.SECRET_KEY,
        {
            expiresIn: "24h",
            subject: user.uuid
        }
    )

    return [200, {token}]
}

const listUsersService = async () => {
    return [200, users]
}

const listUserInSessionService = async (userId) => {
    const user = users.find((user) => user.uuid === userId)
    const userLogged = {...user}
    delete userLogged.password

    return [200, userLogged]
}

const attUserService = async (attBody, userId, userToBeAtt) => {
    const user = users.find((user) => user.uuid === userId)
    const userIndex = users.findIndex((user) => user.uuid === userId)
    const userIsAdmin = user.isAdm
    delete attBody.isAdm
    
    if(userToBeAtt !== user.uuid && !userIsAdmin) {
        return [403, {
            message: "Missing admin permissions"
        }]
    }

    const userAtt = {
        ...user,
        ...attBody,
        updatedOn: new Date()
    }
    users.splice(userIndex, 1, userAtt)
    const attUser = {...userAtt}
    delete attUser.password

    return [200, attUser]
}

const deleteUserService = async (id, idUserToBeDeleted) => {
    const user = users.find((user) => user.uuid === id)
    
    if(id !== idUserToBeDeleted && !user.isAdm) {
        return [403, {
            message: "Missing admin permissions"
        }]
    }
    users.splice(idUserToBeDeleted, 1)

    return [204, {}]
   
}

const createUserController = async (request, response) => {
    const [status, data] = await createUserService(request.body)
    return response.status(status).json(data)
}

const createSessionController = async (request, response) => {
    const [status, data] = await createSessionService(request.body)
    return response.status(status).json(data)
}

const listUsersController = async (request, response) => {
    const [status, data] = await listUsersService(users)
    return response.status(status).json(data)
}
const listUserInSessioController = async (request, response) => {
    const [status, data] = await listUserInSessionService(request.user.id)
    return response.status(status).json(data)
}

const attUserController = async (request, response) => {
    const [status, data] = await attUserService(request.body, request.user.id, request.params.uuid)
    return response.status(status).json(data)
}

const deleteUserController = async (request, response) => {
    const [status, data] = await deleteUserService(request.user.id, request.params.uuid)
    return response.status(status).json(data)
}

app.post("/users", ensureUserAlreadyExistMiddleware, createUserController)
app.post("/login",  createSessionController)
app.get("/users", ensureAuthMiddleware, ensureUserIsAdm, listUsersController)
app.get("/users/profile", ensureAuthMiddleware, listUserInSessioController)
app.patch("/users/:uuid", ensureAuthMiddleware, attUserController)
app.delete("/users/:uuid", ensureAuthMiddleware, deleteUserController)

app.listen(3000, () => {
    console.log("Server running in port 3000")
})

export default app