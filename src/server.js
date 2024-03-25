import fastify from "fastify";
import { env } from "./env/index.js";
import z from 'zod'
import { prisma } from "./lib/prisma.js";
import pgk from "bcryptjs";
import jwt from "@fastify/jwt";

const {compare, bcrypt} = pgk

const app = fastify()

app.register(jwt,{
    secret: env.JWT_SECRET
})

app.post('/users', async (request, reply) => {
    const registerBodySchema = z.object({
        name: z.string(),
        email: z.string(),
        password: z.string().min(6)
    })

    const {name, email, password} = registerBodySchema.parse(request.body)

    const password_hash = await bcrypt.hash(password, 6)

    const userWithSameEmail = await prisma.users.findUnique({
        where:{
            email
        }
    })

    if(userWithSameEmail) {
        return reply.status(409).send({message: 'E-mail já existe'})
    }
    
    await prisma.users.create({
        data:{
            name,
            email,
            password_hash
        }
    })

    return reply.status(201).send()
})

app.post('/authenticate', async (request, reply) => {
    try{
        const registerBodySchema = z.object({
            email: z.string(),
            password: z.string().min(6)
        })
    
        const {email, password} = registerBodySchema.parse(request.body)
        
        const user = await prisma.users.findUnique({
            where:{
                email: email
            }
        })
    
        if (!user){
            return reply.status(409).send({message: 'E-mail não existe'})
        }
    
        const doesPsswordWatches = await compare(password, user.password_hash)

        if(!doesPsswordWatches){
            return reply.status(409).send({message: 'Credenciais inválidas'})
        }
        
        const token = await reply.jwtSign({},{
            sign:{
                sub: user.id
            }
        })

        return reply.status(200).send({
            token
        })
    }catch{
        return reply.status(500).send({message: 'Erro no servidor'})
    }

})

app.get('/me', async (request, reply) => {
     await request.jwtVerify()

     console.log(request.user);

     return reply.status(200).send()
})

app.listen({
    host:'0.0.0.0',
    port:env.PORT
}).then(()=>{
    console.log(`🔥 Servidor rodando 3333`)
}) 