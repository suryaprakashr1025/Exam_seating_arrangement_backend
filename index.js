const express = require("express")
const cors = require("cors")
//const bodyParser = require("body-parser")
const nodemailer = require("nodemailer")
const mongodb = require("mongodb")
const mongoClient = mongodb.MongoClient;
const dotenv = require("dotenv").config()
const bcrypt = require("bcryptjs")
const URL = process.env.DB
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET
//USING THIS URL IN GENERATE ALPHANUMERIC NUMBER (https://www.gigacalculator.com/randomizers/random-alphanumeric-generator.php)
const app = express()

app.use(cors({
   // origin: "http://localhost:3000",
    origin:"https://harmonious-rugelach-13c182.netlify.app/"
}))
app.use(express.json())


//POST = ADMIN REGISTER PAGE
app.post("/admin/register", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        //hasing password
        var salt = await bcrypt.genSalt(10) //secret key
        //console.log(salt)
        var hash = await bcrypt.hash(req.body.password, salt) //hash the password
        //console.log(hash)
        req.body.password = hash;

        //select the collection
        //Do operation
        const checkUsername = await db.collection("admin").find({ username: req.body.username }).toArray()
        console.log(checkUsername.length)

        if (checkUsername.length === 0) {
            const checkEmail = await db.collection("admin").find({ email: req.body.email }).toArray()
            console.log(checkEmail.length)
            if (checkEmail.length === 0) {
                const admin = await db.collection("admin").insertOne(req.body)
                console.log(admin)
                res.status(200).json({ message: "admin created" })
            } else {
                res.json({ message: "username,email and password is already exists" })
            }

        } else {
            res.json({ message: "username,email and password is already exists" })
        }

        //close the connection
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = ADMIN LOGIN PAGE
app.post("/admin/login", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        //select the collection
        //Do operation
        const admin = await db.collection("admin").findOne({ username: req.body.username })
        console.log(admin)

        if (admin) {
            //create token
            const token = jwt.sign({ _id: admin._id }, JWT_SECRET, { expiresIn: "5m" })
            console.log(token)
            const compare = await bcrypt.compare(req.body.password, admin.password) //req.body.password is automatic hasing === admin.password already hasing
            console.log(compare) //return boolean value
            if (compare) {
                res.status(200).json({ message: "success", token })
            } else {
                res.json({ message: "username and password is incorrect" })
            }
        } else {
            res.json({ message: "username and password is incorrect" })
        }
        //close the connection
        await connection.close()


    } catch (error) {
        res.status(500).json({ message: "something went wrong" })
    }
})

//POST = USER REGISTER PAGE
app.post("/user/register", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        //select the collection
        //Do operation
        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(req.body.password, salt)
        req.body.password = hash;

        const checkUsername = await db.collection("user").findOne({ username: req.body.username })
        console.log(checkUsername)

        if (!checkUsername) {
            const checkEmail = await db.collection("user").find({ email: req.body.email }).toArray()
            console.log(checkEmail.length)

            if (checkEmail.length === 0) {
                const user = await db.collection("user").insertOne(req.body)
                console.log(user)
                res.status(200).json({ message: "user created" })
            } else {
                res.json({ message: "username,email and password is already exists" })
            }

        } else {
            res.json({ message: "username,email and password is already exists" })
        }

        //close the connection
        await connection.close()



    } catch (error) {
        res.status(401).json({ message: "something went wrong" })
    }
})

//POST = USER LOGIN PAGE
app.post("/user/login", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        //select the collection
        //Do operation
        const loginUser = await db.collection("user").findOne({ username: req.body.username })
        console.log(loginUser)

        if (loginUser) {
            const token = jwt.sign({ _id: loginUser._id }, JWT_SECRET, { expiresIn: "5m" })
            console.log(token)
            const compare = await bcrypt.compare(req.body.password, loginUser.password)
            console.log(compare)
            if (compare) {
                res.json({ message: "success", token })
            } else {
                res.json({ message: "username and password is incorrect" })
            }
        } else {
            res.json({ message: "username and password is incorrect" })
        }

        //close connection
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "something went wrong" })
    }
})

//PUT = ADMIN PASSWORD CHANGE
app.put("/admin/:username", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        const checkUsername = await db.collection("admin").findOne({ username: req.params.username })
        console.log(checkUsername)
        delete req.body._id
        delete req.body.username
        if (checkUsername) {
            const compare = await bcrypt.compare(req.body.currentPassword, checkUsername.password)
            console.log(compare)
            delete req.body.currentPassword
            if (compare) {
                const salt = await bcrypt.genSalt(10)
                const hash = await bcrypt.hash(req.body.password, salt)
                req.body.password = hash
                const changePassword = await db.collection("admin").updateOne({ username: req.params.username }, { $set: req.body })
                console.log(changePassword)
                res.status(200).json({ message: "password changed successfully" })

                //new password : $2a$10$R93EwsoTAUHjHKnW0RLuAezBADRO8dCN3xtoczaLdOtTb6hKr7AW2

                //current password : $2a$10$HXslJD2SeumtwAbuAJ.DCOTesmiHEBUB3wQIdfnBx8LptQjE2tSyG
            } else {
                res.json({ message: "username and current password is incorrect" })
            }
        } else {
            res.json({ message: "username and current password is incorrect" })
        }

        //connection close
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//PUT = USER PASSWORD CHANGE
app.put("/user/:username", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        const checkUsername = await db.collection("user").findOne({ username: req.params.username })
        console.log(checkUsername)

        delete req.body._id
        delete req.body.username

        if (checkUsername) {
            const compare = await bcrypt.compare(req.body.currentPassword, checkUsername.password)
            console.log(compare)
            delete req.body.currentPassword

            if (compare) {
                const salt = await bcrypt.genSalt(10)
                const hash = await bcrypt.hash(req.body.password, salt)
                req.body.password = hash
                const changePassword = await db.collection("user").updateOne({ username: req.params.username }, { $set: req.body })
                console.log(changePassword)
                res.status(200).json({ message: "password changed successfully" })
            } else {
                res.json({ message: "username and password is incorrect" })
            }

        } else {
            res.json({ message: "username and password is incorrect" })
        }

        //connection close
        await connection.close()
    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = ADMIN FORGET PASSWORD
app.post("/admin/forgetpassword", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the datatbase
        const db = connection.db("Exam_seating_arrangement")
       // console.log("surya")
        //select the collection
        //Do operation
        const adminUsername = await db.collection("admin").findOne({ username: req.body.username })
        console.log(adminUsername)
        delete req.body.username

        if (adminUsername) {
            const adminEmail = req.body.email
            console.log(adminEmail)
            
            if (adminEmail === adminUsername.email) {
                const salt = await bcrypt.genSalt(2)
                console.log(salt) //salt.length = 29

                const hash = await (await bcrypt.hash(req.body.email, salt)).slice(24, 36)
                console.log(hash) //this hash is sending mail code
                //req.body.email = hash

                //mail code again hash
                const hash1 = await bcrypt.hash(hash, salt)
                console.log(hash1)

                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: process.env.US,
                        pass: process.env.PS
                    }
                })

                const mailOptions = {
                    from: process.env.US,
                    to: req.body.email,
                    subject: "This is forget password mail and do not reply",
                    html: `<h1>This is your current password:</h1>
                    <span><h2>${hash}</h2></span>`
                }

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error)
                    } else {
                        console.log(info);
                        console.log("info:" + info.response)
                    }
                })

                transporter.close()

                delete req.body.email

                const changePassword = await db.collection("admin").updateOne({ username: adminUsername.username }, { $set: { password: hash1 } })
                console.log(changePassword)

                res.json({ message: "mail sent successfully" })
            } else {
                res.json({ message: "username and email is incorrect" })
            }
           
        } else {
            res.json({ message: "username and email is incorrect" })
        }

        //close the connection
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

//POST = USER FORGET PASSWORD
app.post("/user/forgetpassword", async (req, res) => {
    try {
        //connect the database
        const connection = await mongoClient.connect(URL)

        //select the database
        const db = connection.db("Exam_seating_arrangement")

        //select the collection
        //Do operation
        const userForget = await db.collection("user").findOne({ username: req.body.username })
        console.log(userForget)
        delete req.body.username
        if (userForget) {
            //const userEmail = await db.collection("user").findOne({ email: req.body.email} )
            const userEmail = req.body.email
           console.log(userEmail)
            if (userForget.email === userEmail ) {
                const salt = await bcrypt.genSalt(2)
                console.log(salt)
                console.log(salt.length)

                const hash = await (await bcrypt.hash(req.body.email, salt)).slice(25, 35)
                console.log(hash)
                const hash1 = await bcrypt.hash(hash, salt)
                console.log(hash1)

                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: process.env.US,
                        pass: process.env.PS
                    }
                })

                const mailOptions = {
                    from: process.env.US,
                    to: req.body.email,
                    subject: "This is forget password mail and do not reply",
                    html: `<h1>This is your current password:</h1>
                <h1>${hash}</h1>`
                }

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error)
                    } else {
                        console.log(info)
                        console.log(info.response)
                    }
                })

                transporter.close()
                delete req.body.email;

                const changePassword = await db.collection('user').updateOne({ username: userForget.username }, { $set: { password: hash1 } })
                console.log(changePassword)

                res.status(200).json({ message: "mail sent successfully" })

            } else {
                res.json({ message: "username and email is incorrect" })
            }
            
        } else {
            res.json({ message: "username and email is incorrect" })
        }

        //connection close
        await connection.close()

    } catch (error) {
        res.status(401).json({ message: "unauthorized" })
    }
})

app.listen(process.env.PORT || 3010)