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
    // origin:"https://harmonious-rugelach-13c182.netlify.app",
    origin: "*",
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
            if (userForget.email === userEmail) {
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



//ADMIN DASHBOARD 
//HALL DETAILS

//POST THE HALL DETAILS
app.post("/createhall", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        const findBlock = await db.collection("hall").find({ block: req.body.block }).toArray()
        console.log(findBlock)
        console.log(findBlock.length)

        let hallno = req.body.hall
        console.log(hallno)

        let startletter = hallno.startsWith(req.body.block)
        console.log(startletter)

        const findhall = findBlock.some(hno => {
            return hno.hall === hallno
        })
        console.log(findhall)


        if (findBlock.length === 0 && startletter) {
            const hall = await db.collection("hall").insertOne(req.body)
            console.log("hall1")
            res.json({ message: "hall created" })

        } else if (findBlock.length > 0 && !findhall && startletter) {
            const hall = await db.collection("hall").insertOne(req.body)
            console.log("hall2")
            res.json({ message: "hall created" })

        } else {
            res.json({ message: "Hall number already exists" })
        }

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "createhall error" })
    }
})

//GET THE HALL DETAILS
app.get("/gethall", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const gethall = await db.collection("hall").find().toArray()
        res.json(gethall)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "gethall error" })
    }
})

//UPDATE THE HALL DETAILS
app.put("/updatehall/:hallid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        const findhall = await db.collection("hall").findOne({ _id: mongodb.ObjectId(req.params.hallid) })
        // console.log(findhall.hall)

        const gethall = await db.collection("hall").find({ hall: { $nin: [findhall.hall] } }).toArray()
        // console.log(gethall)

        let hallno = req.body.hall
        // console.log(hallno)

        let startletter = hallno.startsWith(req.body.block)
        // console.log(startletter)

        const checkhall = gethall.some(hno => {
            return hno.hall === hallno
        })

        // console.log(checkhall)

        if (findhall && !checkhall && startletter) {
            const updatehall = await db.collection("hall").updateOne({ _id: mongodb.ObjectId(req.params.hallid) }, { $set: req.body })
            res.json({ message: "Hall updated successfully" })
        } else {
            res.json({ message: "Hall is not found" })
        }
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Updatehall error" })
    }
})

//DELETE THE HALL DETAILS
app.delete("/deletehall/:hallid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const findhall = await db.collection("hall").findOne({ _id: mongodb.ObjectId(req.params.hallid) })
        if (findhall) {
            const deletehall = await db.collection("hall").deleteOne({ _id: mongodb.ObjectId(req.params.hallid) })
            res.json({ message: "Hall deleted" })
        } else {
            res.json({ message: "Hallid is not found" })
        }
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Delete hall error" })
    }

})



//STAFF DETAILS

//POST STAFF DETAILS
app.post("/createstaff", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        const findstaff = await db.collection("staff").find({ department: req.body.department }).toArray()
        const findphone = await db.collection("staff").find({ phone: req.body.phone }).toArray()
        const findemail = await db.collection("staff").find({ email: req.body.email }).toArray()

        const str = req.body.department
        const matches = str.match(/\b(\w)/g).join("")
        const convert = [...matches]

        console.log(convert.splice(1, 1))
        console.log(convert.join(""))

        const final = convert.join("")
        const number = findstaff.length + 101

        if (findstaff.length === 0 && findphone.length === 0 && findemail.length === 0) {

            req.body.staffid = final + number
            const createstaff = await db.collection("staff").insertOne(req.body)
            res.json({ message: "staff created" })

        } else if (findstaff.length > 0 && findphone.length === 0 && findemail.length === 0) {

            req.body.staffid = final + number
            const createstaff = await db.collection("staff").insertOne(req.body)
            res.json({ message: "staff created" })

        } else {
            res.json({ message: "Phone number and Email is already exists" })
        }

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Create Staff Error" })
    }
})

//UPDATE STAFF DETAILS
app.put("/updatestaff/:staffid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const updatestaff = await db.collection("staff").findOne({ _id: mongodb.ObjectId(req.params.staffid) })
        const findphone = await db.collection("staff").find({ phone: { $nin: [updatestaff.phone] } }).toArray()
        const findemail = await db.collection("staff").find({ email: { $nin: [updatestaff.email] } }).toArray()

        const boophone = findphone.some(ph => {
            return ph === req.body.phone
        })
        // console.log(boophone)

        const booemail = findemail.some(em => {
            return em === req.body.email
        })
        // console.log(booemail)

        if (!boophone && !booemail) {
            const updatestaff = await db.collection("staff").updateOne({ _id: mongodb.ObjectId(req.params.staffid) }, { $set: req.body })
            res.json({ message: "Staff Details updated" })
        } else {
            res.json({ message: "Phone number and Email is already exists" })
        }
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Updatestaff Error" })
    }
})

//GET STAFF DETAILS
app.get("/getstaff", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const getStaff = await db.collection("staff").find().toArray()
        res.json(getStaff)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Get Staff Error" })
    }
})

//DELETE STAFF DETAILS
app.delete("/deletestaff/:staffid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const deleteStaff = await db.collection("staff").deleteOne({ _id: mongodb.ObjectId(req.params.staffid) })
        res.json({ message: "Staff deleted" })
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Delete staff error" })
    }
})


//STUDENT DETAILS
//POST STUDENT DETAILS
app.post("/createstudent", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        const student = await db.collection("student").find({ department: req.body.department }).toArray()
        const department_year = await db.collection("student").find({ $and: [{ department: req.body.department }, { joinyear: req.body.joinyear }] }).toArray()
        const phone = await db.collection("student").find({ phone: req.body.phone }).toArray()
        const email = await db.collection("student").find({ email: req.body.email }).toArray()

        console.log(department_year.length)

        const currentYear = new Date()

        let joinyear = req.body.joinyear

        const year_of_last_two_numbers = [joinyear].join(",").slice(4, joinyear.length)
        console.log("twonumber:" + year_of_last_two_numbers)

        const department = req.body.department
        const first_letters = department.match(/\b(\w)/g).join("")

        const convert_array = [...first_letters]
        console.log(convert_array.splice(1, 1))

        const join_letters = convert_array.join("")

        const student_id = department_year.length + 101
        //console.log(year_of_last_two_numbers + join_letters + student_id)


        const month = currentYear.getMonth() + 1
        //console.log("month:" + month)

        const year = currentYear.getFullYear()
        //console.log("year:" + year)

        const monthyear = `${month}-${year}`
        //console.log("monthyear:" + monthyear)

        const arr = monthyear.split("-");
        //console.log("arr:" + arr)


        const arr1 = joinyear.split("-")
        //console.log("arr1:" + arr1)

        //console.log(arr[0] - arr1[0])
        //console.log((arr[1] - arr1[1]) * 12 + (arr[0] - arr1[0]))

        const study_month = (arr[1] - arr1[1]) * 12 + (arr[0] - arr1[0])

        if (study_month <= 12) {
            req.body.year_of_study = "1st Year"
        } else if (study_month <= 24) {
            req.body.year_of_study = "2nd Year"
        } else if (study_month <= 36) {
            req.body.year_of_study = "3rd Year"
        } else {
            console.log("Join year is incorrect")
        }

        if (student.length === 0 && phone.length === 0 && email.length === 0) {

            req.body.student_id = year_of_last_two_numbers + join_letters + student_id
            const createStudent = await db.collection("student").insertOne(req.body)
            res.json({ message: "Student created" })

        } else if (student.length > 0 && phone.length === 0 && email.length === 0) {

            req.body.student_id = year_of_last_two_numbers + join_letters + student_id
            const createStudent = await db.collection("student").insertOne(req.body)
            res.json({ message: "Student created" })

        } else {

            res.json({ message: "Phone number and email-id is already exists" })
        }

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Create student error" })
    }
})

//UPDATE STUDENT DETAILS
app.put("/updatestudent/:studentid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const updateStudent = await db.collection("student").findOne({ _id: mongodb.ObjectId(req.params.studentid) })
        console.log(updateStudent)
        const phone = await db.collection("student").find({ phone: { $nin: [updateStudent.phone] } }).toArray()
        console.log(phone)
        const email = await db.collection("student").find({ email: { $nin: [updateStudent.email] } }).toArray()
        console.log(email)
        const stuphone = phone.some(ph => {
            return ph === req.body.phone
        })
        console.log("stuphone" + stuphone)

        const stuemail = email.some(em => {
            return em === req.body.email
        })
        console.log("stuemail" + stuemail)

        const department_year = await db.collection("student").find({ $and: [{ department: req.body.department }, { joinyear: req.body.joinyear }] }).toArray()

        console.log(department_year.length)

        const currentYear = new Date()

        let joinyear = req.body.joinyear

        const year_of_last_two_numbers = [joinyear].join(",").slice(4, joinyear.length)
        console.log("twonumber:" + year_of_last_two_numbers)

        const department = req.body.department
        const first_letters = department.match(/\b(\w)/g).join("")

        const convert_array = [...first_letters]
        console.log(convert_array.splice(1, 1))

        const join_letters = convert_array.join("")

        const student_id = department_year.length + 101
        console.log(year_of_last_two_numbers + join_letters + student_id)


        const month = currentYear.getMonth() + 1
        console.log("month:" + month)

        const year = currentYear.getFullYear()
        console.log("year:" + year)

        const monthyear = `${month}-${year}`
        console.log("monthyear:" + monthyear)

        const arr = monthyear.split("-");
        console.log("arr:" + arr)


        const arr1 = joinyear.split("-")
        console.log("arr1:" + arr1)

        //console.log(arr[0] - arr1[0])
        //console.log((arr[1] - arr1[1]) * 12 + (arr[0] - arr1[0]))

        const study_month = (arr[1] - arr1[1]) * 12 + (arr[0] - arr1[0])

        if (study_month <= 12) {
            req.body.year_of_study = "1st Year"
        } else if (study_month <= 24) {
            req.body.year_of_study = "2nd Year"
        } else if (study_month <= 36) {
            req.body.year_of_study = "3rd Year"
        } else {
            console.log("Join year is incorrect")
        }

        if (!stuphone && !stuemail) {

            req.body.student_id = year_of_last_two_numbers + join_letters + student_id
            const createStudent = await db.collection("student").updateOne({ _id: mongodb.ObjectId(req.params.studentid) }, { $set: req.body })
            res.json({ message: "Student updated" })

        } else {

            res.json({ message: "Phone number and email-id is already exists" })
        }

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Update student error" })
    }
})

//GET STUDENT DETAILS
app.get("/getstudent", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const getStudent = await db.collection("student").find().toArray()
        res.json(getStudent)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Get student error" })
    }
})

//GET ONE DEPARTMENT AND ONE YEAR_OF_STUDY
app.get("/getstudent/:department/:yearofstudy", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const getStudent = await db.collection("student").find({ $and: [{ department: req.params.department }, { year_of_study: req.params.yearofstudy }] }).toArray()
        res.json(getStudent)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Get student error" })
    }
})

//DELETE STUDENT
app.delete("/deletestudent/:studentid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const deletestudent = await db.collection("student").deleteOne({ _id: mongodb.ObjectId(req.params.studentid) })
        res.json({ message: "Student deleted" })
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Delete student error" })
    }
})




//EXAM DETAILS
//POST EXAM DETAILS
app.post("/createexam", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const findhall = await db.collection("hall").find().toArray()

        const hallindex = findhall.findIndex(hall => {
            return hall.hall === req.body.hall
        })

        const totalseat = findhall[hallindex].number_of_seats
        console.log("seats:" + findhall[hallindex].number_of_seats)

        // const checkhall = findhall.some(hall => {
        //     return hall.hall === req.body.hall
        // })

        // console.log("checkhall:" + checkhall)

        // const studentDepartment = await db.collection("student").find().toArray()

        // const stuid = studentDepartment.findIndex(student =>{
        //     return student.student_id === req.body.students
        // })
        // console.log(stuid)
        // console.log( req.body.students)

        // const findstudent = await db.collection("exam").find({ students: { student_id: req.body.student_id } }).toArray()
        // console.log("findstudent:" + findstudent)

        const findall = await db.collection("exam").find().toArray()

        const findexam = await db.collection("exam").find({ hall: req.body.hall }).toArray()
        const finddate = await db.collection("exam").find({ date: req.body.date }).toArray()
        console.log("finddate:" + finddate.length)

        const checkdate = finddate.some(date => {
            return date.date === req.body.date
        })
        console.log("checkdate: "+checkdate)

        let stulength = finddate.map(stu => {
            return stu.students.length
        })
        console.log("exam_student_length:" + stulength)



const findstudent = finddate.some(stu=>{
    // console.log(stu.students[0].student_id)
    // console.log(req.body.students)
    // console.log(req.body.students[0].student_id)
    return stu.students[0].student_id === req.body.students[0].student_id
})
console.log("findstudent: "+findstudent)

        const findstartime = await db.collection("exam").find({ start_time: req.body.start_time }).toArray()
        //console.log("findstartime:"+findstartime)

        const findendtime = await db.collection("exam").find({ end_time: req.body.end_time }).toArray()
        //console.log("findendtime:"+findendtime)



        if (checkdate ) {

            if (finddate.length === 1 && findstartime && findendtime && stulength < totalseat && !findstudent) {

                console.log("lengthnotempty:" + findexam.length)
                const exam = await db.collection("exam").updateOne({ date: req.body.date },
                    {
                        $push:
                        {
                            students:
                                req.body.students[0]
                        }
                    })

                res.json({ message: "Exam Hall Created Successfully" })

            }
            // else if (findexam.length === 0 && stulength < totalseat) {

            //     console.log("lengthempty:" + findexam.length)
            //     const exam = await db.collection("exam").insertOne(req.body)
            //     res.json({ message: "Exam Hall Created Successfully" })

            // } 
            else {

                res.json({ message: "1 seats are not available and invalid hallno and student is already exists" })

            }
        } else {

            console.log(findexam.length)
            console.log(stulength)
            console.log(totalseat)
            if (finddate.length === 0 && stulength < totalseat && !findstudent) {

                console.log("lengthempty:" + findexam.length)
                const exam = await db.collection("exam").insertOne(req.body)
                res.json({ message: "Exam Hall Created Successfully" })
            } else {

                res.json({ message: "0 seats are not available and invalid hallno and student is already exists" })

            }
        }



        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Create exam error" })
    }
})

//UPDATE EXAM DETAILS
app.put("/updateexam/:examid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Update exam error" })
    }
})

//GET EXAM DETAILS
app.get("/getexam", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")
        const exam = await db.collection("exam").find().toArray()
        res.json(exam)
        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Get exam error" })
    }
})

//DELETE EXAM
app.delete("/deleteexam/:examid", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL)
        const db = connection.db("Exam_seating_arrangement")

        await connection.close()
    } catch (error) {
        res.status(500).json({ message: "Delete exam error" })
    }
})


app.listen(3010)