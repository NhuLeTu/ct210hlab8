const express = require("express")
const helmet = require("helmet")
const cors = require("cors")
const dotenv = require("dotenv")
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken")
const users = [];
dotenv.config();

const app = express();

app.use(helmet());
app.use(cors());

app.use(express.json());

function authenticateToken(req, res, next) {
    const authHeader = req.headers[authorization];
    const token = authHeader && authHeader.split('')[1];
    if(!token)
        return res.status(401).send("Access denied");

    jwt.verify(token, "giabodihihi", (err, user) => {
        if(err)
            res.status(403).send("Invalid token");
            req.user=user;
            next();
    });
}

app.get('/', (req, res) => {
    res.send("Welcom to B2105681 Cloud Security App!");
});

app.post("/register", async (req, res) => {
    try {
        const pass = await bcrypt.hash(req.body.password, 15);
        const user = {username: req.body.username, password: pass}
        users.push(user);
        res.status(201).send("User registered successfully");
    } catch (error) {
        res.status(500).send("Error registering user")
    }
});

app.post("/login", async (req, res) => {
    const user = users.find( u => u.username === req.body.username)
    if(!user) {
        res.status(400).send("User not found")
    }
    try {
        if(await bcrypt.compare(req.body.password, user.password)) {
            const token = jwt.sign({username: user.username}, "giabodihihi", {expiresIn: '24h'});
            res.json({token})
        } else {
            res.status(403).send("Error registering user")
        }
        res.status(201).send("Incorrect password");
    } catch (error) {
        res.status(500).send("Error logining user")
    }
});

app.get("/protected", authenticateToken, (req,res) => {
    res.send("This is a protected route")
})

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});