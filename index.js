require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const OpenAI = require("openai");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

db.connect(err => {
    if (err) {
        console.error("MySQL connection error:", err);
    } else {
        console.log("Connected to MySQL database.");
        db.query(`
            CREATE TABLE IF NOT EXISTS users_tbl (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE,
                email VARCHAR(255) UNIQUE,
                password VARCHAR(255),
                verified BOOLEAN DEFAULT false
            )
        `);
    }
});

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// OpenAI setup
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Middleware: authenticate JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Register
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.query(
            "INSERT INTO users_tbl (username, email, password) VALUES (?, ?, ?)",
            [username, email, hashedPassword],
            (err) => {
                if (err) {
                    return res.status(400).json({ error: err.message });
                }

                const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1d" });
                const verifyLink = `${process.env.BASE_URL}/verify-email?token=${token}`;

                transporter.sendMail({
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: "Verify your email",
                    html: `<p>Click <a href="${verifyLink}">here</a> to verify your email.</p>`
                });

                res.json({ message: "Registered! Check your email to verify." });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify email
app.get("/verify-email", (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: "Token missing" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(400).json({ error: "Invalid token" });

        db.query("UPDATE users_tbl SET verified = true WHERE email = ?", [decoded.email], (err) => {
            if (err) return res.status(500).json({ error: "Database error" });
            res.send("Email verified! You can now log in.");
        });
    });
});

// Login with email
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    db.query("SELECT * FROM users_tbl WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(400).json({ error: "User not found" });

        const user = results[0];

        if (!user.verified) return res.status(400).json({ error: "Email not verified" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    });
});

// Chatbot route (protected)
app.post("/chat", authenticateToken, async (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    try {
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: message }]
        });

        res.json({ reply: completion.choices[0].message.content });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, () => console.log("Server running on port 3000"));
