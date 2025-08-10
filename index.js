// api/index.js
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const OpenAI = require("openai");
const cors = require("cors");

const app = express();

// Enable CORS for any origin
app.use(cors({
  origin: '*',
}));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Ensure table exists
db.query(
  `CREATE TABLE IF NOT EXISTS users_tbl (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE,
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255),
      verified BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => {
    if (err) console.error("Error creating users_tbl:", err.message);
    else console.log("users_tbl ready (or existed already)");
  }
);

// Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// OpenAI client
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Helper: generate JWT
function signJwt(payload, expires = "1h") {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: expires });
}

// Middleware: authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const tokenFromHeader = authHeader && authHeader.split(" ")[1];
  const token = tokenFromHeader || req.cookies?.token;

  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ---------- Routes ----------

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", api: "jixify backend" });
});

// Register
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const hashed = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users_tbl (username, email, password) VALUES (?, ?, ?)",
      [username || null, email, hashed],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "User or email already exists" });
          console.error("DB insert error:", err);
          return res.status(500).json({ error: "Database error" });
        }

        const token = signJwt({ email }, "1d");
        const verifyLink = `${process.env.BASE_URL_PROD.replace(/\/$/, "")}/verify-email?token=${token}`;

        transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Verify your email",
          html: `<p>Hi ${username || ""},</p>
                 <p>Click to verify your email: <a href="${verifyLink}">${verifyLink}</a></p>`
        }, (mailErr) => {
          if (mailErr) {
            console.error("Mail error:", mailErr);
            return res.status(500).json({ error: "Failed to send verification email" });
          }
          return res.status(201).json({ message: "Registered. Check your email to verify." });
        });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Verify email
app.get("/verify-email", (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send("Token missing");

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(400).send("Invalid or expired token");

    db.query("UPDATE users_tbl SET verified = true WHERE email = ?", [decoded.email], (dbErr, result) => {
      if (dbErr) {
        console.error(dbErr);
        return res.status(500).send("Database error");
      }
      if (result.affectedRows === 0) return res.status(404).send("Email not found");

      res.send(`<html><body style="font-family:Arial;text-align:center;padding:40px;">
        <h1>✅ Email Verified</h1>
        <p>You can now login at your frontend.</p>
      </body></html>`);
    });
  });
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  db.query("SELECT * FROM users_tbl WHERE email = ?", [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }
    if (!results.length) return res.status(400).json({ error: "User not found" });

    const user = results[0];
    if (!user.verified) return res.status(403).json({ error: "Email not verified" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = signJwt({ id: user.id, email: user.email }, "1h");
    return res.json({ token });
  });
});

// Chat (protected)
app.post("/chat", authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message is required" });

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are an assistant." },
        { role: "user", content: message }
      ],
      max_tokens: 2000
    });

    const aiText = response?.choices?.[0]?.message?.content ?? "";
    return res.json({ reply: aiText });
  } catch (err) {
    console.error("OpenAI error:", err);
    return res.status(500).json({ error: "AI processing error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
