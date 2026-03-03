require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- ENV CHECKS ---
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is missing in environment variables!");
}
if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing in environment variables!");
}

// --- DATABASE ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Render Postgres için genelde gerekli
});

pool.on("error", (err) => {
  console.error("❌ Unexpected PG error:", err);
});

// DB init (users tablosu)
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ DB ready: users table OK");
  } catch (err) {
    console.error("❌ DB init error:", err);
  }
}
initDB();

// --- AUTH MIDDLEWARE ---
function auth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "No token" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Bad auth format" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, username, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- ROUTES ---
app.get("/", (req, res) => {
  res.send("Underworld City MMO API is running");
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Invalid fields" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [username, hashed]
    );

    res.json({ success: true });
  } catch (err) {
    // unique ihlali vs.
    return res.status(400).json({ error: "Username already exists" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const result = await pool.query(
      "SELECT id, username, password FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error("❌ /api/login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ME (Token ile kullanıcı bilgisi)
app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, created_at FROM users WHERE id=$1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- SOCKET.IO ---
const io = new Server(server, {
  cors: { origin: "*" },
});

let onlineUsers = 0;

io.on("connection", (socket) => {
  onlineUsers++;
  io.emit("online", onlineUsers);

  socket.on("chat", (data) => {
    // data: { username, message } gibi
    io.emit("chat", data);
  });

  socket.on("disconnect", () => {
    onlineUsers--;
    io.emit("online", onlineUsers);
  });
});

// --- START ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("✅ Server running on port " + PORT);
});
