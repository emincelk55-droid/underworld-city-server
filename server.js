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

const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());

// ====== CONFIG ======
const START_MONEY = 5000;

// Render'da DATABASE_URL ve JWT_SECRET şart
if (!process.env.DATABASE_URL) {
  console.error("Missing env: DATABASE_URL");
}
if (!process.env.JWT_SECRET) {
  console.error("Missing env: JWT_SECRET");
}

// ====== DB ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  // users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // players (1-1)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      money INT NOT NULL DEFAULT 0,
      level INT NOT NULL DEFAULT 1,
      xp INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

initDB().catch((e) => {
  console.error("initDB error:", e);
});

// ====== AUTH MIDDLEWARE ======
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

// ====== ROUTES ======
app.get("/", (req, res) => {
  res.send("Underworld City MMO API is running");
});

// REGISTER
app.post("/api/register", async (req, res) => {
  const client = await pool.connect();
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await client.query("BEGIN");

    const userInsert = await client.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, created_at",
      [username, hashed]
    );

    const user = userInsert.rows[0];

    await client.query(
      "INSERT INTO players (user_id, money, level, xp) VALUES ($1, $2, $3, $4)",
      [user.id, START_MONEY, 1, 0]
    );

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    // username unique hatası vs.
    return res.status(400).json({ error: "Username already exists" });
  } finally {
    client.release();
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const result = await pool.query("SELECT * FROM users WHERE username=$1", [
      username
    ]);

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
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PROFILE (token gerekli)
app.get("/api/profile", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        u.id as user_id,
        u.username,
        u.created_at as user_created_at,
        p.money,
        p.level,
        p.xp,
        p.created_at as player_created_at
      FROM users u
      JOIN players p ON p.user_id = u.id
      WHERE u.id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Profile not found" });
    }

    res.json({ profile: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// TEST: PARA EKLE (token gerekli)
// body: { "amount": 1000 }
app.post("/api/profile/add-money", auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Bad amount" });
    }

    const updated = await pool.query(
      "UPDATE players SET money = money + $1 WHERE user_id = $2 RETURNING money, level, xp",
      [amount, req.user.id]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "Profile not found" });
    }

    res.json({ success: true, stats: updated.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== SOCKET.IO ======
let onlineUsers = 0;

io.on("connection", (socket) => {
  onlineUsers++;
  io.emit("online", onlineUsers);

  socket.on("chat", (data) => {
    io.emit("chat", data);
  });

  socket.on("disconnect", () => {
    onlineUsers--;
    io.emit("online", onlineUsers);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on port " + PORT));
