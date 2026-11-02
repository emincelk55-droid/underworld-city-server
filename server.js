require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const { pool, initDB } = require("./src/db");
const game = require("./src/game");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

// ====== CONFIG ======
const START_MONEY = 5000;
const DEV_ENDPOINTS = process.env.ENABLE_DEV_ENDPOINTS === "true";
const TICK_MS = 10_000;

if (!process.env.DATABASE_URL) console.error("Missing env: DATABASE_URL");
if (!process.env.JWT_SECRET) console.error("Missing env: JWT_SECRET");

// ====== YARDIMCILAR ======
function auth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) return res.status(401).json({ error: "Giriş gerekli" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Oturum geçersiz" });
  }
}

// Hataları tek yerden JSON'a çevirir.
const handle = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    if (e instanceof game.GameError) return res.status(e.status).json({ error: e.message });
    console.error(e);
    res.status(500).json({ error: "Sunucu hatası" });
  }
};

// Basit IP bazlı hız sınırı (giriş/kayıt için)
function rateLimit(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip;
    const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (list.length >= max) return res.status(429).json({ error: "Çok fazla deneme, biraz bekle" });
    list.push(now);
    hits.set(key, list);
    next();
  };
}
const authLimiter = rateLimit(20, 60_000);

// ====== AUTH ======
app.post(
  "/api/register",
  authLimiter,
  handle(async (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== "string" || !/^[A-Za-z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ error: "Kullanıcı adı 3-20 karakter olmalı (harf, rakam, _)" });
    if (typeof password !== "string" || password.length < 6)
      return res.status(400).json({ error: "Şifre en az 6 karakter olmalı" });

    const hashed = await bcrypt.hash(password, 10);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const u = await client.query(
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
        [username, hashed]
      );
      await client.query("INSERT INTO players (user_id, money) VALUES ($1, $2)", [u.rows[0].id, START_MONEY]);
      await client.query("COMMIT");
      const token = jwt.sign({ id: u.rows[0].id, username }, process.env.JWT_SECRET, { expiresIn: "7d" });
      res.json({ success: true, token });
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.code === "23505") return res.status(400).json({ error: "Bu kullanıcı adı alınmış" });
      throw err;
    } finally {
      client.release();
    }
  })
);

app.post(
  "/api/login",
  authLimiter,
  handle(async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik bilgi" });
    const r = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Kullanıcı adı veya şifre hatalı" });
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  })
);

// ====== OYUN ======
app.get("/api/world", handle(async (req, res) => res.json(await game.getWorld(pool))));
app.get("/api/prices", handle(async (req, res) => res.json(await game.getPrices(pool))));
app.get("/api/leaderboard", handle(async (req, res) => res.json(await game.leaderboard(pool))));

app.get("/api/me", auth, handle(async (req, res) => res.json(await game.getState(pool, req.user.id))));

// Eski istemciler için
app.get(
  "/api/profile",
  auth,
  handle(async (req, res) => res.json({ profile: await game.getState(pool, req.user.id) }))
);

app.post(
  "/api/trade",
  auth,
  handle(async (req, res) => {
    const result = await game.trade(pool, req.user.id, req.body || {});
    io.emit("price", { districtId: result.districtId, goodId: result.goodId, price: result.newPrice });
    res.json(result);
  })
);

app.post(
  "/api/travel",
  auth,
  handle(async (req, res) => res.json(await game.startTravel(pool, req.user.id, String(req.body?.to || ""))))
);

// Sadece geliştirme: ENABLE_DEV_ENDPOINTS=true iken açık. Canlıda ekonomiyi bozar.
if (DEV_ENDPOINTS) {
  app.post(
    "/api/profile/add-money",
    auth,
    handle(async (req, res) => {
      const amount = Number(req.body.amount);
      if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: "Bad amount" });
      const r = await pool.query("UPDATE players SET money = money + $1 WHERE user_id = $2 RETURNING money", [
        Math.floor(amount),
        req.user.id
      ]);
      res.json({ success: true, money: Number(r.rows[0].money) });
    })
  );
}

// Derlenmiş Flutter web istemcisi varsa aynı sunucudan servis et
const webDir = path.join(__dirname, "client", "build", "web");
app.use(express.static(webDir));
app.get("/", (req, res) =>
  res.sendFile(path.join(webDir, "index.html"), (err) => {
    if (err) res.send("Underworld City MMO API is running");
  })
);

// ====== SOCKET.IO ======
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (token) {
    try {
      socket.user = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      /* misafir olarak devam */
    }
  }
  next();
});

io.on("connection", (socket) => {
  if (socket.user) socket.join(`user:${socket.user.id}`);
  io.emit("online", io.engine.clientsCount);

  socket.on("chat", (data) => {
    if (!socket.user) return;
    const text = String(data?.text ?? data ?? "").trim().slice(0, 280);
    if (!text) return;
    io.emit("chat", { from: socket.user.username, text, at: new Date().toISOString() });
  });

  socket.on("disconnect", () => io.emit("online", io.engine.clientsCount));
});

// ====== TICK ======
async function tick() {
  try {
    await game.tickPrices(pool);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const arrivals = await game.resolveArrivals(client);
      await client.query("COMMIT");
      for (const a of arrivals) io.to(`user:${a.userId}`).emit("arrived", a);
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
    io.emit("prices", await game.getPrices(pool));
  } catch (e) {
    console.error("tick error:", e.message);
  }
}

const PORT = process.env.PORT || 3000;
initDB()
  .then(() => {
    setInterval(tick, TICK_MS);
    server.listen(PORT, () => console.log("Server running on port " + PORT));
  })
  .catch((e) => {
    console.error("❌ initDB error:", e);
    process.exit(1);
  });
