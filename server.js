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
const gangs = require("./src/gangs");
const pvp = require("./src/pvp");
const market = require("./src/market");

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

// ====== ÇETELER ======
async function pushTerritory() {
  try {
    io.emit("territory", await gangs.territory(pool));
  } catch (e) {
    console.error("territory push:", e.message);
  }
}
async function pushNews() {
  try {
    io.emit("news", await gangs.news(pool, 20));
  } catch (e) {
    console.error("news push:", e.message);
  }
}
// Çete üyeliği değişince kullanıcının socket'lerini doğru çete odasına taşı
async function syncGangRoom(userId) {
  const r = await pool.query("SELECT gang_id FROM gang_members WHERE user_id=$1", [userId]);
  const gangId = r.rows[0]?.gang_id;
  for (const s of await io.in(`user:${userId}`).fetchSockets()) {
    for (const room of s.rooms) if (room.startsWith("gang:")) s.leave(room);
    if (gangId) s.join(`gang:${gangId}`);
  }
}

app.get("/api/gangs", handle(async (req, res) => res.json(await gangs.listGangs(pool))));
app.get("/api/gangs/:id", handle(async (req, res) => res.json(await gangs.gangDetail(pool, Number(req.params.id)))));
app.get("/api/territory", handle(async (req, res) => res.json(await gangs.territory(pool))));
app.get("/api/news", handle(async (req, res) => res.json(await gangs.news(pool, 20))));
app.get(
  "/api/gang-options",
  handle(async (req, res) =>
    res.json({ cost: gangs.GANG_CREATE_COST, emblems: gangs.EMBLEMS, colors: gangs.COLORS, ranks: gangs.RANK_NAMES })
  )
);

app.post(
  "/api/gangs",
  auth,
  handle(async (req, res) => {
    const r = await gangs.createGang(pool, req.user.id, req.body || {});
    await syncGangRoom(req.user.id);
    pushNews();
    res.json(r);
  })
);
app.post(
  "/api/gangs/:id/join",
  auth,
  handle(async (req, res) => {
    const r = await gangs.joinGang(pool, req.user.id, Number(req.params.id));
    await syncGangRoom(req.user.id);
    io.to(`gang:${r.id}`).emit("gang", { type: "join", username: req.user.username });
    res.json(r);
  })
);
app.post(
  "/api/gang/leave",
  auth,
  handle(async (req, res) => {
    const r = await gangs.leaveGang(pool, req.user.id);
    await syncGangRoom(req.user.id);
    if (r.dissolved) {
      pushNews();
      pushTerritory();
    }
    res.json(r);
  })
);
app.post(
  "/api/gang/kick",
  auth,
  handle(async (req, res) => {
    const target = Number(req.body?.userId);
    const r = await gangs.kickMember(pool, req.user.id, target);
    await syncGangRoom(target);
    io.to(`user:${target}`).emit("gang", { type: "kicked" });
    res.json(r);
  })
);
app.post(
  "/api/gang/rank",
  auth,
  handle(async (req, res) => res.json(await gangs.setRank(pool, req.user.id, Number(req.body?.userId), req.body?.rank)))
);
app.post(
  "/api/gang/deposit",
  auth,
  handle(async (req, res) => res.json(await gangs.deposit(pool, req.user.id, req.body?.amount)))
);
app.post(
  "/api/gang/withdraw",
  auth,
  handle(async (req, res) => res.json(await gangs.withdraw(pool, req.user.id, req.body?.amount)))
);
app.post(
  "/api/territory/action",
  auth,
  handle(async (req, res) => {
    const r = await gangs.territoryAction(pool, req.user.id, String(req.body?.action || ""));
    pushTerritory();
    res.json(r);
  })
);

// ====== SOKAK / SOYGUN ======
function onlineUserIds() {
  const ids = new Set();
  for (const s of io.of("/").sockets.values()) if (s.user) ids.add(s.user.id);
  return ids;
}

app.get("/api/street", auth, handle(async (req, res) => res.json(await pvp.street(pool, req.user.id, onlineUserIds()))));
app.get("/api/robberies", auth, handle(async (req, res) => res.json(await pvp.record(pool, req.user.id))));
app.post(
  "/api/rob",
  auth,
  handle(async (req, res) => {
    const r = await pvp.rob(pool, req.user.id, req.body?.targetId);
    if (r.outcome !== "caught") {
      io.to(`user:${r.targetId}`).emit("robbed", {
        attacker: r.attacker,
        success: r.outcome === "success",
        cash: r.cash,
        goods: r.goods,
        districtId: r.districtId
      });
    }
    if (r.newsWorthy) pushNews();
    pushTerritory();
    res.json(r);
  })
);

// ====== BORSA ======
app.get("/api/market/summary/:districtId", handle(async (req, res) => res.json(await market.summary(pool, req.params.districtId))));
app.get(
  "/api/market/book/:districtId/:goodId",
  auth,
  handle(async (req, res) => res.json(await market.book(pool, req.user.id, req.params.districtId, req.params.goodId)))
);
app.get("/api/market/orders", auth, handle(async (req, res) => res.json(await market.myOrders(pool, req.user.id))));
app.get("/api/storage", auth, handle(async (req, res) => res.json(await market.storage(pool, req.user.id))));

app.post(
  "/api/market/order",
  auth,
  handle(async (req, res) => {
    const r = await market.placeOrder(pool, req.user.id, req.body || {});
    // Emri dolan karşı taraflara haber ver
    const byMaker = new Map();
    for (const f of r.fills) {
      const m = byMaker.get(f.makerId) || { side: f.makerSide, qty: 0, value: 0 };
      m.qty += f.qty;
      m.value += f.qty * f.price;
      byMaker.set(f.makerId, m);
    }
    for (const [makerId, m] of byMaker) {
      io.to(`user:${makerId}`).emit("order_filled", {
        side: m.side,
        goodId: r.goodId,
        goodName: r.goodName,
        districtId: r.districtId,
        qty: m.qty,
        avgPrice: Math.round(m.value / m.qty)
      });
    }
    io.emit("book", { districtId: r.districtId, goodId: r.goodId });
    const { fills, ...out } = r;
    res.json(out);
  })
);
app.post(
  "/api/market/cancel",
  auth,
  handle(async (req, res) => {
    const r = await market.cancelOrder(pool, req.user.id, req.body?.orderId);
    io.emit("book", { districtId: r.districtId, goodId: r.goodId });
    res.json(r);
  })
);
app.post("/api/storage/collect", auth, handle(async (req, res) => res.json(await market.collect(pool, req.user.id, req.body || {}))));

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

io.on("connection", async (socket) => {
  if (socket.user) {
    socket.join(`user:${socket.user.id}`);
    try {
      const r = await pool.query("SELECT gang_id FROM gang_members WHERE user_id=$1", [socket.user.id]);
      if (r.rows[0]) socket.join(`gang:${r.rows[0].gang_id}`);
    } catch {
      /* yoksay */
    }
  }
  io.emit("online", io.engine.clientsCount);

  socket.on("chat", (data) => {
    if (!socket.user) return;
    const text = String(data?.text ?? data ?? "").trim().slice(0, 280);
    if (!text) return;
    const msg = { from: socket.user.username, text, at: new Date().toISOString() };
    if (data?.channel === "gang") {
      const room = [...socket.rooms].find((r) => r.startsWith("gang:"));
      if (room) io.to(room).emit("chat", { ...msg, channel: "gang" });
      return;
    }
    io.emit("chat", { ...msg, channel: "global" });
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
    for (const o of await market.expireOrders(pool)) {
      io.to(`user:${o.user_id}`).emit("order_expired", { goodId: o.good_id, districtId: o.district_id });
      io.emit("book", { districtId: o.district_id, goodId: o.good_id });
    }
    const changes = await gangs.resolveWars(pool);
    await pushTerritory();
    if (changes.length) await pushNews();
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
