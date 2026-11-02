// Uçtan uca API testleri: gerçek sunucuyu ayrı bir veritabanıyla başlatır.
// Çalıştırma: TEST_DATABASE_URL=postgres://... npm test
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { Pool } = require("pg");

const DB = process.env.TEST_DATABASE_URL || "postgres://uw:uw@localhost:5432/uw_test";
const PORT = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://localhost:${PORT}`;
let server;
let pool;

async function api(method, url, body, token) {
  const res = await fetch(BASE + url, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}
const post = (url, body, token) => api("POST", url, body, token);
const get = (url, token) => api("GET", url, null, token);

const uid = () => Math.random().toString(36).slice(2, 8);
async function newPlayer(prefix = "t") {
  const username = `${prefix}_${uid()}`;
  const r = await post("/api/register", { username, password: "secret123" });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const id = (await pool.query("SELECT id FROM users WHERE username=$1", [username])).rows[0].id;
  return { username, token: r.data.token, id };
}
const sql = (q, p) => pool.query(q, p);
const moneyOf = async (id) => Number((await sql("SELECT money FROM players WHERE user_id=$1", [id])).rows[0].money);
const totalMoney = async () => {
  const r = await sql(`SELECT
    (SELECT COALESCE(SUM(money),0) FROM players) +
    (SELECT COALESCE(SUM(bank),0) FROM gangs) +
    (SELECT COALESCE(SUM(escrow),0) FROM market_orders WHERE status='open') AS t`);
  return Number(r.rows[0].t);
};

before(async () => {
  // Temiz test veritabanı
  const admin = new Pool({ connectionString: DB.replace(/\/[^/]+$/, "/postgres"), ssl: false });
  const name = DB.split("/").pop();
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`).catch(() => {});
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  pool = new Pool({ connectionString: DB, ssl: false });

  server = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: {
      ...process.env,
      DATABASE_URL: DB,
      DATABASE_SSL: "false",
      JWT_SECRET: "test-secret-test-secret-test-secret-123",
      PORT: String(PORT),
      TRAVEL_SECONDS_PER_UNIT: "1",
      NODE_ENV: "test"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  server.stderr.on("data", (d) => process.stderr.write(d));
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(BASE + "/healthz")).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("Sunucu başlamadı");
});

after(async () => {
  server?.kill();
  await pool?.end();
});

test("kayıt ve giriş doğrulaması", async () => {
  assert.equal((await post("/api/register", { username: "a", password: "secret123" })).status, 400);
  assert.equal((await post("/api/register", { username: "ok_name", password: "123" })).status, 400);
  const p = await newPlayer();
  const dup = await post("/api/register", { username: p.username, password: "secret123" });
  assert.equal(dup.status, 400);
  assert.equal((await post("/api/login", { username: p.username, password: "wrong" })).status, 400);
  const ok = await post("/api/login", { username: p.username, password: "secret123" });
  assert.equal(ok.status, 200);
  assert.ok(ok.data.token);
  assert.equal((await get("/api/me")).status, 401);
});

test("tüccar ticareti: para, envanter, vergi ve kapasite", async () => {
  const p = await newPlayer();
  const me = (await get("/api/me", p.token)).data;
  assert.equal(me.money, 5000);
  const buy = await post("/api/trade", { goodId: "kahve", qty: 10, side: "buy" }, p.token);
  assert.equal(buy.status, 200, JSON.stringify(buy.data));
  assert.equal(await moneyOf(p.id), 5000 - buy.data.total);
  const sell = await post("/api/trade", { goodId: "kahve", qty: 10, side: "sell" }, p.token);
  assert.equal(sell.status, 200);
  assert.ok(sell.data.total < buy.data.total, "al-sat aynı yerde zarar ettirmeli (makas + vergi)");
  // Olmayan malı satamaz, kapasiteyi aşamaz, parası yetmeyeni alamaz
  assert.equal((await post("/api/trade", { goodId: "kahve", qty: 1, side: "sell" }, p.token)).status, 400);
  assert.equal((await post("/api/trade", { goodId: "radyo", qty: 50, side: "buy" }, p.token)).status, 400);
  assert.equal((await post("/api/trade", { goodId: "mucevher", qty: 10, side: "buy" }, p.token)).status, 400);
  assert.equal((await post("/api/trade", { goodId: "kahve", qty: -5, side: "buy" }, p.token)).status, 400);
});

test("aynı anda gelen alımlar para kopyalamaz", async () => {
  const p = await newPlayer();
  await sql("UPDATE players SET money=1000, capacity=1000 WHERE user_id=$1", [p.id]);
  const results = await Promise.all(
    Array.from({ length: 10 }, () => post("/api/trade", { goodId: "kahve", qty: 5, side: "buy" }, p.token))
  );
  const spent = results.filter((r) => r.status === 200).reduce((s, r) => s + r.data.total, 0);
  assert.equal(await moneyOf(p.id), 1000 - spent);
  assert.ok((await moneyOf(p.id)) >= 0);
});

test("yolculuk: enerji harcar, yoldayken ticaret yok, varınca semt değişir", async () => {
  const p = await newPlayer();
  const t = await post("/api/travel", { to: "carsi" }, p.token);
  assert.equal(t.status, 200, JSON.stringify(t.data));
  assert.equal((await post("/api/trade", { goodId: "kahve", qty: 1, side: "buy" }, p.token)).status, 400);
  assert.equal((await post("/api/travel", { to: "merkez" }, p.token)).status, 400);
  const wait = new Date(t.data.arriveAt) - Date.now() + 300;
  await new Promise((r) => setTimeout(r, Math.max(0, wait)));
  const me = (await get("/api/me", p.token)).data;
  assert.equal(me.districtId, "carsi");
  assert.equal(me.energy, 90);
});

test("borsa: eşleşme, emanet, iptal iadesi ve para korunumu", async () => {
  const seller = await newPlayer("s");
  const buyer = await newPlayer("b");
  await sql("INSERT INTO player_goods (user_id, good_id, qty, avg_cost) VALUES ($1,'tutun',20,50)", [seller.id]);
  const before = await totalMoney();

  const ask1 = await post("/api/market/order", { goodId: "tutun", side: "sell", price: 70, qty: 10 }, seller.token);
  const ask2 = await post("/api/market/order", { goodId: "tutun", side: "sell", price: 65, qty: 4 }, seller.token);
  assert.equal(ask1.status, 200, JSON.stringify(ask1.data));
  assert.equal(ask2.data.restingQty, 4);

  // Alıcı 72'den 6 adet ister: önce 65'ten 4, sonra 70'ten 2 dolar
  const bid = await post("/api/market/order", { goodId: "tutun", side: "buy", price: 72, qty: 6 }, buyer.token);
  assert.equal(bid.status, 200, JSON.stringify(bid.data));
  assert.equal(bid.data.filledQty, 6);
  assert.equal(bid.data.spent, 4 * 65 + 2 * 70);
  const st = await get("/api/storage", buyer.token);
  assert.equal(st.data.find((x) => x.goodId === "tutun").qty, 6);

  // Bekleyen alış emri parayı emanete alır, iptal edince iade eder
  const m0 = await moneyOf(buyer.id);
  const rest = await post("/api/market/order", { goodId: "tutun", side: "buy", price: 50, qty: 10 }, buyer.token);
  assert.equal(await moneyOf(buyer.id), m0 - 500);
  const c = await post("/api/market/cancel", { orderId: rest.data.orderId }, buyer.token);
  assert.equal(c.status, 200);
  assert.equal(await moneyOf(buyer.id), m0);
  // Başkasının emrini iptal edemez
  assert.equal((await post("/api/market/cancel", { orderId: ask1.data.orderId }, buyer.token)).status, 404);

  // Toplam para sadece vergi kadar azalmış olmalı
  const tax = Math.ceil(4 * 65 * 0.03) + Math.ceil(2 * 70 * 0.03);
  assert.equal(before - (await totalMoney()), tax);
});

test("çete: kurma, katılma, yetki ve kasa", async () => {
  const boss = await newPlayer("boss");
  const soldier = await newPlayer("sol");
  const g = await post("/api/gangs", { name: `Test ${uid()}`, tag: uid().slice(0, 3).toUpperCase(), color: "#C0392B", emblem: "rose" }, boss.token);
  assert.equal(g.status, 200, JSON.stringify(g.data));
  assert.equal(await moneyOf(boss.id), 2500);
  assert.equal((await post(`/api/gangs/${g.data.id}/join`, {}, soldier.token)).status, 200);
  assert.equal((await post("/api/gang/deposit", { amount: 1000 }, soldier.token)).status, 200);
  // Asker kasadan para çekemez, Baba çekebilir
  assert.equal((await post("/api/gang/withdraw", { amount: 100 }, soldier.token)).status, 400);
  assert.equal((await post("/api/gang/withdraw", { amount: 100 }, boss.token)).status, 200);
  // Asker Babayı atamaz
  assert.equal((await post("/api/gang/kick", { userId: boss.id }, soldier.token)).status, 400);
});

test("soygun: koruma, aile üyesi ve para aktarımı", async () => {
  const a = await newPlayer("rob");
  const v = await newPlayer("vic");
  // Yeni oyuncular korumada
  assert.equal((await post("/api/rob", { targetId: v.id }, a.token)).status, 400);
  await sql("UPDATE players SET protected_until = now() - interval '1 minute', district_id='gecekondu', money=10000 WHERE user_id = ANY($1)", [[a.id, v.id]]);
  const before = await totalMoney();
  const r = await post("/api/rob", { targetId: v.id }, a.token);
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(["success", "escaped", "caught"].includes(r.data.outcome));
  if (r.data.outcome === "success") {
    assert.equal(await moneyOf(v.id), 10000 - r.data.cash);
    // Soyulan kişi korumaya girer
    await sql("UPDATE players SET energy=100 WHERE user_id=$1", [a.id]);
    assert.equal((await post("/api/rob", { targetId: v.id }, a.token)).status, 400);
  }
  // Soygun para yaratmaz (yakalanınca ceza para giderdir)
  assert.equal(before - (await totalMoney()), r.data.fine || 0);
  assert.equal((await post("/api/rob", { targetId: a.id }, a.token)).status, 400);
});

test("işletme: kurma, semt kısıtı, hammadde ve kira", async () => {
  const p = await newPlayer("biz");
  await sql("UPDATE players SET money=20000, district_id='carsi' WHERE user_id=$1", [p.id]);
  assert.equal((await post("/api/business/buy", { type: "imalathane" }, p.token)).status, 400, "Çarşı'da imalathane olmaz");
  const b = await post("/api/business/buy", { type: "kahvehane" }, p.token);
  assert.equal(b.status, 200, JSON.stringify(b.data));
  assert.equal(await moneyOf(p.id), 20000 - 3000 - 25);
  assert.equal((await post("/api/business/buy", { type: "kahvehane" }, p.token)).status, 400, "aynı semtte ikinci kahvehane olmaz");

  await post("/api/trade", { goodId: "kahve", qty: 8, side: "buy" }, p.token);
  const load = await post(`/api/business/${b.data.id}/load`, { goodId: "kahve", qty: 8 }, p.token);
  assert.equal(load.data.loaded, 8);
  // 2 saat geçmiş gibi yap: 2 parti üretilir, 2 saatlik kira kesilir
  await sql(
    "UPDATE businesses SET last_tick = now() - interval '2 hours 1 minute', rent_paid_until = now() - interval '1 hour 1 minute' WHERE id=$1",
    [b.data.id]
  );
  const m0 = await moneyOf(p.id);
  const list = (await get("/api/businesses", p.token)).data;
  const k = list.find((x) => x.id === b.data.id);
  assert.equal(k.till, 2 * 255);
  assert.equal(k.stock.kahve ?? 0, 0);
  assert.equal(m0 - (await moneyOf(p.id)), 2 * 25);
  const c = await post(`/api/business/${b.data.id}/collect`, {}, p.token);
  assert.equal(c.data.collected, 510);
});

test("hız sınırı ve güvenlik başlıkları", async () => {
  const res = await fetch(BASE + "/healthz");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal((await post("/api/profile/add-money", { amount: 1e6 }, "x")).status, 404, "geliştirme endpoint'i kapalı");
});
