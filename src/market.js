// Oyuncular arası borsa.
//
// - Her semtin, her mal için ayrı bir emir defteri vardır. Emir vermek için o semtte olmalısın.
// - Fiyat-zaman önceliği: en iyi fiyat önce, aynı fiyatta önce gelen önce.
//   İşlem, defterde bekleyen emrin fiyatından gerçekleşir.
// - Alış emri verirken limit fiyat × miktar kadar para emanete alınır.
//   Satış emri verirken mal önce çantadan, sonra o semtteki depodan alınır.
// - Satın alınan mal alıcının o semtteki deposuna teslim edilir. Alıcı oradayken çantasına alır.
// - Satıcı semtin satış vergisini öder (kendi bölgesinde yarı vergi). Vergi gideri oyundaki parayı eritir.
//   Bölgeyi tutan aile verginin yarısını kasaya alır.
// - Fiyat sınırı: semtteki NPC çapa fiyatının %30'u ile 3 katı arası.
// - Kişi başı en fazla 10 açık emir. Emirler 72 saat sonra kendiliğinden iptal olur.

const { GameError, lockPlayer, activeTravel, resolveArrivals, cargo, cargoWeight } = require("./game");
const { gangOf, addInfluence } = require("./influence");

const MAX_OPEN = 10;
const ORDER_TTL_HOURS = 72;
const MIN_FACTOR = 0.3;
const MAX_FACTOR = 3;

async function tx(pool, fn, retries = 3) {
  for (let attempt = 0; ; attempt++) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (e) {
      await client.query("ROLLBACK");
      // Kilitlenme ya da serileştirme hatasında yeniden dene
      if ((e.code === "40P01" || e.code === "40001") && attempt < retries) continue;
      throw e;
    } finally {
      client.release();
    }
  }
}

// Aynı defter üzerindeki tüm değişiklikleri sıraya sokar
async function lockBook(client, districtId, goodId) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`book:${districtId}:${goodId}`]);
}

async function addStorage(client, userId, districtId, goodId, qty, unitCost) {
  if (qty <= 0) return;
  await client.query(
    `INSERT INTO player_storage (user_id, district_id, good_id, qty, avg_cost) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (user_id, district_id, good_id) DO UPDATE SET
       avg_cost = (player_storage.qty * player_storage.avg_cost + $4 * $5) / NULLIF(player_storage.qty + $4, 0),
       qty = player_storage.qty + $4`,
    [userId, districtId, goodId, qty, unitCost]
  );
}

// Satıcıya ödeme: vergi düşülür, bölgeyi tutan aileye pay gider
async function paySeller(client, sellerId, district, gross) {
  const g = await gangOf(client, sellerId);
  const ownTurf = g && district.controller_gang_id === g.id;
  const tax = Math.ceil(gross * district.tax * (ownTurf ? 0.5 : 1));
  await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [sellerId, gross - tax]);
  if (district.controller_gang_id && tax > 0) {
    await client.query("UPDATE gangs SET bank = bank + $2 WHERE id=$1", [district.controller_gang_id, Math.floor(tax / 2)]);
  }
  return tax;
}

function parseOrder({ goodId, side, price, qty }) {
  price = Math.floor(Number(price));
  qty = Math.floor(Number(qty));
  if (side !== "buy" && side !== "sell") throw new GameError("Geçersiz işlem");
  if (!Number.isFinite(price) || price < 1) throw new GameError("Geçersiz fiyat");
  if (!Number.isFinite(qty) || qty < 1 || qty > 1000) throw new GameError("Miktar 1-1000 arası olmalı");
  return { goodId: String(goodId || ""), side, price, qty };
}

async function placeOrder(pool, userId, body) {
  const { goodId, side, price, qty } = parseOrder(body);
  return tx(pool, async (client) => {
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken borsada işlem yapamazsın");
    const districtId = player.district_id;
    await lockBook(client, districtId, goodId);

    const dg = await client.query(
      `SELECT dg.anchor, g.name FROM district_goods dg JOIN goods g ON g.id=dg.good_id
       WHERE dg.district_id=$1 AND dg.good_id=$2`,
      [districtId, goodId]
    );
    if (!dg.rows.length) throw new GameError("Bu mal burada işlem görmüyor");
    const anchor = dg.rows[0].anchor;
    const minP = Math.max(1, Math.round(anchor * MIN_FACTOR));
    const maxP = Math.round(anchor * MAX_FACTOR);
    if (price < minP || price > maxP) throw new GameError(`Fiyat ₺${minP} ile ₺${maxP} arasında olmalı`);

    const open = await client.query("SELECT COUNT(*)::int AS n FROM market_orders WHERE user_id=$1 AND status='open'", [
      userId
    ]);
    if (open.rows[0].n >= MAX_OPEN) throw new GameError(`En fazla ${MAX_OPEN} açık emrin olabilir`);

    const district = (await client.query("SELECT * FROM districts WHERE id=$1", [districtId])).rows[0];
    const fills = [];
    let remaining = qty;
    let spent = 0;
    let earned = 0;
    let taxPaid = 0;

    if (side === "sell") {
      // Malı ayır: önce çanta, sonra depo
      const inv = await client.query(
        "SELECT qty FROM player_goods WHERE user_id=$1 AND good_id=$2 FOR UPDATE",
        [userId, goodId]
      );
      const st = await client.query(
        "SELECT qty FROM player_storage WHERE user_id=$1 AND district_id=$2 AND good_id=$3 FOR UPDATE",
        [userId, districtId, goodId]
      );
      const invQty = inv.rows[0]?.qty || 0;
      const stQty = st.rows[0]?.qty || 0;
      if (invQty + stQty < qty) throw new GameError("Çantanda ve bu semtteki deponda o kadar mal yok");
      const fromInv = Math.min(invQty, qty);
      if (fromInv) {
        await client.query("UPDATE player_goods SET qty = qty - $3 WHERE user_id=$1 AND good_id=$2", [userId, goodId, fromInv]);
      }
      if (qty - fromInv) {
        await client.query(
          "UPDATE player_storage SET qty = qty - $4 WHERE user_id=$1 AND district_id=$2 AND good_id=$3",
          [userId, districtId, goodId, qty - fromInv]
        );
      }

      // Bekleyen alış emirleriyle eşleş
      const bids = await client.query(
        `SELECT * FROM market_orders WHERE district_id=$1 AND good_id=$2 AND side='buy' AND status='open'
           AND price >= $3 AND user_id <> $4
         ORDER BY price DESC, id FOR UPDATE`,
        [districtId, goodId, price, userId]
      );
      for (const o of bids.rows) {
        if (remaining <= 0) break;
        const fill = Math.min(remaining, o.qty_left);
        const gross = o.price * fill;
        const tax = await paySeller(client, userId, district, gross);
        earned += gross - tax;
        taxPaid += tax;
        await client.query(
          `UPDATE market_orders SET qty_left = qty_left - $2, escrow = escrow - $3,
             status = CASE WHEN qty_left - $2 = 0 THEN 'filled' ELSE status END WHERE id=$1`,
          [o.id, fill, gross]
        );
        await addStorage(client, o.user_id, districtId, goodId, fill, o.price);
        await client.query(
          "INSERT INTO market_trades (district_id, good_id, price, qty, buyer_id, seller_id) VALUES ($1,$2,$3,$4,$5,$6)",
          [districtId, goodId, o.price, fill, o.user_id, userId]
        );
        fills.push({ makerId: o.user_id, makerSide: "buy", price: o.price, qty: fill, orderId: o.id });
        remaining -= fill;
      }
    } else {
      const worst = price * qty;
      if (Number(player.money) < worst) throw new GameError(`Bu emir için ${"₺" + worst.toLocaleString("tr-TR")} gerekiyor`);

      const asks = await client.query(
        `SELECT * FROM market_orders WHERE district_id=$1 AND good_id=$2 AND side='sell' AND status='open'
           AND price <= $3 AND user_id <> $4
         ORDER BY price ASC, id FOR UPDATE`,
        [districtId, goodId, price, userId]
      );
      for (const o of asks.rows) {
        if (remaining <= 0) break;
        const fill = Math.min(remaining, o.qty_left);
        const gross = o.price * fill;
        await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, gross]);
        spent += gross;
        await paySeller(client, o.user_id, district, gross);
        await client.query(
          `UPDATE market_orders SET qty_left = qty_left - $2,
             status = CASE WHEN qty_left - $2 = 0 THEN 'filled' ELSE status END WHERE id=$1`,
          [o.id, fill]
        );
        await addStorage(client, userId, districtId, goodId, fill, o.price);
        await client.query(
          "INSERT INTO market_trades (district_id, good_id, price, qty, buyer_id, seller_id) VALUES ($1,$2,$3,$4,$5,$6)",
          [districtId, goodId, o.price, fill, userId, o.user_id]
        );
        fills.push({ makerId: o.user_id, makerSide: "sell", price: o.price, qty: fill, orderId: o.id });
        remaining -= fill;
      }
    }

    // Kalan miktar deftere yazılır
    let orderId = null;
    if (remaining > 0) {
      const escrow = side === "buy" ? price * remaining : 0;
      if (escrow) await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, escrow]);
      const ins = await client.query(
        `INSERT INTO market_orders (user_id, district_id, good_id, side, price, qty_total, qty_left, escrow)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
        [userId, districtId, goodId, side, price, qty, remaining, escrow]
      );
      orderId = ins.rows[0].id;
    }

    const filledQty = qty - remaining;
    const volume = fills.reduce((s, f) => s + f.price * f.qty, 0);
    const g = await gangOf(client, userId);
    if (g && volume) await addInfluence(client, g.id, districtId, Math.floor(volume / 100), userId);
    if (filledQty) await client.query("UPDATE players SET xp = xp + $2 WHERE user_id=$1", [userId, Math.max(1, Math.floor(filledQty / 5))]);

    return {
      side,
      goodId,
      goodName: dg.rows[0].name,
      districtId,
      filledQty,
      avgPrice: filledQty ? Math.round(volume / filledQty) : null,
      spent,
      earned,
      tax: taxPaid,
      restingQty: remaining,
      orderId,
      fills
    };
  });
}

// Emri iptal et: alışta emanet para iade edilir, satışta mal o semtteki depoya döner
async function cancelOrderTx(client, order) {
  if (order.side === "buy") {
    if (order.escrow > 0) await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [order.user_id, order.escrow]);
  } else if (order.qty_left > 0) {
    const anchor = await client.query("SELECT anchor FROM district_goods WHERE district_id=$1 AND good_id=$2", [
      order.district_id,
      order.good_id
    ]);
    await addStorage(client, order.user_id, order.district_id, order.good_id, order.qty_left, anchor.rows[0]?.anchor || 0);
  }
  await client.query("UPDATE market_orders SET status='cancelled', escrow=0 WHERE id=$1", [order.id]);
}

async function cancelOrder(pool, userId, orderId) {
  orderId = Number(orderId);
  return tx(pool, async (client) => {
    const peek = await client.query("SELECT district_id, good_id FROM market_orders WHERE id=$1 AND user_id=$2", [
      orderId,
      userId
    ]);
    if (!peek.rows.length) throw new GameError("Emir bulunamadı", 404);
    await lockBook(client, peek.rows[0].district_id, peek.rows[0].good_id);
    const o = (await client.query("SELECT * FROM market_orders WHERE id=$1 FOR UPDATE", [orderId])).rows[0];
    if (o.status !== "open") throw new GameError("Bu emir artık açık değil");
    await cancelOrderTx(client, o);
    return { ok: true, districtId: o.district_id, goodId: o.good_id };
  });
}

// Süresi dolan emirleri iptal et (tick)
async function expireOrders(pool) {
  const due = await pool.query(
    `SELECT id, user_id, district_id, good_id FROM market_orders
     WHERE status='open' AND created_at < now() - make_interval(hours => $1) LIMIT 100`,
    [ORDER_TTL_HOURS]
  );
  const out = [];
  for (const d of due.rows) {
    await tx(pool, async (client) => {
      await lockBook(client, d.district_id, d.good_id);
      const o = (await client.query("SELECT * FROM market_orders WHERE id=$1 FOR UPDATE", [d.id])).rows[0];
      if (o.status === "open") {
        await cancelOrderTx(client, o);
        out.push(d);
      }
    });
  }
  return out;
}

// Depodan çantaya al
async function collect(pool, userId, { goodId, qty }) {
  return tx(pool, async (client) => {
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken depoya ulaşamazsın");
    const st = await client.query(
      `SELECT s.qty, s.avg_cost, g.weight FROM player_storage s JOIN goods g ON g.id=s.good_id
       WHERE s.user_id=$1 AND s.district_id=$2 AND s.good_id=$3 FOR UPDATE OF s`,
      [userId, player.district_id, goodId]
    );
    const row = st.rows[0];
    if (!row || row.qty <= 0) throw new GameError("Bu semtteki deponda bu mal yok");
    const free = player.capacity - cargoWeight(await cargo(client, userId));
    let want = qty == null ? row.qty : Math.floor(Number(qty));
    if (!Number.isFinite(want) || want < 1) throw new GameError("Geçersiz miktar");
    want = Math.min(want, row.qty);
    const fit = row.weight > 0 ? Math.min(want, Math.floor(free / row.weight)) : want;
    if (fit <= 0) throw new GameError("Çantanda yer yok");

    await client.query(
      "UPDATE player_storage SET qty = qty - $4 WHERE user_id=$1 AND district_id=$2 AND good_id=$3",
      [userId, player.district_id, goodId, fit]
    );
    const inv = await client.query("SELECT qty, avg_cost FROM player_goods WHERE user_id=$1 AND good_id=$2 FOR UPDATE", [
      userId,
      goodId
    ]);
    const have = inv.rows[0] || { qty: 0, avg_cost: 0 };
    const newQty = have.qty + fit;
    await client.query(
      `INSERT INTO player_goods (user_id, good_id, qty, avg_cost) VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id, good_id) DO UPDATE SET qty=$3, avg_cost=$4`,
      [userId, goodId, newQty, (have.qty * have.avg_cost + fit * row.avg_cost) / newQty]
    );
    return { collected: fit, left: row.qty - fit };
  });
}

// ====== OKUMA ======
async function summary(pool, districtId) {
  const r = await pool.query(
    `SELECT g.id AS good_id,
       (SELECT MAX(price) FROM market_orders o WHERE o.district_id=$1 AND o.good_id=g.id AND o.side='buy' AND o.status='open') AS best_bid,
       (SELECT MIN(price) FROM market_orders o WHERE o.district_id=$1 AND o.good_id=g.id AND o.side='sell' AND o.status='open') AS best_ask,
       (SELECT COALESCE(SUM(qty_left),0) FROM market_orders o WHERE o.district_id=$1 AND o.good_id=g.id AND o.side='buy' AND o.status='open')::int AS bid_qty,
       (SELECT COALESCE(SUM(qty_left),0) FROM market_orders o WHERE o.district_id=$1 AND o.good_id=g.id AND o.side='sell' AND o.status='open')::int AS ask_qty,
       (SELECT COALESCE(SUM(qty),0) FROM market_trades t WHERE t.district_id=$1 AND t.good_id=g.id AND t.created_at > now() - interval '24 hours')::int AS vol24,
       (SELECT price FROM market_trades t WHERE t.district_id=$1 AND t.good_id=g.id ORDER BY id DESC LIMIT 1) AS last
     FROM goods g ORDER BY g.base_price`,
    [districtId]
  );
  return r.rows.map((x) => ({
    goodId: x.good_id,
    bestBid: x.best_bid,
    bestAsk: x.best_ask,
    bidQty: x.bid_qty,
    askQty: x.ask_qty,
    vol24: x.vol24,
    last: x.last
  }));
}

async function book(pool, userId, districtId, goodId) {
  const [bids, asks, trades, mine, storage, dg] = await Promise.all([
    pool.query(
      `SELECT price, SUM(qty_left)::int AS qty, COUNT(*)::int AS orders FROM market_orders
       WHERE district_id=$1 AND good_id=$2 AND side='buy' AND status='open' GROUP BY price ORDER BY price DESC LIMIT 8`,
      [districtId, goodId]
    ),
    pool.query(
      `SELECT price, SUM(qty_left)::int AS qty, COUNT(*)::int AS orders FROM market_orders
       WHERE district_id=$1 AND good_id=$2 AND side='sell' AND status='open' GROUP BY price ORDER BY price ASC LIMIT 8`,
      [districtId, goodId]
    ),
    pool.query(
      `SELECT t.price, t.qty, t.created_at, b.username AS buyer, s.username AS seller FROM market_trades t
       LEFT JOIN users b ON b.id=t.buyer_id LEFT JOIN users s ON s.id=t.seller_id
       WHERE t.district_id=$1 AND t.good_id=$2 ORDER BY t.id DESC LIMIT 20`,
      [districtId, goodId]
    ),
    pool.query(
      `SELECT id, side, price, qty_total, qty_left, created_at FROM market_orders
       WHERE user_id=$1 AND district_id=$2 AND good_id=$3 AND status='open' ORDER BY id DESC`,
      [userId, districtId, goodId]
    ),
    pool.query("SELECT qty FROM player_storage WHERE user_id=$1 AND district_id=$2 AND good_id=$3", [
      userId,
      districtId,
      goodId
    ]),
    pool.query("SELECT anchor FROM district_goods WHERE district_id=$1 AND good_id=$2", [districtId, goodId])
  ]);
  const anchor = dg.rows[0]?.anchor || 1;
  return {
    districtId,
    goodId,
    minPrice: Math.max(1, Math.round(anchor * MIN_FACTOR)),
    maxPrice: Math.round(anchor * MAX_FACTOR),
    bids: bids.rows,
    asks: asks.rows,
    trades: trades.rows.map((t) => ({
      price: t.price,
      qty: t.qty,
      buyer: t.buyer,
      seller: t.seller,
      at: new Date(t.created_at).toISOString()
    })),
    myOrders: mine.rows.map((o) => ({
      id: o.id,
      side: o.side,
      price: o.price,
      qtyTotal: o.qty_total,
      qtyLeft: o.qty_left,
      at: new Date(o.created_at).toISOString()
    })),
    storage: storage.rows[0]?.qty || 0
  };
}

async function myOrders(pool, userId) {
  const r = await pool.query(
    `SELECT id, district_id, good_id, side, price, qty_total, qty_left, created_at FROM market_orders
     WHERE user_id=$1 AND status='open' ORDER BY id DESC`,
    [userId]
  );
  return r.rows.map((o) => ({
    id: o.id,
    districtId: o.district_id,
    goodId: o.good_id,
    side: o.side,
    price: o.price,
    qtyTotal: o.qty_total,
    qtyLeft: o.qty_left,
    expiresAt: new Date(new Date(o.created_at).getTime() + ORDER_TTL_HOURS * 3600e3).toISOString()
  }));
}

async function storage(pool, userId) {
  const r = await pool.query(
    "SELECT district_id, good_id, qty, avg_cost FROM player_storage WHERE user_id=$1 AND qty > 0 ORDER BY district_id",
    [userId]
  );
  return r.rows.map((s) => ({ districtId: s.district_id, goodId: s.good_id, qty: s.qty, avgCost: Math.round(s.avg_cost) }));
}

module.exports = { placeOrder, cancelOrder, expireOrders, collect, summary, book, myOrders, storage, MAX_OPEN };
