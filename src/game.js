const { gangOf, addInfluence } = require("./influence");
const ECON = require("./economy");

// Oyun kuralları: enerji, fiyatlar, ticaret, yolculuk.
// Para ve envanteri değiştiren her işlem bir transaction içinde, ilgili satırlar
// FOR UPDATE ile kilitlenerek yapılır. Böylece aynı anda gelen istekler para kopyalayamaz.

const ENERGY_MAX = 100;
const ENERGY_REGEN_SECONDS = 360; // 6 dakikada 1 enerji, saatte 10
const TRAVEL_ENERGY = 10;
const TRAVEL_SECONDS_PER_UNIT = Number(process.env.TRAVEL_SECONDS_PER_UNIT || 120);
const TRAVEL_MIN_SECONDS = 15;
const NPC_SPREAD = ECON.NPC_SPREAD;
const PRICE_MIN_FACTOR = 0.4;
const PRICE_MAX_FACTOR = 2.5;

class GameError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function energyNow(player, now = Date.now()) {
  const elapsed = (now - new Date(player.energy_updated_at).getTime()) / 1000;
  const gained = Math.floor(elapsed / ENERGY_REGEN_SECONDS);
  return Math.min(ENERGY_MAX, player.energy + Math.max(0, gained));
}

// Enerjiyi harcar. Yenilenme zamanlayıcısının artan kısmını kaybetmemek için
// energy_updated_at, tam olarak "kazanılan" süre kadar ileri alınır.
async function spendEnergy(client, player, amount) {
  const now = Date.now();
  const current = energyNow(player, now);
  if (current < amount) throw new GameError("Yeterli enerjin yok");
  let updatedAt;
  if (current >= ENERGY_MAX) {
    updatedAt = new Date(now);
  } else {
    const gained = current - player.energy;
    updatedAt = new Date(new Date(player.energy_updated_at).getTime() + gained * ENERGY_REGEN_SECONDS * 1000);
  }
  await client.query("UPDATE players SET energy=$1, energy_updated_at=$2 WHERE user_id=$3", [
    current - amount,
    updatedAt,
    player.user_id
  ]);
}

function npcBuyPrice(price) {
  return round2(price * (1 + NPC_SPREAD));
}
function npcSellPrice(price) {
  return round2(price * (1 - NPC_SPREAD));
}

async function lockPlayer(client, userId) {
  const r = await client.query("SELECT * FROM players WHERE user_id=$1 FOR UPDATE", [userId]);
  if (!r.rows.length) throw new GameError("Oyuncu bulunamadı", 404);
  return r.rows[0];
}

async function activeTravel(client, userId) {
  const r = await client.query(
    "SELECT * FROM travels WHERE user_id=$1 AND resolved=false ORDER BY id DESC LIMIT 1",
    [userId]
  );
  return r.rows[0] || null;
}

async function cargo(client, userId) {
  const r = await client.query(
    `SELECT pg.good_id, pg.qty, pg.avg_cost, g.weight, g.heat, g.name
     FROM player_goods pg JOIN goods g ON g.id = pg.good_id
     WHERE pg.user_id=$1 AND pg.qty > 0`,
    [userId]
  );
  return r.rows;
}

function cargoWeight(rows) {
  return rows.reduce((s, r) => s + r.qty * r.weight, 0);
}

// ====== TİCARET ======
async function trade(pool, userId, { goodId, qty, side }) {
  qty = Math.floor(Number(qty));
  if (!Number.isFinite(qty) || qty <= 0 || qty > 1000) throw new GameError("Geçersiz miktar");
  if (side !== "buy" && side !== "sell") throw new GameError("Geçersiz işlem");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken ticaret yapamazsın");

    const dg = await client.query(
      `SELECT dg.*, g.weight, g.name, d.tax, d.controller_gang_id FROM district_goods dg
       JOIN goods g ON g.id = dg.good_id JOIN districts d ON d.id = dg.district_id
       WHERE dg.district_id=$1 AND dg.good_id=$2 FOR UPDATE OF dg`,
      [player.district_id, goodId]
    );
    if (!dg.rows.length) throw new GameError("Bu mal burada satılmıyor");
    const market = dg.rows[0];

    // Ortalama fiyat: işlem fiyatı, kaydırmanın yarısı kadar etkilenir.
    const impact = ECON.impactPerUnit({ id: goodId }) * qty;
    let unit, newPrice;
    if (side === "buy") {
      unit = npcBuyPrice(market.price * (1 + impact / 2));
      newPrice = Math.min(market.anchor * PRICE_MAX_FACTOR, market.price * (1 + impact));
    } else {
      unit = npcSellPrice(market.price * (1 - impact / 2));
      newPrice = Math.max(market.anchor * PRICE_MIN_FACTOR, market.price * (1 - impact));
    }
    const gross = unit * qty;

    const held = await client.query(
      "SELECT qty, avg_cost FROM player_goods WHERE user_id=$1 AND good_id=$2 FOR UPDATE",
      [userId, goodId]
    );
    const have = held.rows[0] || { qty: 0, avg_cost: 0 };

    const gang = await gangOf(client, userId);
    const ownTurf = gang && market.controller_gang_id === gang.id;

    let moneyDelta, tax = 0;
    if (side === "buy") {
      const total = Math.ceil(gross);
      if (Number(player.money) < total) throw new GameError("Yeterli paran yok");
      const rows = await cargo(client, userId);
      if (cargoWeight(rows) + market.weight * qty > player.capacity)
        throw new GameError("Taşıma kapasiten dolu");
      moneyDelta = -total;
      const newQty = have.qty + qty;
      const newAvg = (have.qty * have.avg_cost + total) / newQty;
      await client.query(
        `INSERT INTO player_goods (user_id, good_id, qty, avg_cost) VALUES ($1,$2,$3,$4)
         ON CONFLICT (user_id, good_id) DO UPDATE SET qty=$3, avg_cost=$4`,
        [userId, goodId, newQty, newAvg]
      );
    } else {
      if (have.qty < qty) throw new GameError("Elinde o kadar mal yok");
      // Kendi bölgende vergi yarı yarıya. Bölgeyi tutan çete verginin yarısını kasaya alır.
      tax = Math.ceil(gross * market.tax * (ownTurf ? 0.5 : 1));
      moneyDelta = Math.floor(gross) - tax;
      if (market.controller_gang_id) {
        await client.query("UPDATE gangs SET bank = bank + $2 WHERE id=$1", [
          market.controller_gang_id,
          Math.floor(tax * 0.5)
        ]);
      }
      await client.query("UPDATE player_goods SET qty=qty-$3 WHERE user_id=$1 AND good_id=$2", [
        userId,
        goodId,
        qty
      ]);
    }

    const updated = await client.query(
      "UPDATE players SET money = money + $1, xp = xp + $3 WHERE user_id=$2 RETURNING money",
      [moneyDelta, userId, Math.max(1, Math.floor(qty / 5))]
    );
    // Çete üyelerinin ticareti bölgede nüfuz kazandırır (her ₺100 için 1 puan)
    if (gang) await addInfluence(client, gang.id, player.district_id, Math.floor(gross / 100), userId);

    await client.query("UPDATE district_goods SET price=$1 WHERE district_id=$2 AND good_id=$3", [
      newPrice,
      player.district_id,
      goodId
    ]);
    await client.query(
      "INSERT INTO trades (user_id, district_id, good_id, side, qty, price) VALUES ($1,$2,$3,$4,$5,$6)",
      [userId, player.district_id, goodId, side, qty, unit]
    );
    await client.query("COMMIT");

    return {
      side,
      goodId,
      qty,
      unitPrice: unit,
      total: Math.abs(moneyDelta),
      tax,
      money: Number(updated.rows[0].money),
      districtId: player.district_id,
      newPrice: round2(newPrice)
    };
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

// ====== YOLCULUK ======
function travelSeconds(from, to) {
  const dist = Math.hypot(from.x - to.x, from.y - to.y);
  return Math.max(TRAVEL_MIN_SECONDS, Math.round(dist * TRAVEL_SECONDS_PER_UNIT));
}

// Yolculuğun sonucu yola çıkarken belirlenir, varışta uygulanır.
// Kendi çetenin bölgesinde polis riski yarıya iner, soygun olmaz.
function rollEvent(dest, origin, rows, money, gangId = null) {
  const ownTurf = gangId && dest.controller_gang_id === gangId;
  const hotness = rows.reduce((s, r) => s + r.qty * r.heat, 0);
  const pPolice = Math.min(0.85, dest.police * (ownTurf ? 0.5 : 1) * (hotness / ECON.HEAT_DIVISOR));
  if (hotness > 0 && Math.random() < pPolice) {
    const seized = rows
      .filter((r) => r.heat > 0)
      .map((r) => ({ goodId: r.good_id, name: r.name, qty: Math.ceil(r.qty * 0.5) }));
    return { type: "police", seized };
  }
  const roughArea = dest.id === "gecekondu" || origin.id === "gecekondu";
  if (roughArea && !ownTurf && money > 500 && Math.random() < 0.2) {
    return { type: "robbery", lost: Math.floor(money * 0.15) };
  }
  if (Math.random() < 0.08) {
    return { type: "tip", found: 100 + Math.floor(Math.random() * 400) };
  }
  return { type: "safe" };
}

async function startTravel(pool, userId, toId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Zaten yoldasın");
    if (player.district_id === toId) throw new GameError("Zaten buradasın");

    const ds = await client.query("SELECT * FROM districts WHERE id = ANY($1)", [[player.district_id, toId]]);
    const from = ds.rows.find((d) => d.id === player.district_id);
    const to = ds.rows.find((d) => d.id === toId);
    if (!to) throw new GameError("Böyle bir semt yok");

    await spendEnergy(client, player, TRAVEL_ENERGY);
    const seconds = travelSeconds(from, to);
    const rows = await cargo(client, userId);
    const gang = await gangOf(client, userId);
    const event = rollEvent(to, from, rows, Number(player.money), gang?.id);

    const t = await client.query(
      `INSERT INTO travels (user_id, from_id, to_id, arrive_at, event)
       VALUES ($1,$2,$3, now() + make_interval(secs => $4), $5)
       RETURNING id, from_id, to_id, depart_at, arrive_at`,
      [userId, from.id, to.id, seconds, event]
    );
    await client.query("COMMIT");
    return formatTravel(t.rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

function formatTravel(t) {
  return {
    id: t.id,
    from: t.from_id,
    to: t.to_id,
    departAt: new Date(t.depart_at).toISOString(),
    arriveAt: new Date(t.arrive_at).toISOString()
  };
}

// Varış zamanı geçmiş yolculukları sonuçlandırır. userId verilmezse herkesi işler.
async function resolveArrivals(client, userId = null) {
  const due = await client.query(
    `SELECT * FROM travels WHERE resolved=false AND arrive_at <= now()
     ${userId ? "AND user_id=$1" : ""} ORDER BY id FOR UPDATE SKIP LOCKED`,
    userId ? [userId] : []
  );
  const results = [];
  for (const t of due.rows) {
    const ev = t.event || { type: "safe" };
    const applied = { ...ev };
    if (ev.type === "police") {
      applied.seized = [];
      for (const s of ev.seized) {
        const r = await client.query(
          `UPDATE player_goods SET qty = GREATEST(0, qty - $3) WHERE user_id=$1 AND good_id=$2
           RETURNING qty`,
          [t.user_id, s.goodId, s.qty]
        );
        if (r.rows.length) applied.seized.push(s);
      }
    } else if (ev.type === "robbery") {
      const r = await client.query(
        "UPDATE players SET money = GREATEST(0, money - $2) WHERE user_id=$1 RETURNING money",
        [t.user_id, ev.lost]
      );
      applied.money = Number(r.rows[0]?.money ?? 0);
    } else if (ev.type === "tip") {
      await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [t.user_id, ev.found]);
    }
    await client.query("UPDATE players SET district_id=$2, xp = xp + 5 WHERE user_id=$1", [t.user_id, t.to_id]);
    await client.query("UPDATE travels SET resolved=true, event=$2 WHERE id=$1", [t.id, { ...applied, seen: false }]);
    results.push({ userId: t.user_id, travelId: t.id, to: t.to_id, event: applied });
  }
  return results;
}

// ====== OYUNCU DURUMU ======
async function getState(pool, userId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await resolveArrivals(client, userId);
    const p = await client.query(
      `SELECT u.username, p.* FROM players p JOIN users u ON u.id = p.user_id WHERE p.user_id=$1`,
      [userId]
    );
    if (!p.rows.length) throw new GameError("Profil bulunamadı", 404);
    const player = p.rows[0];
    const rows = await cargo(client, userId);
    const travel = await activeTravel(client, userId);
    const gang = await gangOf(client, userId);

    // Görülmemiş son yolculuk olayı (bir kez gösterilir)
    const last = await client.query(
      `SELECT id, to_id, event FROM travels WHERE user_id=$1 AND resolved=true
       AND (event->>'seen')::boolean = false ORDER BY id DESC LIMIT 1`,
      [userId]
    );
    let lastEvent = null;
    if (last.rows.length) {
      const { seen, ...ev } = last.rows[0].event;
      lastEvent = { ...ev, to: last.rows[0].to_id };
      await client.query(
        `UPDATE travels SET event = jsonb_set(event, '{seen}', 'true') WHERE user_id=$1 AND resolved=true`,
        [userId]
      );
    }
    // Görülmemiş soyulma olayı (bir kez gösterilir)
    const rob = await client.query(
      `UPDATE robberies SET seen=true WHERE id = (
         SELECT id FROM robberies WHERE target_id=$1 AND seen=false ORDER BY id DESC LIMIT 1)
       RETURNING id, success, cash, goods, district_id,
         (SELECT username FROM users WHERE id = attacker_id) AS attacker`,
      [userId]
    );
    await client.query("UPDATE robberies SET seen=true WHERE target_id=$1 AND seen=false", [userId]);
    const robbed = rob.rows[0]
      ? {
          attacker: rob.rows[0].attacker,
          success: rob.rows[0].success,
          cash: Number(rob.rows[0].cash),
          goods: rob.rows[0].goods || [],
          districtId: rob.rows[0].district_id
        }
      : null;
    await client.query("COMMIT");

    const level = 1 + Math.floor(Math.sqrt(player.xp / 50));
    return {
      username: player.username,
      protectedUntil:
        new Date(player.protected_until) > new Date() ? new Date(player.protected_until).toISOString() : null,
      robbed,
      money: Number(player.money),
      xp: player.xp,
      level,
      energy: energyNow(player),
      energyMax: ENERGY_MAX,
      energyRegenSeconds: ENERGY_REGEN_SECONDS,
      districtId: player.district_id,
      capacity: player.capacity,
      load: cargoWeight(rows),
      heat: rows.reduce((s, r) => s + r.qty * r.heat, 0),
      inventory: rows.map((r) => ({
        goodId: r.good_id,
        qty: r.qty,
        avgCost: round2(r.avg_cost)
      })),
      travel: travel ? formatTravel(travel) : null,
      gang: gang
        ? { id: gang.id, name: gang.name, tag: gang.tag, color: gang.color, emblem: gang.emblem, rank: gang.rank, bank: Number(gang.bank) }
        : null,
      lastEvent
    };
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

async function getWorld(pool) {
  const [d, g] = await Promise.all([
    pool.query("SELECT * FROM districts ORDER BY id"),
    pool.query("SELECT * FROM goods ORDER BY base_price")
  ]);
  return {
    districts: d.rows.map((r) => ({
      id: r.id,
      name: r.name,
      police: r.police,
      tax: r.tax,
      x: r.x,
      y: r.y,
      color: r.color,
      description: r.description
    })),
    goods: g.rows.map((r) => ({
      id: r.id,
      name: r.name,
      basePrice: r.base_price,
      weight: r.weight,
      heat: r.heat,
      icon: r.icon
    })),
    travelEnergy: TRAVEL_ENERGY,
    npcSpread: NPC_SPREAD
  };
}

async function getPrices(pool) {
  const r = await pool.query("SELECT district_id, good_id, price, anchor FROM district_goods");
  const out = {};
  for (const row of r.rows) {
    (out[row.district_id] ||= {})[row.good_id] = {
      buy: npcBuyPrice(row.price),
      sell: npcSellPrice(row.price),
      anchor: round2(row.anchor)
    };
  }
  return out;
}

async function leaderboard(pool) {
  const r = await pool.query(`
    SELECT u.username, p.money, p.xp,
      p.money
      + COALESCE((SELECT SUM(pg.qty * g.base_price) FROM player_goods pg JOIN goods g ON g.id=pg.good_id
                  WHERE pg.user_id=p.user_id), 0)
      + COALESCE((SELECT SUM(s.qty * g.base_price) FROM player_storage s JOIN goods g ON g.id=s.good_id
                  WHERE s.user_id=p.user_id), 0)
      + COALESCE((SELECT SUM(CASE WHEN o.side='buy' THEN o.escrow ELSE o.qty_left * g.base_price END)
                  FROM market_orders o JOIN goods g ON g.id=o.good_id
                  WHERE o.user_id=p.user_id AND o.status='open'), 0) AS net_worth
    FROM players p JOIN users u ON u.id = p.user_id
    ORDER BY net_worth DESC LIMIT 20`);
  return r.rows.map((x, i) => ({
    rank: i + 1,
    username: x.username,
    netWorth: Number(x.net_worth),
    level: 1 + Math.floor(Math.sqrt(x.xp / 50))
  }));
}

// Fiyatlar zamanla çapa değerine döner, üstüne küçük bir dalgalanma eklenir.
async function tickPrices(pool) {
  await pool.query(`
    UPDATE district_goods SET price = LEAST(anchor * ${PRICE_MAX_FACTOR}, GREATEST(anchor * ${PRICE_MIN_FACTOR},
      price + (anchor - price) * ${ECON.PRICE_REVERT} + anchor * (random() - 0.5) * ${ECON.PRICE_NOISE}))`);
}

module.exports = {
  GameError,
  cargo,
  cargoWeight,
  lockPlayer,
  activeTravel,
  spendEnergy,
  energyNow,
  trade,
  startTravel,
  resolveArrivals,
  getState,
  getWorld,
  getPrices,
  leaderboard,
  tickPrices,
  ENERGY_MAX
};
