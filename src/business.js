// İşletmeler ve üretim.
//
// - Bulunduğun semtte işletme satın alırsın (her türden semt başına bir tane, toplam en fazla 4).
// - Üretim işletmeleri ham maddeyi mala çevirir. Çıkan mal o semtteki depona gider.
// - Paravan işletmeler (kahvehane, gece kulübü) mal tüketip kasaya para yazar. Gece kulübü ailene nüfuz da kazandırır.
// - Hammaddeyi işletmeye sen taşırsın (çantandan ya da o semtteki deponda olandan).
// - Kira saatlik ve peşin ödenir. Paran yetmezse üretim durur, para gelince kaldığı yerden devam eder.
// - Üretim tembel hesaplanır: son hesaptan bu yana geçen süre kadar parti üretilir (hammadde yettiği kadar).
// - Kaçak mal üreten işletmelere polis baskını olabilir: hammaddenin yarısına el konur, işletme 30 dk kapanır.
//   Kendi ailenin bölgesinde risk yarıya iner.

const { GameError, lockPlayer, activeTravel, resolveArrivals, cargo } = require("./game");
const { gangOf, addInfluence, addNews } = require("./influence");
const { addStorage } = require("./market");

const ECON = require("./economy");
const MAX_BUSINESSES = ECON.MAX_BUSINESSES;
const SPEED = ECON.BUSINESS_SPEED;
const STOCK_CAP = ECON.STOCK_CAP;
const RAID_CLOSE_MIN = ECON.RAID_CLOSE_MIN;
const TYPES = ECON.BUSINESS_TYPES;

const upgradeCost = (type, level) => Math.round(TYPES[type].cost * level * ECON.UPGRADE_FACTOR);

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
      if ((e.code === "40P01" || e.code === "40001") && attempt < retries) continue;
      throw e;
    } finally {
      client.release();
    }
  }
}

async function stockOf(client, businessId) {
  const r = await client.query("SELECT good_id, qty FROM business_stock WHERE business_id=$1 AND qty > 0", [businessId]);
  return Object.fromEntries(r.rows.map((x) => [x.good_id, x.qty]));
}

// Kira ve üretimi şimdiye kadar hesapla. b ve player satırları kilitli olmalı.
async function settle(client, b, player) {
  const type = TYPES[b.type];
  const recipe = type.recipes.find((r) => r.id === b.recipe_id);
  const now = Date.now();

  // Peşin saatlik kira
  let rentUntil = new Date(b.rent_paid_until).getTime();
  let money = Number(player.money);
  let rentPaid = 0;
  for (let i = 0; i < 72 && rentUntil < now; i++) {
    if (money < type.rent) break;
    money -= type.rent;
    rentPaid += type.rent;
    rentUntil += 3600e3;
  }
  if (rentPaid) {
    await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [b.user_id, rentPaid]);
    player.money = money;
  }
  const unpaid = rentUntil < now;
  const closedUntil = b.closed_until ? new Date(b.closed_until).getTime() : 0;

  let last = new Date(b.last_tick).getTime();
  let batches = 0;
  const stock = await stockOf(client, b.id);

  if (closedUntil > now) {
    last = closedUntil; // baskından sonra kaldığı yerden başlar
  } else if (!recipe) {
    last = now;
  } else {
    const start = Math.max(last, closedUntil);
    const end = Math.min(now, rentUntil);
    const batchMs = (recipe.seconds / SPEED[b.level - 1]) * 1000;
    const possible = end > start ? Math.floor((end - start) / batchMs) : 0;
    let byInput = Infinity;
    for (const [g, need] of Object.entries(recipe.inputs)) byInput = Math.min(byInput, Math.floor((stock[g] || 0) / need));
    batches = Math.max(0, Math.min(possible, byInput));

    if (batches > 0) {
      for (const [g, need] of Object.entries(recipe.inputs)) {
        await client.query("UPDATE business_stock SET qty = qty - $3 WHERE business_id=$1 AND good_id=$2", [
          b.id,
          g,
          need * batches
        ]);
        stock[g] -= need * batches;
      }
      const outEntries = Object.entries(recipe.outputs);
      if (outEntries.length) {
        // Çıkan malın maliyeti: hammaddelerin taban fiyatı
        const bases = await client.query("SELECT id, base_price FROM goods WHERE id = ANY($1)", [Object.keys(recipe.inputs)]);
        const inputValue = bases.rows.reduce((s, r) => s + r.base_price * recipe.inputs[r.id], 0);
        const outUnits = outEntries.reduce((s, [, q]) => s + q, 0);
        for (const [g, q] of outEntries) {
          await addStorage(client, b.user_id, b.district_id, g, q * batches, inputValue / outUnits);
        }
      }
      if (recipe.cash) await client.query("UPDATE businesses SET till = till + $2 WHERE id=$1", [b.id, recipe.cash * batches]);
      if (recipe.influence) {
        const g = await gangOf(client, b.user_id);
        if (g) await addInfluence(client, g.id, b.district_id, recipe.influence * batches, b.user_id);
      }
    }
    // Hammadde ya da kira bittiyse süre birikmez; yoksa yarım kalan parti korunur
    last = batches === possible && !unpaid ? start + batches * batchMs : now;
  }

  await client.query(
    `UPDATE businesses SET last_tick=$2, rent_paid_until=$3, produced_total = produced_total + $4 WHERE id=$1`,
    [b.id, new Date(last), new Date(rentUntil), batches]
  );
  b.last_tick = new Date(last);
  b.rent_paid_until = new Date(rentUntil);
  return { batches, rentPaid, stock };
}

function describe(b, stock, now = Date.now()) {
  const type = TYPES[b.type];
  const recipe = type.recipes.find((r) => r.id === b.recipe_id) || null;
  const closedUntil = b.closed_until && new Date(b.closed_until).getTime() > now ? new Date(b.closed_until) : null;
  const rentUntil = new Date(b.rent_paid_until).getTime();
  const batchMs = recipe ? (recipe.seconds / SPEED[b.level - 1]) * 1000 : 0;
  let status = "producing";
  if (closedUntil) status = "raided";
  else if (rentUntil < now) status = "unpaid";
  else if (!recipe) status = "idle";
  else if (Object.entries(recipe.inputs).some(([g, need]) => (stock[g] || 0) < need)) status = "starved";
  const last = new Date(b.last_tick).getTime();
  const progress = status === "producing" ? Math.min(1, (now - last) / batchMs) : 0;
  const stockTotal = Object.values(stock).reduce((s, q) => s + q, 0);
  let batchesLeft = null;
  if (recipe) {
    batchesLeft = Infinity;
    for (const [g, need] of Object.entries(recipe.inputs)) batchesLeft = Math.min(batchesLeft, Math.floor((stock[g] || 0) / need));
  }
  return {
    id: b.id,
    type: b.type,
    name: type.name,
    kind: type.kind,
    districtId: b.district_id,
    level: b.level,
    maxLevel: SPEED.length,
    speed: SPEED[b.level - 1],
    upgradeCost: b.level < SPEED.length ? upgradeCost(b.type, b.level) : null,
    rent: type.rent,
    rentPaidUntil: new Date(rentUntil).toISOString(),
    recipeId: b.recipe_id,
    batchSeconds: recipe ? Math.round(batchMs / 1000) : null,
    status,
    progress,
    nextBatchAt: status === "producing" ? new Date(last + batchMs).toISOString() : null,
    closedUntil: closedUntil ? closedUntil.toISOString() : null,
    stock,
    stockTotal,
    stockCap: STOCK_CAP[b.level - 1],
    batchesLeft,
    till: Number(b.till),
    producedTotal: b.produced_total,
    sellValue: Math.round((type.cost + Array.from({ length: b.level - 1 }, (_, i) => upgradeCost(b.type, i + 1)).reduce((s, x) => s + x, 0)) * 0.5)
  };
}

async function lockBusiness(client, userId, id) {
  const r = await client.query("SELECT * FROM businesses WHERE id=$1 AND user_id=$2 FOR UPDATE", [Number(id), userId]);
  if (!r.rows.length) throw new GameError("İşletme bulunamadı", 404);
  return r.rows[0];
}

// ====== OKUMA ======
function types() {
  return Object.entries(TYPES).map(([id, t]) => ({
    id,
    name: t.name,
    kind: t.kind,
    desc: t.desc,
    cost: t.cost,
    rent: t.rent,
    districts: t.districts,
    recipes: t.recipes.map((r) => ({
      id: r.id,
      name: r.name,
      inputs: r.inputs,
      outputs: r.outputs,
      cash: r.cash || 0,
      influence: r.influence || 0,
      seconds: r.seconds
    }))
  }));
}

async function list(pool, userId) {
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const r = await client.query("SELECT * FROM businesses WHERE user_id=$1 ORDER BY id FOR UPDATE", [userId]);
    const out = [];
    for (const b of r.rows) {
      const { stock } = await settle(client, b, player);
      const fresh = (await client.query("SELECT * FROM businesses WHERE id=$1", [b.id])).rows[0];
      out.push(describe(fresh, stock));
    }
    return out;
  });
}

// ====== EYLEMLER ======
async function buy(pool, userId, typeId) {
  const type = TYPES[typeId];
  if (!type) throw new GameError("Geçersiz işletme türü");
  return tx(pool, async (client) => {
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken işletme alamazsın");
    if (!type.districts.includes(player.district_id)) throw new GameError(`${type.name} bu semtte açılamaz`);
    const count = await client.query("SELECT COUNT(*)::int AS n FROM businesses WHERE user_id=$1", [userId]);
    if (count.rows[0].n >= MAX_BUSINESSES) throw new GameError(`En fazla ${MAX_BUSINESSES} işletmen olabilir`);
    const dup = await client.query("SELECT 1 FROM businesses WHERE user_id=$1 AND district_id=$2 AND type=$3", [
      userId,
      player.district_id,
      typeId
    ]);
    if (dup.rows.length) throw new GameError("Bu semtte zaten böyle bir işletmen var");
    if (Number(player.money) < type.cost + type.rent) throw new GameError(`Gereken: ₺${(type.cost + type.rent).toLocaleString("tr-TR")} (ilk saat kira dahil)`);
    await client.query("UPDATE players SET money = money - $2, xp = xp + 25 WHERE user_id=$1", [userId, type.cost + type.rent]);
    const r = await client.query(
      `INSERT INTO businesses (user_id, district_id, type, recipe_id, rent_paid_until)
       VALUES ($1,$2,$3,$4, now() + interval '1 hour') RETURNING id`,
      [userId, player.district_id, typeId, type.recipes[0].id]
    );
    const d = (await client.query("SELECT name FROM districts WHERE id=$1", [player.district_id])).rows[0];
    const u = (await client.query("SELECT username FROM users WHERE id=$1", [userId])).rows[0];
    if (typeId === "gece_kulubu") await addNews(client, `${d.name}'da yeni bir gece kulübü açıldı. Sahibi: ${u.username}`, "info");
    return { id: r.rows[0].id };
  });
}

async function setRecipe(pool, userId, id, recipeId) {
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const b = await lockBusiness(client, userId, id);
    if (!TYPES[b.type].recipes.some((r) => r.id === recipeId)) throw new GameError("Bu işletme bunu üretemez");
    await settle(client, b, player);
    // Tarif değişince yarım kalan parti sıfırlanır
    await client.query("UPDATE businesses SET recipe_id=$2, last_tick=GREATEST(now(), last_tick) WHERE id=$1", [b.id, recipeId]);
    return { ok: true };
  });
}

// Hammaddeyi işletmeye yükle: önce çanta, sonra o semtteki depo
async function load(pool, userId, id, { goodId, qty }) {
  qty = Math.floor(Number(qty));
  if (!Number.isFinite(qty) || qty < 1) throw new GameError("Geçersiz miktar");
  return tx(pool, async (client) => {
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    const b = await lockBusiness(client, userId, id);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken mal taşıyamazsın");
    if (player.district_id !== b.district_id) throw new GameError("Mal yüklemek için işletmenin semtinde olmalısın");
    const type = TYPES[b.type];
    if (!type.recipes.some((r) => goodId in r.inputs)) throw new GameError("Bu işletme bu malı kullanmıyor");
    const { stock } = await settle(client, b, player);
    const total = Object.values(stock).reduce((s, q) => s + q, 0);
    const room = STOCK_CAP[b.level - 1] - total;
    if (room <= 0) throw new GameError("İşletmenin ambarı dolu");
    qty = Math.min(qty, room);

    const inv = await client.query("SELECT qty FROM player_goods WHERE user_id=$1 AND good_id=$2 FOR UPDATE", [userId, goodId]);
    const st = await client.query(
      "SELECT qty FROM player_storage WHERE user_id=$1 AND district_id=$2 AND good_id=$3 FOR UPDATE",
      [userId, b.district_id, goodId]
    );
    const invQty = inv.rows[0]?.qty || 0;
    const stQty = st.rows[0]?.qty || 0;
    qty = Math.min(qty, invQty + stQty);
    if (qty <= 0) throw new GameError("Çantanda ya da bu semtteki deponda bu mal yok");
    const fromInv = Math.min(invQty, qty);
    if (fromInv) await client.query("UPDATE player_goods SET qty = qty - $3 WHERE user_id=$1 AND good_id=$2", [userId, goodId, fromInv]);
    if (qty - fromInv)
      await client.query("UPDATE player_storage SET qty = qty - $4 WHERE user_id=$1 AND district_id=$2 AND good_id=$3", [
        userId,
        b.district_id,
        goodId,
        qty - fromInv
      ]);
    await client.query(
      `INSERT INTO business_stock (business_id, good_id, qty) VALUES ($1,$2,$3)
       ON CONFLICT (business_id, good_id) DO UPDATE SET qty = business_stock.qty + $3`,
      [b.id, goodId, qty]
    );
    // Hammadde beklerken geçen süre birikmesin: üretim yüklendiği andan başlar
    const recipe = type.recipes.find((r) => r.id === b.recipe_id);
    const wasStarved = recipe && Object.entries(recipe.inputs).some(([g, need]) => (stock[g] || 0) < need);
    if (wasStarved) await client.query("UPDATE businesses SET last_tick = GREATEST(now(), last_tick) WHERE id=$1", [b.id]);
    return { loaded: qty };
  });
}

async function collectTill(pool, userId, id) {
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const b = await lockBusiness(client, userId, id);
    await settle(client, b, player);
    const amount = Number((await client.query("SELECT till FROM businesses WHERE id=$1", [b.id])).rows[0].till);
    if (amount <= 0) throw new GameError("Kasada para yok");
    await client.query("UPDATE businesses SET till = 0 WHERE id=$1", [b.id]);
    await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [userId, amount]);
    return { collected: amount };
  });
}

async function upgrade(pool, userId, id) {
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const b = await lockBusiness(client, userId, id);
    if (b.level >= SPEED.length) throw new GameError("İşletme zaten en üst seviyede");
    await settle(client, b, player);
    const cost = upgradeCost(b.type, b.level);
    if (Number(player.money) < cost) throw new GameError(`Yükseltme için ₺${cost.toLocaleString("tr-TR")} gerekiyor`);
    await client.query("UPDATE players SET money = money - $2, xp = xp + 15 WHERE user_id=$1", [userId, cost]);
    await client.query("UPDATE businesses SET level = level + 1 WHERE id=$1", [b.id]);
    return { level: b.level + 1 };
  });
}

// İşletmeyi sat: yatırımın yarısı, kasa ve ambardaki mal geri gelir (mal o semtteki depoya)
async function sell(pool, userId, id) {
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const b = await lockBusiness(client, userId, id);
    const { stock } = await settle(client, b, player);
    const fresh = (await client.query("SELECT * FROM businesses WHERE id=$1", [b.id])).rows[0];
    const info = describe(fresh, stock);
    for (const [g, q] of Object.entries(stock)) if (q > 0) await addStorage(client, userId, b.district_id, g, q, 0);
    await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [userId, info.sellValue + info.till]);
    await client.query("DELETE FROM businesses WHERE id=$1", [b.id]);
    return { received: info.sellValue + info.till };
  });
}

// ====== TICK: tüm işletmeleri hesapla, baskın zarı at ======
async function tickAll(pool, minutes = 1) {
  const ids = await pool.query("SELECT id, user_id FROM businesses ORDER BY user_id, id");
  const raids = [];
  for (const row of ids.rows) {
    try {
      await tx(pool, async (client) => {
        const player = await lockPlayer(client, row.user_id);
        const b = (await client.query("SELECT * FROM businesses WHERE id=$1 FOR UPDATE", [row.id])).rows[0];
        if (!b) return;
        const { batches, stock } = await settle(client, b, player);
        const type = TYPES[b.type];
        const recipe = type.recipes.find((r) => r.id === b.recipe_id);
        if (!recipe || type.kind !== "production") return;
        const fresh = (await client.query("SELECT * FROM businesses WHERE id=$1", [b.id])).rows[0];
        if (describe(fresh, stock).status !== "producing" && batches === 0) return;

        // Kaçak mal üretimi (çıkan malın ısısı) baskın riski taşır
        const heat = await client.query("SELECT COALESCE(MAX(heat),0) AS h FROM goods WHERE id = ANY($1)", [Object.keys(recipe.outputs)]);
        if (heat.rows[0].h <= 0) return;
        const d = (await client.query("SELECT * FROM districts WHERE id=$1", [b.district_id])).rows[0];
        const g = await gangOf(client, b.user_id);
        const ownTurf = g && d.controller_gang_id === g.id;
        // Saatte yaklaşık polis × 0.25 baskın
        const p = (d.police * 0.25 * (ownTurf ? 0.5 : 1) * minutes) / 60;
        if (Math.random() >= p) return;

        const seized = [];
        for (const [gid, q] of Object.entries(stock)) {
          const take = Math.ceil(q / 2);
          if (take > 0) {
            await client.query("UPDATE business_stock SET qty = qty - $3 WHERE business_id=$1 AND good_id=$2", [b.id, gid, take]);
            seized.push({ goodId: gid, qty: take });
          }
        }
        await client.query("UPDATE businesses SET closed_until = now() + make_interval(mins => $2) WHERE id=$1", [
          b.id,
          RAID_CLOSE_MIN
        ]);
        await addNews(client, `Polis ${d.name}'daki bir ${type.name.toLocaleLowerCase("tr-TR")} baskın yaptı!`, "crime");
        raids.push({ userId: b.user_id, businessId: b.id, name: type.name, districtId: b.district_id, seized });
      });
    } catch (e) {
      console.error("business tick:", e.message);
    }
  }
  return raids;
}

module.exports = { types, list, buy, setRecipe, load, collectTill, upgrade, sell, tickAll, TYPES };
