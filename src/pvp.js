// Oyuncular arası soygun (PvP).
//
// Kurallar:
//  - Sadece aynı semtteki, yolda olmayan oyuncular soyulabilir. Aynı aileden kimse soyulamaz.
//  - Soygun 20 enerji ister.
//  - Yeni oyuncular ilk 2 saat korumadadır. Soyulan oyuncu 30 dakika korumaya girer.
//    Soygun yapan oyuncunun kendi koruması hemen biter.
//  - Başarı şansı: %50 + seviye farkı başına %5
//      hedefin ailesi semti tutuyorsa -%15, senin ailen tutuyorsa +%10
//      son 24 saatte seni soyan kişiye intikam: +%15
//    En az %15, en fazla %85.
//  - Önce polis riski var (semtin polis oranı × 0.3). Yakalanırsan ceza ödersin ve soygun olmaz.
//  - Başarılı soygun: hedefin parasının %10-20'si (üst sınır 2000 + 400 × hedef seviyesi)
//    ve rastgele bir malının %25'i (çantanda yer varsa). Aileler farklıysa +15 nüfuz.
//  - Başarısız soygun: hedef kaçar ve deneyim kazanır.

const { GameError, lockPlayer, activeTravel, spendEnergy, resolveArrivals, cargo, cargoWeight } = require("./game");
const { gangOf, addInfluence, addNews } = require("./influence");

const ECON = require("./economy");
const ROB_ENERGY = ECON.ROB_ENERGY;
const VICTIM_PROTECT_MIN = 30;
const REVENGE_HOURS = 24;

const levelOf = (xp) => 1 + Math.floor(Math.sqrt(xp / 50));

async function tx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

function odds({ attackerLevel, targetLevel, controllerId, attackerGangId, targetGangId, revenge }) {
  let p = 0.5 + (attackerLevel - targetLevel) * 0.05;
  if (controllerId && controllerId === targetGangId) p -= 0.15;
  if (controllerId && controllerId === attackerGangId) p += 0.1;
  if (revenge) p += 0.15;
  return Math.min(0.85, Math.max(0.15, p));
}

function wealthTier(money) {
  if (money >= 20000) return "rich";
  if (money >= 4000) return "comfortable";
  return "poor";
}

async function revengeTargets(client, userId) {
  const r = await client.query(
    `SELECT DISTINCT r.attacker_id FROM robberies r
     WHERE r.target_id=$1 AND r.success=true AND r.created_at > now() - make_interval(hours => $2)
       -- intikam bir kez alınır: sonrasında o kişiyi başarıyla soyduysan bonus biter
       AND NOT EXISTS (
         SELECT 1 FROM robberies x WHERE x.attacker_id=$1 AND x.target_id=r.attacker_id
           AND x.success=true AND x.created_at > r.created_at)`,
    [userId, REVENGE_HOURS]
  );
  return new Set(r.rows.map((x) => x.attacker_id));
}

// Bulunduğun semtteki diğer oyuncular
async function street(pool, userId, onlineIds = new Set()) {
  return tx(pool, async (client) => {
    await resolveArrivals(client);
    const me = (await client.query("SELECT * FROM players WHERE user_id=$1", [userId])).rows[0];
    if (!me) throw new GameError("Oyuncu bulunamadı", 404);
    const myGang = await gangOf(client, userId);
    const d = (await client.query("SELECT * FROM districts WHERE id=$1", [me.district_id])).rows[0];
    const revenge = await revengeTargets(client, userId);
    const traveling = !!(await activeTravel(client, userId));

    const r = await client.query(
      `SELECT p.user_id, u.username, p.xp, p.money, p.protected_until,
              g.id AS gang_id, g.name AS gang_name, g.tag, g.color, g.emblem
       FROM players p JOIN users u ON u.id = p.user_id
       LEFT JOIN gang_members m ON m.user_id = p.user_id
       LEFT JOIN gangs g ON g.id = m.gang_id
       WHERE p.district_id = $1 AND p.user_id <> $2
         AND NOT EXISTS (SELECT 1 FROM travels t WHERE t.user_id = p.user_id AND t.resolved = false)
       ORDER BY p.xp DESC LIMIT 40`,
      [me.district_id, userId]
    );

    const now = new Date();
    const people = r.rows.map((x) => {
      const sameGang = myGang && x.gang_id === myGang.id;
      const protectedUntil = new Date(x.protected_until) > now ? new Date(x.protected_until).toISOString() : null;
      const isRevenge = revenge.has(x.user_id);
      return {
        userId: x.user_id,
        username: x.username,
        level: levelOf(x.xp),
        online: onlineIds.has(x.user_id),
        wealth: wealthTier(Number(x.money)),
        gang: x.gang_id ? { id: x.gang_id, name: x.gang_name, tag: x.tag, color: x.color, emblem: x.emblem } : null,
        ally: !!sameGang,
        protectedUntil,
        revenge: isRevenge,
        odds: Math.round(
          odds({
            attackerLevel: levelOf(me.xp),
            targetLevel: levelOf(x.xp),
            controllerId: d.controller_gang_id,
            attackerGangId: myGang?.id,
            targetGangId: x.gang_id,
            revenge: isRevenge
          }) * 100
        )
      };
    });
    // Önce intikam hedefleri, sonra soyulabilenler, sonra korumadakiler ve aile üyeleri
    const score = (p) => (p.revenge ? 0 : 1) + (p.protectedUntil ? 2 : 0) + (p.ally ? 4 : 0);
    people.sort((a, b) => score(a) - score(b) || (b.online ? 1 : 0) - (a.online ? 1 : 0));

    return {
      districtId: me.district_id,
      traveling,
      robEnergy: ROB_ENERGY,
      policeRisk: Math.round(d.police * 30),
      people
    };
  });
}

async function rob(pool, userId, targetId) {
  targetId = Number(targetId);
  if (!Number.isInteger(targetId)) throw new GameError("Geçersiz hedef");
  if (targetId === userId) throw new GameError("Kendini soyamazsın");

  return tx(pool, async (client) => {
    await resolveArrivals(client);
    // Kilitlenme olmasın diye iki oyuncuyu hep aynı sırada kilitle
    const locked = await client.query(
      "SELECT * FROM players WHERE user_id = ANY($1) ORDER BY user_id FOR UPDATE",
      [[userId, targetId]]
    );
    const me = locked.rows.find((p) => p.user_id === userId);
    const target = locked.rows.find((p) => p.user_id === targetId);
    if (!me) throw new GameError("Oyuncu bulunamadı", 404);
    if (!target) throw new GameError("Hedef bulunamadı", 404);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken soygun yapamazsın");
    if (await activeTravel(client, targetId)) throw new GameError("Hedef yolda, yakalayamazsın");
    if (me.district_id !== target.district_id) throw new GameError("Hedef artık bu semtte değil");
    if (new Date(target.protected_until) > new Date()) throw new GameError("Bu kişi şu an koruma altında");

    const myGang = await gangOf(client, userId);
    const theirGang = await gangOf(client, targetId);
    if (myGang && theirGang && myGang.id === theirGang.id) throw new GameError("Kendi aileni soyamazsın");

    await spendEnergy(client, me, ROB_ENERGY);
    // Saldıran oyuncunun koruması biter
    await client.query("UPDATE players SET protected_until = LEAST(protected_until, now()) WHERE user_id=$1", [userId]);

    const d = (await client.query("SELECT * FROM districts WHERE id=$1", [me.district_id])).rows[0];
    const revenge = (await revengeTargets(client, userId)).has(targetId);
    const users = await client.query("SELECT id, username FROM users WHERE id = ANY($1)", [[userId, targetId]]);
    const nameOf = (id) => users.rows.find((u) => u.id === id)?.username || "?";

    const chance = odds({
      attackerLevel: levelOf(me.xp),
      targetLevel: levelOf(target.xp),
      controllerId: d.controller_gang_id,
      attackerGangId: myGang?.id,
      targetGangId: theirGang?.id,
      revenge
    });

    let outcome, cash = 0, fine = 0;
    const goods = [];

    if (Math.random() < d.police * 0.3) {
      outcome = "caught";
      fine = Math.min(Number(me.money), 300 + Math.floor(Number(me.money) * 0.05));
      await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, fine]);
    } else if (Math.random() < chance) {
      outcome = "success";
      const tLevel = levelOf(target.xp);
      cash = Math.min(
        Math.floor(Number(target.money) * (ECON.ROB_CASH_MIN + Math.random() * (ECON.ROB_CASH_MAX - ECON.ROB_CASH_MIN))),
        ECON.ROB_CASH_CAP(tLevel)
      );
      if (cash > 0) {
        await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [targetId, cash]);
        await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [userId, cash]);
      }

      // Rastgele bir mal yığınının %25'i (çantada yer kadar)
      const theirCargo = await cargo(client, targetId);
      if (theirCargo.length) {
        const pick = theirCargo[Math.floor(Math.random() * theirCargo.length)];
        const free = me.capacity - cargoWeight(await cargo(client, userId));
        let qty = Math.ceil(pick.qty * 0.25);
        if (pick.weight > 0) qty = Math.min(qty, Math.floor(free / pick.weight));
        if (qty > 0) {
          await client.query("UPDATE player_goods SET qty = qty - $3 WHERE user_id=$1 AND good_id=$2", [
            targetId,
            pick.good_id,
            qty
          ]);
          const mine = await client.query("SELECT qty, avg_cost FROM player_goods WHERE user_id=$1 AND good_id=$2", [
            userId,
            pick.good_id
          ]);
          const have = mine.rows[0] || { qty: 0, avg_cost: 0 };
          const newQty = have.qty + qty;
          // Çalınan mal, kurbanın maliyetinden çantaya girer
          const newAvg = (have.qty * have.avg_cost + qty * pick.avg_cost) / newQty;
          await client.query(
            `INSERT INTO player_goods (user_id, good_id, qty, avg_cost) VALUES ($1,$2,$3,$4)
             ON CONFLICT (user_id, good_id) DO UPDATE SET qty=$3, avg_cost=$4`,
            [userId, pick.good_id, newQty, newAvg]
          );
          goods.push({ goodId: pick.good_id, name: pick.name, qty });
        }
      }

      await client.query(
        "UPDATE players SET protected_until = now() + make_interval(mins => $2) WHERE user_id=$1",
        [targetId, VICTIM_PROTECT_MIN]
      );
      await client.query("UPDATE players SET xp = xp + 10 WHERE user_id=$1", [userId]);
      if (myGang && theirGang) await addInfluence(client, myGang.id, d.id, 15, userId);

      if (cash >= 1000) {
        const tag = myGang ? `[${myGang.tag}] ` : "";
        await addNews(
          client,
          `${tag}${nameOf(userId)}, ${d.name}'da ${nameOf(targetId)} adlı oyuncuyu soydu: ₺${cash.toLocaleString("tr-TR")}!`,
          "crime"
        );
      }
    } else {
      outcome = "escaped";
      await client.query("UPDATE players SET xp = xp + 5 WHERE user_id=$1", [targetId]);
      await client.query("UPDATE players SET xp = xp + 2 WHERE user_id=$1", [userId]);
    }

    // Polis yakalarsa kurbana bildirim gitmez (olay yaşanmadı)
    await client.query(
      `INSERT INTO robberies (attacker_id, target_id, district_id, success, outcome, cash, goods, seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [userId, targetId, d.id, outcome === "success", outcome, cash, JSON.stringify(goods), outcome === "caught"]
    );

    return {
      outcome,
      chance: Math.round(chance * 100),
      cash,
      goods,
      fine,
      revenge,
      target: nameOf(targetId),
      targetId,
      attacker: nameOf(userId),
      districtId: d.id,
      newsWorthy: outcome === "success" && cash >= 1000
    };
  });
}

// Son soygun kayıtları (yaptıkların ve sana yapılanlar)
async function record(pool, userId) {
  const r = await pool.query(
    `SELECT r.*, a.username AS attacker, t.username AS target FROM robberies r
     JOIN users a ON a.id = r.attacker_id JOIN users t ON t.id = r.target_id
     WHERE r.attacker_id=$1 OR (r.target_id=$1 AND r.outcome <> 'caught')
     ORDER BY r.id DESC LIMIT 12`,
    [userId]
  );
  return r.rows.map((x) => ({
    id: x.id,
    mine: x.attacker_id === userId,
    attacker: x.attacker,
    target: x.target,
    outcome: x.outcome,
    cash: Number(x.cash),
    goods: x.goods,
    districtId: x.district_id,
    at: new Date(x.created_at).toISOString()
  }));
}

module.exports = { street, rob, record, ROB_ENERGY };
