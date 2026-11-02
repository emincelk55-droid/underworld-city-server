// Çeteler ve semt kontrolü.
//
// Nüfuz (influence): Çete üyeleri bir semtte ticaret yaptıkça ve eylem yaptıkça
// o semtte çeteleri için nüfuz puanı toplar. Her semtte belli aralıklarla bir
// "bölge savaşı turu" biter. En çok nüfuzu olan çete (en az CONTROL_MIN puanla)
// semtin kontrolünü alır. Puanların %30'u bir sonraki tura devreder.
//
// Kontrolün faydaları (game.js içinde uygulanır):
//  - Üyeler o semtte yarı vergi öder
//  - Satışlardan alınan verginin yarısı çete kasasına gider
//  - Üyeler için polis riski yarıya iner, soygun olmaz

const { GameError, lockPlayer, activeTravel, spendEnergy, resolveArrivals } = require("./game");
const { gangOf, addInfluence, addNews } = require("./influence");

const GANG_CREATE_COST = 2500;
const GANG_MAX_MEMBERS = 15;
const CONTROL_MIN = 100;
const CARRY_OVER = 0.3;
const WAR_ROUND_MINUTES = Number(process.env.WAR_ROUND_MINUTES || 60);

const RANKS = ["soldier", "capo", "underboss", "boss"];
const RANK_NAMES = { boss: "Baba", underboss: "Sağ Kol", capo: "Kaptan", soldier: "Asker" };
const EMBLEMS = ["star", "rose", "crown", "flame", "anchor", "dice", "eye", "bolt"];
const COLORS = ["#C0392B", "#8E44AD", "#2980B9", "#16A085", "#D4AF37", "#E67E22", "#7F8C8D", "#E84393"];

const ACTIONS = {
  patrol: { name: "Nöbet Tut", energy: 15, money: 0, desc: "Semtte adamlarını dolaştır. +25 nüfuz" },
  bribe: { name: "Rüşvet Dağıt", energy: 5, money: 1000, desc: "Polise ve esnafa zarf. +45 nüfuz" },
  raid: { name: "Baskın", energy: 25, money: 0, desc: "Rakip çetenin adamlarını dağıt. Rakibe -40 nüfuz" }
};

const rankIndex = (r) => RANKS.indexOf(r);

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

async function requireGang(client, userId, minRank = "soldier") {
  const g = await gangOf(client, userId);
  if (!g) throw new GameError("Bir çeteye üye değilsin");
  if (rankIndex(g.rank) < rankIndex(minRank)) throw new GameError("Rütben bunun için yetmiyor");
  return g;
}

// ====== LİSTE / DETAY ======
async function listGangs(pool) {
  const r = await pool.query(`
    SELECT g.id, g.name, g.tag, g.color, g.emblem, g.motto,
      (SELECT COUNT(*) FROM gang_members m WHERE m.gang_id=g.id)::int AS members,
      (SELECT COUNT(*) FROM districts d WHERE d.controller_gang_id=g.id)::int AS territories,
      (SELECT COALESCE(SUM(points),0) FROM district_influence i WHERE i.gang_id=g.id)::float AS influence
    FROM gangs g ORDER BY territories DESC, influence DESC, g.id`);
  return r.rows.map((g) => ({ ...g, maxMembers: GANG_MAX_MEMBERS }));
}

async function gangDetail(pool, gangId) {
  const g = await pool.query("SELECT * FROM gangs WHERE id=$1", [gangId]);
  if (!g.rows.length) throw new GameError("Çete bulunamadı", 404);
  const m = await pool.query(
    `SELECT u.id AS user_id, u.username, m.rank, m.contribution, p.xp, p.district_id
     FROM gang_members m JOIN users u ON u.id=m.user_id JOIN players p ON p.user_id=m.user_id
     WHERE m.gang_id=$1`,
    [gangId]
  );
  const t = await pool.query("SELECT id FROM districts WHERE controller_gang_id=$1", [gangId]);
  const gang = g.rows[0];
  return {
    id: gang.id,
    name: gang.name,
    tag: gang.tag,
    color: gang.color,
    emblem: gang.emblem,
    motto: gang.motto,
    bank: Number(gang.bank),
    territories: t.rows.map((x) => x.id),
    maxMembers: GANG_MAX_MEMBERS,
    members: m.rows
      .map((x) => ({
        userId: x.user_id,
        username: x.username,
        rank: x.rank,
        rankName: RANK_NAMES[x.rank],
        contribution: x.contribution,
        level: 1 + Math.floor(Math.sqrt(x.xp / 50)),
        districtId: x.district_id
      }))
      .sort((a, b) => rankIndex(b.rank) - rankIndex(a.rank) || b.contribution - a.contribution)
  };
}

// ====== KUR / KATIL / AYRIL ======
async function createGang(pool, userId, { name, tag, color, emblem, motto }) {
  name = String(name || "").trim();
  tag = String(tag || "").trim().toUpperCase();
  motto = String(motto || "").trim().slice(0, 80);
  if (!/^[\p{L}0-9 ._'-]{3,24}$/u.test(name)) throw new GameError("Çete adı 3-24 karakter olmalı");
  if (!/^[A-ZÇĞİÖŞÜ0-9]{2,4}$/u.test(tag)) throw new GameError("Kısaltma 2-4 harf/rakam olmalı");
  if (!COLORS.includes(color)) throw new GameError("Geçersiz renk");
  if (!EMBLEMS.includes(emblem)) throw new GameError("Geçersiz amblem");

  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    if (await gangOf(client, userId)) throw new GameError("Zaten bir çetedesin");
    if (Number(player.money) < GANG_CREATE_COST)
      throw new GameError(`Çete kurmak için ₺${GANG_CREATE_COST} gerekiyor`);
    let g;
    try {
      g = await client.query(
        "INSERT INTO gangs (name, tag, color, emblem, motto) VALUES ($1,$2,$3,$4,$5) RETURNING id",
        [name, tag, color, emblem, motto]
      );
    } catch (e) {
      if (e.code === "23505") throw new GameError("Bu isim ya da kısaltma alınmış");
      throw e;
    }
    await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, GANG_CREATE_COST]);
    await client.query("INSERT INTO gang_members (user_id, gang_id, rank) VALUES ($1,$2,'boss')", [
      userId,
      g.rows[0].id
    ]);
    await addNews(client, `Şehirde yeni bir aile: [${tag}] ${name}`, "gang");
    return { id: g.rows[0].id };
  });
}

async function joinGang(pool, userId, gangId) {
  return tx(pool, async (client) => {
    await lockPlayer(client, userId);
    if (await gangOf(client, userId)) throw new GameError("Zaten bir çetedesin");
    const g = await client.query("SELECT * FROM gangs WHERE id=$1 FOR UPDATE", [gangId]);
    if (!g.rows.length) throw new GameError("Çete bulunamadı", 404);
    const c = await client.query("SELECT COUNT(*)::int AS n FROM gang_members WHERE gang_id=$1", [gangId]);
    if (c.rows[0].n >= GANG_MAX_MEMBERS) throw new GameError("Bu çete dolu");
    await client.query("INSERT INTO gang_members (user_id, gang_id) VALUES ($1,$2)", [userId, gangId]);
    return { id: Number(gangId) };
  });
}

// Çeteden ayrıl. Baba ayrılırsa en yüksek rütbeli/katkılı üye Baba olur.
// Son üye ayrılırsa çete dağılır, kasası ve bölgeleri kaybolur.
async function leaveGang(pool, userId) {
  return tx(pool, async (client) => {
    const g = await requireGang(client, userId);
    await client.query("SELECT id FROM gangs WHERE id=$1 FOR UPDATE", [g.id]);
    await client.query("DELETE FROM gang_members WHERE user_id=$1", [userId]);
    const rest = await client.query(
      `SELECT user_id, rank FROM gang_members WHERE gang_id=$1
       ORDER BY array_position(ARRAY['boss','underboss','capo','soldier']::varchar[], rank), contribution DESC, joined_at
       LIMIT 1`,
      [g.id]
    );
    if (!rest.rows.length) {
      await client.query("DELETE FROM gangs WHERE id=$1", [g.id]);
      await addNews(client, `[${g.tag}] ${g.name} dağıldı.`, "gang");
      return { dissolved: true };
    }
    if (g.rank === "boss") {
      await client.query("UPDATE gang_members SET rank='boss' WHERE user_id=$1", [rest.rows[0].user_id]);
    }
    return { dissolved: false };
  });
}

async function kickMember(pool, userId, targetId) {
  return tx(pool, async (client) => {
    const me = await requireGang(client, userId, "underboss");
    const t = await client.query("SELECT * FROM gang_members WHERE user_id=$1 AND gang_id=$2 FOR UPDATE", [
      targetId,
      me.id
    ]);
    if (!t.rows.length) throw new GameError("Bu kişi çetende değil");
    if (Number(targetId) === userId) throw new GameError("Kendini atamazsın");
    if (rankIndex(t.rows[0].rank) >= rankIndex(me.rank)) throw new GameError("Kendi rütbende ya da üstündekini atamazsın");
    await client.query("DELETE FROM gang_members WHERE user_id=$1", [targetId]);
    return { ok: true };
  });
}

async function setRank(pool, userId, targetId, rank) {
  if (!RANKS.includes(rank)) throw new GameError("Geçersiz rütbe");
  return tx(pool, async (client) => {
    const me = await requireGang(client, userId, "boss");
    if (Number(targetId) === userId) throw new GameError("Kendi rütbeni değiştiremezsin");
    const t = await client.query("SELECT * FROM gang_members WHERE user_id=$1 AND gang_id=$2 FOR UPDATE", [
      targetId,
      me.id
    ]);
    if (!t.rows.length) throw new GameError("Bu kişi çetende değil");
    if (rank === "boss") {
      // Babalığı devret
      await client.query("UPDATE gang_members SET rank='underboss' WHERE user_id=$1", [userId]);
    }
    await client.query("UPDATE gang_members SET rank=$2 WHERE user_id=$1", [targetId, rank]);
    return { ok: true };
  });
}

// ====== KASA ======
async function deposit(pool, userId, amount) {
  amount = Math.floor(Number(amount));
  if (!Number.isFinite(amount) || amount <= 0) throw new GameError("Geçersiz miktar");
  return tx(pool, async (client) => {
    const player = await lockPlayer(client, userId);
    const g = await requireGang(client, userId);
    if (Number(player.money) < amount) throw new GameError("Yeterli paran yok");
    await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, amount]);
    await client.query("UPDATE gangs SET bank = bank + $2 WHERE id=$1", [g.id, amount]);
    await client.query("UPDATE gang_members SET contribution = contribution + $2 WHERE user_id=$1", [
      userId,
      Math.floor(amount / 100)
    ]);
    return { ok: true };
  });
}

async function withdraw(pool, userId, amount) {
  amount = Math.floor(Number(amount));
  if (!Number.isFinite(amount) || amount <= 0) throw new GameError("Geçersiz miktar");
  return tx(pool, async (client) => {
    await lockPlayer(client, userId);
    const g = await requireGang(client, userId, "underboss");
    const b = await client.query("SELECT bank FROM gangs WHERE id=$1 FOR UPDATE", [g.id]);
    if (Number(b.rows[0].bank) < amount) throw new GameError("Kasada o kadar para yok");
    await client.query("UPDATE gangs SET bank = bank - $2 WHERE id=$1", [g.id, amount]);
    await client.query("UPDATE players SET money = money + $2 WHERE user_id=$1", [userId, amount]);
    return { ok: true };
  });
}

// ====== BÖLGE ======
async function territory(pool) {
  const d = await pool.query(
    `SELECT d.id, d.war_ends_at, g.id AS gid, g.name, g.tag, g.color, g.emblem
     FROM districts d LEFT JOIN gangs g ON g.id = d.controller_gang_id`
  );
  const inf = await pool.query(
    `SELECT i.district_id, i.points, g.id, g.name, g.tag, g.color, g.emblem
     FROM district_influence i JOIN gangs g ON g.id=i.gang_id WHERE i.points >= 1
     ORDER BY i.points DESC`
  );
  const out = {};
  for (const row of d.rows) {
    out[row.id] = {
      warEndsAt: row.war_ends_at ? new Date(row.war_ends_at).toISOString() : null,
      controller: row.gid ? { id: row.gid, name: row.name, tag: row.tag, color: row.color, emblem: row.emblem } : null,
      influence: []
    };
  }
  for (const r of inf.rows) {
    const list = out[r.district_id]?.influence;
    if (list && list.length < 5)
      list.push({ id: r.id, name: r.name, tag: r.tag, color: r.color, emblem: r.emblem, points: Math.round(r.points) });
  }
  return { districts: out, controlMin: CONTROL_MIN, roundMinutes: WAR_ROUND_MINUTES, actions: ACTIONS };
}

async function territoryAction(pool, userId, action) {
  const a = ACTIONS[action];
  if (!a) throw new GameError("Geçersiz eylem");
  return tx(pool, async (client) => {
    await resolveArrivals(client, userId);
    const player = await lockPlayer(client, userId);
    const g = await requireGang(client, userId);
    if (await activeTravel(client, userId)) throw new GameError("Yoldayken bunu yapamazsın");
    const d = (await client.query("SELECT * FROM districts WHERE id=$1", [player.district_id])).rows[0];

    if (a.money && Number(player.money) < a.money) throw new GameError("Yeterli paran yok");
    await spendEnergy(client, player, a.energy);
    if (a.money) await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, a.money]);

    const levelBonus = 1 + Math.floor(Math.sqrt(player.xp / 50)) * 0.05;
    let result;
    if (action === "patrol") {
      const pts = Math.round(25 * levelBonus);
      await addInfluence(client, g.id, d.id, pts, userId);
      result = { type: "patrol", points: pts };
    } else if (action === "bribe") {
      const pts = Math.round(45 * levelBonus);
      await addInfluence(client, g.id, d.id, pts, userId);
      result = { type: "bribe", points: pts };
    } else {
      // Baskın: en güçlü rakibi (kontrol eden ya da nüfuzu en yüksek) hedef al
      const rival = await client.query(
        `SELECT i.gang_id, i.points, g.name, g.tag FROM district_influence i JOIN gangs g ON g.id=i.gang_id
         WHERE i.district_id=$1 AND i.gang_id<>$2 AND i.points > 0
         ORDER BY (i.gang_id = $3) DESC, i.points DESC LIMIT 1 FOR UPDATE OF i`,
        [d.id, g.id, d.controller_gang_id || 0]
      );
      if (!rival.rows.length) throw new GameError("Bu semtte baskın yapılacak rakip yok");
      const r = rival.rows[0];
      // Polisin olduğu yerde baskın riskli: yakalanırsan ceza ödersin
      if (Math.random() < d.police * 0.45) {
        const fine = Math.min(Number(player.money), 400 + Math.floor(Number(player.money) * 0.05));
        await client.query("UPDATE players SET money = money - $2 WHERE user_id=$1", [userId, fine]);
        result = { type: "raid_caught", fine, rival: `[${r.tag}] ${r.name}` };
      } else {
        const dmg = Math.min(r.points, Math.round(40 * levelBonus));
        await client.query("UPDATE district_influence SET points = points - $3 WHERE district_id=$1 AND gang_id=$2", [
          d.id,
          r.gang_id,
          dmg
        ]);
        await client.query("UPDATE gang_members SET contribution = contribution + $2 WHERE user_id=$1", [userId, dmg]);
        result = { type: "raid", damage: dmg, rival: `[${r.tag}] ${r.name}` };
      }
    }
    await client.query("UPDATE players SET xp = xp + 3 WHERE user_id=$1", [userId]);
    return { ...result, districtId: d.id };
  });
}

// Süresi dolan bölge savaşı turlarını sonuçlandırır. Değişiklik olursa haber döner.
async function resolveWars(pool) {
  return tx(pool, async (client) => {
    const due = await client.query(
      `SELECT d.*, g.name AS cname, g.tag AS ctag FROM districts d LEFT JOIN gangs g ON g.id=d.controller_gang_id
       WHERE d.war_ends_at <= now() FOR UPDATE OF d SKIP LOCKED`
    );
    const changes = [];
    for (const d of due.rows) {
      const top = await client.query(
        `SELECT i.gang_id, i.points, g.name, g.tag FROM district_influence i JOIN gangs g ON g.id=i.gang_id
         WHERE i.district_id=$1 ORDER BY i.points DESC LIMIT 2`,
        [d.id]
      );
      const t = top.rows[0];
      const challenger = top.rows[1];
      if (t && t.points >= CONTROL_MIN && t.gang_id !== d.controller_gang_id) {
        await client.query("UPDATE districts SET controller_gang_id=$2 WHERE id=$1", [d.id, t.gang_id]);
        const text = d.controller_gang_id
          ? `[${t.tag}] ${t.name}, ${d.name} semtini [${d.ctag}] ${d.cname} ailesinden aldı!`
          : `[${t.tag}] ${t.name} artık ${d.name} semtini yönetiyor!`;
        await addNews(client, text, "war");
        changes.push({ districtId: d.id, gangId: t.gang_id, text });
      } else if (d.controller_gang_id && t?.gang_id === d.controller_gang_id && challenger?.points >= CONTROL_MIN / 2) {
        // Sadece ciddi bir rakip varsa haber olur
        await addNews(client, `[${d.ctag}] ${d.cname}, ${d.name} semtini elinde tuttu.`, "hold");
      }
      await client.query("UPDATE district_influence SET points = points * $2 WHERE district_id=$1", [
        d.id,
        CARRY_OVER
      ]);
      await client.query(
        "UPDATE districts SET war_ends_at = now() + make_interval(mins => $2) WHERE id=$1",
        [d.id, WAR_ROUND_MINUTES]
      );
    }
    return changes;
  });
}

async function news(pool, limit = 20) {
  const r = await pool.query("SELECT id, text, kind, created_at FROM news ORDER BY id DESC LIMIT $1", [limit]);
  return r.rows.map((n) => ({ id: n.id, text: n.text, kind: n.kind, at: new Date(n.created_at).toISOString() }));
}

module.exports = {
  listGangs,
  gangDetail,
  createGang,
  joinGang,
  leaveGang,
  kickMember,
  setRank,
  deposit,
  withdraw,
  territory,
  territoryAction,
  resolveWars,
  news,
  GANG_CREATE_COST,
  EMBLEMS,
  COLORS,
  RANK_NAMES
};
