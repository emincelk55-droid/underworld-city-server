// Çete/bölge yardımcıları (game.js ve gangs.js ortak kullanır)

async function gangOf(client, userId) {
  const r = await client.query(
    `SELECT g.*, m.rank FROM gang_members m JOIN gangs g ON g.id = m.gang_id WHERE m.user_id=$1`,
    [userId]
  );
  return r.rows[0] || null;
}

async function addInfluence(client, gangId, districtId, points, userId = null) {
  if (!gangId || points <= 0) return;
  await client.query(
    `INSERT INTO district_influence (district_id, gang_id, points) VALUES ($1,$2,$3)
     ON CONFLICT (district_id, gang_id) DO UPDATE SET points = district_influence.points + $3`,
    [districtId, gangId, points]
  );
  if (userId) {
    await client.query("UPDATE gang_members SET contribution = contribution + $2 WHERE user_id=$1", [
      userId,
      Math.round(points)
    ]);
  }
}

async function addNews(client, text, kind = "info") {
  await client.query("INSERT INTO news (text, kind) VALUES ($1,$2)", [text, kind]);
}

module.exports = { gangOf, addInfluence, addNews };
