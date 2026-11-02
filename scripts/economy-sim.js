// Ekonomi simülasyonu: oyunun sayılarını gerçek kurallarla hesaplar ve hedeflerle karşılaştırır.
// Kullanım: node scripts/economy-sim.js
// Veritabanı gerekmez; değerler src/ altındaki sabitlerden okunur.

process.env.DATABASE_URL ||= "postgres://sim@localhost/sim";
const { DISTRICTS, GOODS, anchorOf } = require("../src/db");
const game = require("../src/game");
const { TYPES } = require("../src/business");

const C = require("../src/economy");
const SPREAD = C.NPC_SPREAD;
const CAPACITY = C.START_CAPACITY;
const START_MONEY = C.START_MONEY;
const impactPerUnit = (g) => C.impactPerUnit(g);
const policeChance = (d, hot) => Math.min(0.85, d.police * (hot / C.HEAT_DIVISOR));

const fmt = (n) => "₺" + Math.round(n).toLocaleString("tr-TR");
const pct = (n) => (n * 100).toFixed(0) + "%";

// Tek bir sefer: A'da al, B'de sat. Fiyat etkisi, NPC makası, vergi ve polis riski dahil.
function trip(good, from, to, capital) {
  const buyA = anchorOf(from.id, good.id);
  const sellB = anchorOf(to.id, good.id);
  const k = impactPerUnit(good);
  const maxByWeight = good.weight > 0 ? Math.floor(CAPACITY / good.weight) : 1000;
  let best = null;
  for (let q = 1; q <= Math.min(maxByWeight, 1000); q++) {
    const buyUnit = buyA * (1 + (k * q) / 2) * (1 + SPREAD);
    if (buyUnit * q > capital) break;
    const sellUnit = sellB * (1 - (k * q) / 2) * (1 - SPREAD);
    const gross = sellUnit * q * (1 - to.tax);
    const cost = buyUnit * q;
    const hot = good.heat * q;
    const pPolice = hot > 0 ? policeChance(to, hot) : 0;
    // Polis malın yarısına el koyar
    const expected = (1 - pPolice) * gross + pPolice * gross * 0.5 - cost;
    if (!best || expected > best.expected) best = { q, cost, gross, expected, pPolice };
  }
  return best;
}

function bestRoutes(capital, n = 6) {
  const out = [];
  for (const g of GOODS)
    for (const a of DISTRICTS)
      for (const b of DISTRICTS) {
        if (a.id === b.id) continue;
        const t = trip(g, a, b, capital);
        if (t && t.expected > 0) out.push({ g, a, b, ...t });
      }
  return out.sort((x, y) => y.expected - x.expected).slice(0, n);
}

console.log("=".repeat(78));
console.log("UNDERWORLD CITY · EKONOMİ SİMÜLASYONU");
console.log("=".repeat(78));

for (const capital of [START_MONEY, 25000, 200000]) {
  console.log(`\n■ En iyi ticaret seferleri (sermaye ${fmt(capital)}, çanta ${CAPACITY} kg)`);
  for (const r of bestRoutes(capital, 5)) {
    console.log(
      `  ${r.g.name.padEnd(12)} ${r.a.name.padEnd(16)} → ${r.b.name.padEnd(16)} ${String(r.q).padStart(3)} adet` +
        `  maliyet ${fmt(r.cost).padStart(9)}  beklenen kâr ${fmt(r.expected).padStart(8)}` +
        `  (${pct(r.expected / r.cost)}/sefer, polis ${pct(r.pPolice)})`
    );
  }
}

// Sermaye büyümesi: her sefer en iyi rotayı kullanan aktif oyuncu.
// Enerji: 100 başlangıç, saatte 10 yenilenir, sefer 10 enerji → günde ~34 sefer (tam aktif).
function growth(tripsPerDay, days) {
  let money = START_MONEY;
  const rows = [];
  for (let d = 1; d <= days; d++) {
    for (let t = 0; t < tripsPerDay; t++) {
      const r = bestRoutes(money, 1)[0];
      if (!r) break;
      money += r.expected;
    }
    rows.push(money);
  }
  return rows;
}
console.log("\n■ Sadece ticaretle sermaye (her seferde en iyi rota, beklenen değer)");
for (const [label, tpd] of [
  ["Gündelik oyuncu (günde 12 sefer)", 12],
  ["Çok aktif oyuncu (günde 30 sefer)", 30]
]) {
  const g = growth(tpd, 7);
  console.log(`  ${label.padEnd(34)} ` + g.map((m, i) => `G${i + 1}:${fmt(m)}`).join("  "));
}

// İşletmeler: taban fiyatla hammadde alıp çıktıyı taban fiyattan saydığımızda saatlik net ve geri dönüş süresi
const base = Object.fromEntries(GOODS.map((g) => [g.id, g.base]));
const speeds = C.BUSINESS_SPEED;
console.log("\n■ İşletmeler (taban fiyatlarla, lojistik avantajı hariç)");
for (const [id, t] of Object.entries(TYPES)) {
  for (const r of t.recipes) {
    const inV = Object.entries(r.inputs).reduce((s, [g, q]) => s + base[g] * q, 0);
    const outV = Object.entries(r.outputs).reduce((s, [g, q]) => s + base[g] * q, 0) + (r.cash || 0);
    const perH = 3600 / r.seconds;
    const net = (outV - inV) * perH - t.rent;
    const inputsPerH = Object.values(r.inputs).reduce((s, q) => s + q, 0) * perH;
    const capHours = C.STOCK_CAP[0] / inputsPerH;
    console.log(
      `  ${t.name.padEnd(12)} ${r.name.padEnd(18)} parti ${String(Math.round(r.seconds / 60)).padStart(3)} dk` +
        `  net ${fmt(net).padStart(7)}/sa  geri dönüş ${(t.cost / net).toFixed(1).padStart(5)} sa` +
        `  ambar ${capHours.toFixed(1)} sa yeter`
    );
    for (let lv = 2; lv <= speeds.length; lv++) {
      const up = Math.round(t.cost * (lv - 1) * C.UPGRADE_FACTOR);
      const extra = (outV - inV) * perH * (speeds[lv - 1] - speeds[lv - 2]);
      console.log(`      → Sv${lv} yükseltme ${fmt(up)}: +${fmt(extra)}/sa, geri dönüş ${(up / extra).toFixed(1)} sa`);
    }
  }
}
// Günlük gelir karşılaştırması
const dayTrade = (trips) => {
  let money = 20000, earned = 0;
  for (let t = 0; t < trips; t++) {
    const r = bestRoutes(money, 1)[0];
    if (!r) break;
    money += r.expected;
    earned += r.expected;
  }
  return earned;
};
const bizDaily = Object.values(TYPES).map((t) => {
  const r = t.recipes[0];
  const inV = Object.entries(r.inputs).reduce((s, [g, q]) => s + base[g] * q, 0);
  const outV = Object.entries(r.outputs).reduce((s, [g, q]) => s + base[g] * q, 0) + (r.cash || 0);
  return { name: t.name, daily: ((outV - inV) * 3600) / r.seconds * 24 - t.rent * 24 };
});
console.log("\n■ Günlük gelir karşılaştırması");
console.log(`  Ticaret, gündelik (12 sefer)     ${fmt(dayTrade(12))}/gün`);
console.log(`  Ticaret, çok aktif (30 sefer)    ${fmt(dayTrade(30))}/gün`);
for (const b of bizDaily) console.log(`  ${("1 × " + b.name + " (Sv1)").padEnd(32)} ${fmt(b.daily)}/gün`);
console.log();
