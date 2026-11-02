// =====================================================================
// EKONOMİ AYARLARI — oyunun tüm sayıları burada.
// Değiştirdikten sonra `node scripts/economy-sim.js` ile sonucu kontrol et.
// Hedefler ve gerekçeler: docs/EKONOMI.md
// =====================================================================

// ---- Başlangıç ----
const START_MONEY = 5000;
const START_CAPACITY = 40; // kg

// ---- NPC pazarı ----
const NPC_SPREAD = 0.05; // tüccardan alırken +%5, satarken -%5 (gidiş-dönüş %10 komisyon)

// Semtler arası fiyat farkı. db.js'teki PRICE_MODS çarpanları bu üsle sıkıştırılır:
// çarpan^0.45 → 0.6 ↔ 1.6 arası fark (2.7 kat) 0.79 ↔ 1.24 arasına (~1.55 kat) iner.
const PRICE_EXPONENT = 0.45;

// Piyasa derinliği: fiyatı %10 kaydırmak için gereken birim sayısı.
// Lüks ve kaçak mallarda piyasa sığdır, bu yüzden bir seferde taşınabilecek kârlı miktar sınırlanır.
const DEPTH = {
  kahve: 150,
  tutun: 120,
  icki: 70,
  ilac: 40,
  radyo: 35,
  silah: 12,
  mucevher: 8,
  belge: 12,
  seker: 200,
  hurda: 160,
  kagit: 220
};
const impactPerUnit = (good) => 0.1 / (DEPTH[good.id] || 100);

// Fiyatlar her tick'te (10 sn) çapaya bu oranda döner. 0.015 → yarılanma ~7.5 dk
const PRICE_REVERT = 0.015;
const PRICE_NOISE = 0.012;

// ---- Polis ----
// Yolculukta yakalanma şansı = semt polisi × (taşınan ısı / HEAT_DIVISOR), en fazla %85
const HEAT_DIVISOR = 90;

// ---- İşletmeler ----
const MAX_BUSINESSES = 4;
const BUSINESS_SPEED = [1, 1.5, 2.2];
const STOCK_CAP = [60, 120, 240]; // ambar (birim). Sv1'de en az 8 saatlik hammadde sığmalı
const RAID_CLOSE_MIN = 30;
const UPGRADE_FACTOR = 0.8; // yükseltme bedeli = kuruluş × seviye × 0.8

// Hedef: Sv1, taban fiyatlarla 48–72 saatte kendini amorti etsin.
// Doğru semtten ucuz alıp pahalı satan (lojistik yapan) oyuncu bunu ~1–2 güne indirebilir.
const BUSINESS_TYPES = {
  imalathane: {
    name: "İmalathane",
    kind: "production",
    desc: "Bodrumda kazanlar. Şekerden kaçak içki damıtılır.",
    cost: 4000,
    rent: 30,
    districts: ["liman", "fabrika", "gecekondu"],
    recipes: [{ id: "icki", name: "Kaçak İçki damıt", inputs: { seker: 3 }, outputs: { icki: 1 }, seconds: 1800 }]
  },
  atolye: {
    name: "Atölye",
    kind: "production",
    desc: "Tornalar ve lehim kokusu. Hurdadan radyo ve silah çıkar.",
    cost: 6000,
    rent: 45,
    districts: ["fabrika", "gecekondu"],
    recipes: [
      { id: "radyo", name: "Radyo topla", inputs: { hurda: 6 }, outputs: { radyo: 1 }, seconds: 3600 },
      { id: "silah", name: "Silah dök", inputs: { hurda: 6, radyo: 1 }, outputs: { silah: 1 }, seconds: 7200 }
    ]
  },
  matbaa: {
    name: "Matbaa",
    kind: "production",
    desc: "Gece vardiyasında baskı makineleri. Kağıttan sahte belge.",
    cost: 5000,
    rent: 40,
    districts: ["fabrika", "carsi", "merkez"],
    recipes: [{ id: "belge", name: "Sahte belge bas", inputs: { kagit: 8 }, outputs: { belge: 1 }, seconds: 14400 }]
  },
  kahvehane: {
    name: "Kahvehane",
    kind: "front",
    desc: "Tavla şakırtısı ve dumanlı sohbetler. Kahve satar, kasaya para akar.",
    cost: 3000,
    rent: 25,
    districts: ["liman", "carsi", "gecekondu", "merkez"],
    recipes: [{ id: "kahve_sat", name: "Kahve servisi", inputs: { kahve: 4 }, outputs: {}, cash: 255, seconds: 3600 }]
  },
  gece_kulubu: {
    name: "Gece Kulübü",
    kind: "front",
    desc: "Caz, ipek perdeler ve arka oda. İçki satar, aileye nüfuz kazandırır.",
    cost: 8000,
    rent: 70,
    districts: ["villalar", "merkez", "carsi"],
    recipes: [
      { id: "icki_sat", name: "Bar servisi", inputs: { icki: 3 }, outputs: {}, cash: 560, influence: 4, seconds: 3600 }
    ]
  }
};

// ---- PvP ----
const ROB_ENERGY = 20;
const ROB_CASH_MIN = 0.08; // kurbanın parasının %8–15'i
const ROB_CASH_MAX = 0.15;
const ROB_CASH_CAP = (targetLevel) => 1500 + 300 * targetLevel;

module.exports = {
  START_MONEY,
  START_CAPACITY,
  NPC_SPREAD,
  PRICE_EXPONENT,
  DEPTH,
  impactPerUnit,
  PRICE_REVERT,
  PRICE_NOISE,
  HEAT_DIVISOR,
  MAX_BUSINESSES,
  BUSINESS_SPEED,
  STOCK_CAP,
  RAID_CLOSE_MIN,
  UPGRADE_FACTOR,
  BUSINESS_TYPES,
  ROB_ENERGY,
  ROB_CASH_MIN,
  ROB_CASH_MAX,
  ROB_CASH_CAP
};
