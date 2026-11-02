const { Pool } = require("pg");

const useSsl =
  process.env.DATABASE_SSL === "false"
    ? false
    : /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || "")
    ? false
    : { rejectUnauthorized: false };

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl
});

// ====== STATİK DÜNYA VERİSİ ======
// x/y: harita üzerindeki konum (0-1 aralığı), istemci haritayı bununla çizer.
const DISTRICTS = [
  { id: "liman", name: "Liman", police: 0.15, tax: 0.03, x: 0.18, y: 0.72, color: "#3FA7D6", desc: "Kaçak malın şehre girdiği sisli rıhtımlar." },
  { id: "fabrika", name: "Fabrika Bölgesi", police: 0.35, tax: 0.03, x: 0.22, y: 0.32, color: "#E07A5F", desc: "Bacalar, depolar ve ucuz ham madde." },
  { id: "carsi", name: "Çarşı", police: 0.4, tax: 0.02, x: 0.5, y: 0.52, color: "#F2CC8F", desc: "Şehrin kalbi. Her şey alınır, her şey satılır." },
  { id: "villalar", name: "Villalar", police: 0.7, tax: 0.05, x: 0.8, y: 0.25, color: "#B388EB", desc: "Zenginler lüks ister ve parasını öder." },
  { id: "gecekondu", name: "Gecekondu", police: 0.05, tax: 0.01, x: 0.78, y: 0.78, color: "#81B29A", desc: "Polis buraya girmez. Sen de dikkatli gir." },
  { id: "merkez", name: "Merkez", police: 0.9, tax: 0.04, x: 0.52, y: 0.16, color: "#D4AF37", desc: "Belediye, mahkeme ve rüşvet trafiği." }
];

const GOODS = [
  { id: "icki", name: "Kaçak İçki", base: 120, weight: 2, heat: 3, icon: "wine" },
  { id: "tutun", name: "Tütün", base: 60, weight: 1, heat: 1, icon: "smoke" },
  { id: "kahve", name: "Kahve", base: 45, weight: 1, heat: 0, icon: "coffee" },
  { id: "ilac", name: "İlaç", base: 220, weight: 1, heat: 4, icon: "medical" },
  { id: "radyo", name: "Radyo", base: 380, weight: 4, heat: 1, icon: "radio" },
  { id: "silah", name: "Silah", base: 900, weight: 3, heat: 8, icon: "gun" },
  { id: "mucevher", name: "Mücevher", base: 1500, weight: 1, heat: 5, icon: "diamond" },
  { id: "belge", name: "Sahte Belge", base: 650, weight: 0, heat: 6, icon: "document" },
  // Ham maddeler (işletmelerde işlenir)
  { id: "seker", name: "Şeker", base: 22, weight: 1, heat: 0, icon: "sugar" },
  { id: "hurda", name: "Hurda Metal", base: 38, weight: 2, heat: 0, icon: "scrap" },
  { id: "kagit", name: "Kağıt", base: 18, weight: 1, heat: 0, icon: "paper" }
];

// Semt × mal fiyat çarpanı (1 = taban fiyat). <1 ucuz (al), >1 pahalı (sat).
const PRICE_MODS = {
  liman:     { icki: 0.6,  tutun: 0.6,  kahve: 0.7,  ilac: 1.0,  radyo: 1.1,  silah: 0.9,  mucevher: 1.1,  belge: 1.2, seker: 0.6,  hurda: 0.8,  kagit: 1.0 },
  fabrika:   { icki: 1.0,  tutun: 0.9,  kahve: 1.2,  ilac: 0.8,  radyo: 0.65, silah: 0.8,  mucevher: 1.0,  belge: 1.0, seker: 0.9,  hurda: 1.25, kagit: 0.6 },
  carsi:     { icki: 1.05, tutun: 1.05, kahve: 1.0,  ilac: 1.05, radyo: 1.05, silah: 1.05, mucevher: 1.0,  belge: 1.0, seker: 1.0,  hurda: 1.0,  kagit: 1.0 },
  villalar:  { icki: 1.6,  tutun: 1.3,  kahve: 1.4,  ilac: 1.3,  radyo: 1.35, silah: 1.1,  mucevher: 1.5,  belge: 1.2, seker: 1.4,  hurda: 1.3,  kagit: 1.2 },
  gecekondu: { icki: 0.9,  tutun: 1.1,  kahve: 0.9,  ilac: 1.5,  radyo: 0.9,  silah: 1.55, mucevher: 0.6,  belge: 0.7, seker: 1.1,  hurda: 0.6,  kagit: 1.1 },
  merkez:    { icki: 1.3,  tutun: 1.2,  kahve: 1.1,  ilac: 1.1,  radyo: 1.2,  silah: 1.4,  mucevher: 1.3,  belge: 1.6, seker: 1.2,  hurda: 1.1,  kagit: 1.3 }
};

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS players (
        id SERIAL PRIMARY KEY,
        user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        money BIGINT NOT NULL DEFAULT 5000,
        level INT NOT NULL DEFAULT 1,
        xp INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      ALTER TABLE players ALTER COLUMN money TYPE BIGINT;
      ALTER TABLE players ADD COLUMN IF NOT EXISTS energy INT NOT NULL DEFAULT 100;
      ALTER TABLE players ADD COLUMN IF NOT EXISTS energy_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
      ALTER TABLE players ADD COLUMN IF NOT EXISTS district_id VARCHAR(32) NOT NULL DEFAULT 'liman';
      ALTER TABLE players ADD COLUMN IF NOT EXISTS capacity INT NOT NULL DEFAULT 40;

      CREATE TABLE IF NOT EXISTS districts (
        id VARCHAR(32) PRIMARY KEY,
        name VARCHAR(64) NOT NULL,
        police REAL NOT NULL,
        tax REAL NOT NULL,
        x REAL NOT NULL,
        y REAL NOT NULL,
        color VARCHAR(9) NOT NULL,
        description TEXT NOT NULL DEFAULT ''
      );

      CREATE TABLE IF NOT EXISTS goods (
        id VARCHAR(32) PRIMARY KEY,
        name VARCHAR(64) NOT NULL,
        base_price INT NOT NULL,
        weight INT NOT NULL,
        heat INT NOT NULL,
        icon VARCHAR(32) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS district_goods (
        district_id VARCHAR(32) REFERENCES districts(id) ON DELETE CASCADE,
        good_id VARCHAR(32) REFERENCES goods(id) ON DELETE CASCADE,
        anchor REAL NOT NULL,
        price REAL NOT NULL,
        PRIMARY KEY (district_id, good_id)
      );

      CREATE TABLE IF NOT EXISTS player_goods (
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        good_id VARCHAR(32) REFERENCES goods(id) ON DELETE CASCADE,
        qty INT NOT NULL DEFAULT 0 CHECK (qty >= 0),
        avg_cost REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, good_id)
      );

      CREATE TABLE IF NOT EXISTS travels (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        from_id VARCHAR(32) NOT NULL,
        to_id VARCHAR(32) NOT NULL,
        depart_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        arrive_at TIMESTAMPTZ NOT NULL,
        resolved BOOLEAN NOT NULL DEFAULT false,
        event JSONB
      );
      CREATE INDEX IF NOT EXISTS travels_active ON travels(user_id) WHERE resolved = false;

      CREATE TABLE IF NOT EXISTS gangs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(32) UNIQUE NOT NULL,
        tag VARCHAR(4) UNIQUE NOT NULL,
        color VARCHAR(9) NOT NULL,
        emblem VARCHAR(16) NOT NULL DEFAULT 'star',
        motto VARCHAR(80) NOT NULL DEFAULT '',
        bank BIGINT NOT NULL DEFAULT 0 CHECK (bank >= 0),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS gang_members (
        user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        gang_id INT NOT NULL REFERENCES gangs(id) ON DELETE CASCADE,
        rank VARCHAR(12) NOT NULL DEFAULT 'soldier',
        contribution INT NOT NULL DEFAULT 0,
        joined_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS gang_members_gang ON gang_members(gang_id);

      ALTER TABLE districts ADD COLUMN IF NOT EXISTS controller_gang_id INT REFERENCES gangs(id) ON DELETE SET NULL;
      ALTER TABLE districts ADD COLUMN IF NOT EXISTS war_ends_at TIMESTAMPTZ;

      CREATE TABLE IF NOT EXISTS district_influence (
        district_id VARCHAR(32) REFERENCES districts(id) ON DELETE CASCADE,
        gang_id INT REFERENCES gangs(id) ON DELETE CASCADE,
        points REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (district_id, gang_id)
      );

      CREATE TABLE IF NOT EXISTS news (
        id SERIAL PRIMARY KEY,
        text TEXT NOT NULL,
        kind VARCHAR(16) NOT NULL DEFAULT 'info',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      ALTER TABLE players ADD COLUMN IF NOT EXISTS protected_until TIMESTAMPTZ NOT NULL DEFAULT now() + interval '2 hours';

      CREATE TABLE IF NOT EXISTS robberies (
        id SERIAL PRIMARY KEY,
        attacker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        target_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        district_id VARCHAR(32) NOT NULL,
        success BOOLEAN NOT NULL,
        outcome VARCHAR(16) NOT NULL,
        cash BIGINT NOT NULL DEFAULT 0,
        goods JSONB NOT NULL DEFAULT '[]',
        seen BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS robberies_target ON robberies(target_id, id DESC);
      CREATE INDEX IF NOT EXISTS robberies_attacker ON robberies(attacker_id, id DESC);

      -- Oyuncu borsası: semt başına emir defteri
      CREATE TABLE IF NOT EXISTS market_orders (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        district_id VARCHAR(32) NOT NULL REFERENCES districts(id),
        good_id VARCHAR(32) NOT NULL REFERENCES goods(id),
        side VARCHAR(4) NOT NULL CHECK (side IN ('buy','sell')),
        price INT NOT NULL CHECK (price > 0),
        qty_total INT NOT NULL CHECK (qty_total > 0),
        qty_left INT NOT NULL CHECK (qty_left >= 0),
        escrow BIGINT NOT NULL DEFAULT 0 CHECK (escrow >= 0),
        status VARCHAR(10) NOT NULL DEFAULT 'open',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS market_orders_book
        ON market_orders(district_id, good_id, side, price) WHERE status = 'open';
      CREATE INDEX IF NOT EXISTS market_orders_user ON market_orders(user_id) WHERE status = 'open';

      CREATE TABLE IF NOT EXISTS market_trades (
        id SERIAL PRIMARY KEY,
        district_id VARCHAR(32) NOT NULL,
        good_id VARCHAR(32) NOT NULL,
        price INT NOT NULL,
        qty INT NOT NULL,
        buyer_id INT REFERENCES users(id) ON DELETE SET NULL,
        seller_id INT REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS market_trades_book ON market_trades(district_id, good_id, id DESC);

      -- Semt depoları: borsadan alınan mal buraya teslim edilir
      CREATE TABLE IF NOT EXISTS player_storage (
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        district_id VARCHAR(32) REFERENCES districts(id),
        good_id VARCHAR(32) REFERENCES goods(id),
        qty INT NOT NULL DEFAULT 0 CHECK (qty >= 0),
        avg_cost REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, district_id, good_id)
      );

      -- İşletmeler
      CREATE TABLE IF NOT EXISTS businesses (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        district_id VARCHAR(32) NOT NULL REFERENCES districts(id),
        type VARCHAR(24) NOT NULL,
        level INT NOT NULL DEFAULT 1,
        recipe_id VARCHAR(24),
        last_tick TIMESTAMPTZ NOT NULL DEFAULT now(),
        rent_paid_until TIMESTAMPTZ NOT NULL DEFAULT now(),
        closed_until TIMESTAMPTZ,
        till BIGINT NOT NULL DEFAULT 0,
        produced_total INT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (user_id, district_id, type)
      );
      CREATE TABLE IF NOT EXISTS business_stock (
        business_id INT REFERENCES businesses(id) ON DELETE CASCADE,
        good_id VARCHAR(32) REFERENCES goods(id),
        qty INT NOT NULL DEFAULT 0 CHECK (qty >= 0),
        PRIMARY KEY (business_id, good_id)
      );

      CREATE TABLE IF NOT EXISTS trades (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        district_id VARCHAR(32) NOT NULL,
        good_id VARCHAR(32) NOT NULL,
        side VARCHAR(4) NOT NULL,
        qty INT NOT NULL,
        price REAL NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    for (const d of DISTRICTS) {
      await client.query(
        `INSERT INTO districts (id, name, police, tax, x, y, color, description)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (id) DO UPDATE SET name=$2, police=$3, tax=$4, x=$5, y=$6, color=$7, description=$8`,
        [d.id, d.name, d.police, d.tax, d.x, d.y, d.color, d.desc]
      );
    }
    // Bölge savaşı turu olmayan semtlere ilk turu başlat
    await client.query(
      `UPDATE districts SET war_ends_at = now() + make_interval(mins => $1) WHERE war_ends_at IS NULL`,
      [Number(process.env.WAR_ROUND_MINUTES || 60)]
    );

    for (const g of GOODS) {
      await client.query(
        `INSERT INTO goods (id, name, base_price, weight, heat, icon)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET name=$2, base_price=$3, weight=$4, heat=$5, icon=$6`,
        [g.id, g.name, g.base, g.weight, g.heat, g.icon]
      );
    }
    for (const d of DISTRICTS) {
      for (const g of GOODS) {
        const anchor = g.base * PRICE_MODS[d.id][g.id];
        await client.query(
          `INSERT INTO district_goods (district_id, good_id, anchor, price)
           VALUES ($1,$2,$3,$3)
           ON CONFLICT (district_id, good_id) DO UPDATE SET anchor=$3`,
          [d.id, g.id, anchor]
        );
      }
    }

    await client.query("COMMIT");
    console.log("✅ DB tables ready");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB, DISTRICTS, GOODS };
