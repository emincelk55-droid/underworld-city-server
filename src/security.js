// Güvenlik yardımcıları: hız sınırı, CORS ayarı, sohbet filtresi.

// Kayan pencereli hız sınırı. key fonksiyonu IP ya da kullanıcı id döndürür.
function rateLimit({ max, windowMs, key = (req) => req.ip, message = "Çok hızlısın, biraz bekle" }) {
  const hits = new Map();
  // Bellek şişmesin: eski kayıtları dakikada bir temizle
  setInterval(() => {
    const now = Date.now();
    for (const [k, list] of hits) {
      const fresh = list.filter((t) => now - t < windowMs);
      if (fresh.length) hits.set(k, fresh);
      else hits.delete(k);
    }
  }, 60_000).unref();

  const limiter = (req, res, next) => {
    const now = Date.now();
    const k = key(req);
    const list = (hits.get(k) || []).filter((t) => now - t < windowMs);
    if (list.length >= max) {
      res.set("Retry-After", Math.ceil(windowMs / 1000));
      return res.status(429).json({ error: message });
    }
    list.push(now);
    hits.set(k, list);
    next();
  };
  // Socket olayları için: true dönerse izin var
  limiter.allow = (k) => {
    const now = Date.now();
    const list = (hits.get(k) || []).filter((t) => now - t < windowMs);
    if (list.length >= max) return false;
    list.push(now);
    hits.set(k, list);
    return true;
  };
  return limiter;
}

// CORS_ORIGIN boşsa sadece aynı adres (istemci zaten aynı sunucudan servis ediliyor).
// Geliştirmede Flutter dev sunucusu için: CORS_ORIGIN=http://localhost:5000,http://localhost:8080
function corsOrigins() {
  const raw = (process.env.CORS_ORIGIN || "").trim();
  if (!raw) return false;
  if (raw === "*") return "*";
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

// Basit sohbet filtresi: yaygın küfürleri yıldızlar. Liste ENV ile genişletilebilir.
const BASE_WORDS = ["amk", "aq", "orospu", "piç", "sik", "yarrak", "göt", "ananı", "siktir", "pezevenk", "kahpe", "fuck", "shit"];
const EXTRA = (process.env.CHAT_BLOCKLIST || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const WORDS = [...new Set([...BASE_WORDS, ...EXTRA])];
const PATTERN = new RegExp(`(^|[^\\p{L}])(${WORDS.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(?=[^\\p{L}]|$)`, "giu");

function cleanChat(text) {
  return String(text)
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 280)
    .replace(PATTERN, (m, pre, word) => pre + "*".repeat([...word].length));
}

module.exports = { rateLimit, corsOrigins, cleanChat };
