# Underworld City — Oyun Tasarım Planı (v0.1)

> Tarayıcıda oynanan, online, **oyuncuların yönettiği ekonomi** üzerine kurulu bir ticaret ve strateji oyunu.
> Mevcut altyapı: Node.js + Express + Socket.io + PostgreSQL (`server.js`).

---

## 1. Araştırmadan çıkan dersler

| Örnek | Ne öğrendik | Bizde karşılığı |
|---|---|---|
| **Torn** (2004'ten beri yayında, günde 100 bin oyuncunun üstünde) | Yazı tabanlı ve hafif bir suç MMO'su 20 yıldan uzun yaşayabiliyor. Ayakta kalmasının sebepleri: oyuncuların yönettiği ekonomi, arada bir girip oynamaya uygun olması ve ekonominin sıkı yönetilmesi. Ekonomisi elden çıkan benzer oyunlar kapandı. | Grafik ağırlıklı değil, hafif bir web arayüzü. Ekonomiyi en baştan para giderleriyle (sink) dengelemek. |
| **EVE Online** | Fiyatlar bölgeye göre değişiyor ve bu fark ticareti doğuruyor. Vergi hem para gideri hem de ticareti merkezlere çeken bir araç. Tehlike her yerde aynı olursa herkes her işi yapar, uzmanlaşma olmaz. | Semtlere göre farklı arz ve talep. Riskli semtlerde daha yüksek kâr. Pazar vergisi. |
| **Albion Online** (GDC konuşması) | Pazarı oyuncuların yönettiği bir MMO'da denge "çapa" değerlerle (balance anchor) ve kısıtlarla kuruluyor. | Her malın bir taban fiyatı ve üretim maliyeti olsun. Dengeyi kısıtlarla (zaman, depo, risk) kurmak. |
| **Travian** | Sunucular yaklaşık bir yıl süren turlar halinde dönüyor ve oyun sona doğru büyük bir hedefle (World Wonder) bitiyor. Parayla alınabilen avantajlar oyun içinde de kazanılabiliyor. | Sezon sistemi. Sezon sonunda büyük bir hedef. Kazanmak için para ödemek gerekmesin (pay-to-win yok). |
| **Schedule I** (2025, suç ve işletme simülasyonu) | Suç ve işletme temalı oyunlar 2025'te Steam'de çok popüler oldu (kaynaktaki sayılar doğrulanmadı). | Tema ve tür tutuyor. Bizim farkımız bunun **çok oyunculu** olması. |

**Özet:** İnsanları oyunda tutan şey grafik değil. Tutan şeyler şunlar: **gerçek oyunculara karşı ticaret, çete/topluluk, kısa ama her gün girilen oturumlar ve adil sezonlar.**

---

## 2. Oyunun fikri (tek cümle)

**1930'ların hayali bir liman şehrinde sıfırdan başlıyorsun. Semtler arasında kaçak mal taşıyıp satıyor, işletme kurup üretim yapıyorsun. Bir çeteye katılıp semtlerin kontrolü için savaşıyorsun. Sezon sonunda şehrin "Baba"sı olmaya çalışıyorsun.**

Neden işe yarar: herkesin bildiği "ucuza al, pahalıya sat" mantığına risk (polis, soygun, rakip çete) ve sosyal rekabet ekleniyor.

---

## 3. Çekirdek oyun döngüsü

```
Günlük (5-15 dk):  Enerji harca → mal al → taşı (süre + risk) → sat → kâr
Haftalık:          İşletme kur/yükselt → üretim zinciri → pazarda emir ver
Sezonluk (8 hafta): Çete savaşları → semt kontrolü → sezon sıralaması → ödüller
```

### 3.1 Semtler (harita)
6 semtle başlıyoruz. Her semtin kendine ait **arz/talep profili**, **polis yoğunluğu** ve **vergisi** var:

| Semt | Ucuz olan | Pahalı olan | Polis | Not |
|---|---|---|---|---|
| Liman | Kaçak içki, tütün | — | Düşük | Malın şehre girdiği yer |
| Fabrika Bölgesi | Ham madde | Gıda | Orta | Üretim tesisleri burada |
| Çarşı | — | Her şey (orta) | Orta | Ana pazar merkezi, likidite yüksek |
| Villalar | — | Lüks mal, içki | Yüksek | En yüksek kâr, en yüksek risk |
| Gecekondu | İşgücü | Silah | Çok düşük | Soygun riski yüksek |
| Merkez | — | Rüşvet, bilgi | Çok yüksek | Siyasi binalar, sezon hedefi |

### 3.2 Mallar (MVP için 8 tane)
Kaçak içki, tütün, kahve, ilaç, elektronik (radyo), silah, mücevher, sahte belge.
Her malın:
- `base_price` (çapa fiyat)
- semte göre `supply` / `demand` değeri. NPC fiyatı bu ikisinden hesaplanır ve zamanla taban fiyata geri döner.
- `weight` (taşıma kapasitesini doldurur)
- `heat` (yanında taşıdığında polis riskini artırır)

### 3.3 Taşıma ve risk
- Semtler arası yolculuk **gerçek zamanlı** sürer (2-10 dk). Araç yükseltildikçe süre kısalır, kapasite artar.
- Yolda olabilecekler: polis araması (mal el konur ya da rüşvetle kurtulursun), başka oyuncunun soygunu, olaysız varış.
- Risk = `taşınan heat` × `semt polisi` − `rüşvet/koruma`.

### 3.4 Oyuncu pazarı
- Her semtte ayrı bir **emir defteri** (alış ve satış emirleri). EVE'deki gibi bölgesel çalışır.
- Satıştan %3 pazar vergisi alınır. Bu bir para gideridir. Semti kontrol eden çete verginin bir kısmını alır.
- NPC tüccarları likidite sağlar ama fiyatları kötüdür. Bu sayede oyuncular birbirleriyle ticaret yapmaya yönelir.

### 3.5 İşletmeler ve üretim
- Paravan işletmeler: Kahvehane, gece kulübü, depo, atölye.
- Üretim zinciri örneği: ham madde → atölye → radyo. Üretim zaman alır ve işletmenin bakım ücreti vardır.
- Depo, polis baskınlarından korunan güvenli stok alanı sağlar.

### 3.6 Çeteler (aileler)
- 5-30 kişilik gruplar. Ortak kasa ve rütbeler (Baba, Danışman, Kaptan, Asker) var.
- **Semt kontrolü:** Haftada bir yapılan "bölge savaşı". Katkı puanı belirleyicidir: semtte yapılan ticaret, adam sayısı ve savaşa harcanan kaynak.
- Semti kontrol eden çete, oradaki pazar vergisinden pay alır ve kendi üyelerine indirim verebilir.

### 3.7 Enerji ve aksiyon sistemi
- Kısa günlük oturumlar için **enerji** (örneğin 100 puan, saatte 10 dolar).
- Her aksiyonun bir enerji bedeli var. Böylece bütün gün başında oturan oyuncu, arada bir giren oyuncuyu ezemez.

### 3.8 Sezonlar (8 hafta)
- Sezon sonunda para, mal ve işletmeler **sıfırlanır**.
- **Kalıcı olanlar:** kozmetikler, unvanlar, "itibar" seviyesi (küçük kolaylıklar sağlar, güç vermez), çete adı ve geçmişi.
- **Sezon sonu hedefi:** Son haftalarda Merkez'de "Belediye"yi ele geçirmek. Kazanan çete Onur Listesi'ne yazılır.
- Her sezonda yeni bir kural (mutator) gelir: örneğin "İçki Yasağı Sezonu" (içki 3 kat pahalı, polis 2 kat).

---

## 4. Ekonomi dengesi (en önemli kısım)

**Paranın oyuna girdiği yerler (faucet):** NPC'ye satış, görev ödülleri, günlük giriş bonusu (küçük).

**Paranın oyundan çıktığı yerler (sink):** Pazar vergisi, rüşvet, polisin el koyması, işletme bakımı, araç yakıtı ve tamiri, kozmetik olmayan mağaza ürünleri.

Kurallar:
1. Her saat başı ekonomi raporu: toplam para arzı ve mal başına ortalama fiyat. Admin paneline düşer.
2. NPC fiyatları oyuncu hacmiyle değişir. Herkes aynı rotayı kullanırsa o rotanın kârı erir.
3. **Test endpoint'i olan `add-money` canlıda KAPALI olmalı.** Ekonomiyi tek başına bozar.

---

## 5. Gelir modeli (pay-to-win yok)
- Kozmetikler: karakter portresi, araç görünümü, çete arması.
- Sezon kartı (Battle pass): ücretsiz ve ücretli yol. Ücretli yolda sadece kozmetik ve küçük kolaylıklar var (örneğin ek emir yuvası).
- Enerji ya da para **satılmaz**. Torn ve Travian'daki gibi, parayla alınabilen her şey oyunda da kazanılabilir.

---

## 6. Teknik mimari

```
[Tarayıcı istemcisi: React/Vite veya düz HTML+JS]
        │  REST (aksiyonlar)      │  Socket.io (canlı fiyat, sohbet, olaylar)
        ▼                         ▼
[Node.js / Express API  +  Socket.io]  ──►  [PostgreSQL]
        │
        └── Tick işçisi (her 1 dk): yolculukları bitir, üretimi tamamla,
            NPC fiyatlarını güncelle, enerjiyi doldur
```

**Önemli prensip:** Bütün hesaplamalar sunucuda yapılır. İstemci sadece niyetini gönderir ("şunu al"). Para işlemleri DB transaction içinde ve `SELECT ... FOR UPDATE` ile yapılır. Böylece aynı anda gelen istekler para kopyalamaya (dupe) yol açamaz.

### Taslak tablolar
- `users`, `players` (var). `players`'a eklenecek alanlar: `energy`, `energy_updated_at`, `district_id`, `heat`, `gang_id`
- `districts` (id, name, police_level, tax_rate, controlling_gang_id)
- `goods` (id, name, base_price, weight, heat)
- `district_goods` (district_id, good_id, supply, demand, npc_price)
- `inventory` (player_id, good_id, qty)
- `market_orders` (id, player_id, district_id, good_id, side, price, qty, created_at)
- `trades` (log: buyer, seller, good, price, qty, ts)
- `travels` (player_id, from, to, depart_at, arrive_at, cargo_json, resolved)
- `businesses`, `gangs`, `gang_members`, `seasons`

---

## 7. Yol haritası

### Faz 0: Temizlik (1-2 gün)
- `server.js` içinde `initDB` iki kez tanımlanmış. JavaScript'te sonraki tanım öncekini ezdiği için **`items` ve `inventory` tabloları hiç oluşmuyor.** Tek fonksiyona indirilecek.
- `add-money` endpoint'i sadece geliştirme ortamında açık olacak.
- Klasör yapısı (`routes/`, `db/`, `game/`), migration sistemi, giriş için basit hız sınırı (rate limit).

### Faz 1: Oynanabilir MVP (2-3 hafta)
- Semtler, mallar, NPC al/sat, enerji
- Yolculuk ve risk sistemi, tick işçisi
- Basit web istemcisi: profil, semt ekranı, al/sat, yolculuk
- Genel sohbet (Socket.io bağlantısı zaten var)

### Faz 2: Oyuncu ekonomisi (2 hafta)
- Semt başına emir defteri, eşleşme motoru, vergi
- Canlı fiyat akışı (socket), fiyat grafiği
- Sıralama listeleri (servet, haftalık kâr)

### Faz 3: Sosyal ve strateji (3 hafta) — ✅ çeteler ve semt kontrolü yapıldı, PvP soygun sırada
- Çeteler, ortak kasa, çete sohbeti
- Semt kontrolü ve haftalık bölge savaşı
- Oyuncu soygunu (PvP), koruma

### Faz 4: Sezon ve canlı yayın (2 hafta)
- Sezon sıfırlama ve kalıcı ödüller, sezon kuralları (mutator)
- Admin ve ekonomi paneli
- Kapalı beta (Discord topluluğu ile)

---

## 8. Başarıyı nasıl ölçeceğiz
- 1., 7. ve 30. gün geri dönen oyuncu oranı (D1/D7/D30)
- Günlük ortalama oturum sayısı (hedef: günde 2 veya daha fazla kısa oturum)
- Para arzı ve enflasyon trendi
- Çetedeki oyuncu oranı (çetedeki oyuncu genelde daha uzun kalır)

---

## Kaynaklar
- Torn, 22. yılda günde 100 bin oyuncu: https://www.pocketgamer.biz/torn-rpg-surpasses-100000-daily-players-after-22-years-of-growth/
- Torn, 21. yıl röportajı: https://www.pocketgamer.com/torn/twenty-one-years-interview
- Albion Online ekonomi dengesi (GDC): https://gdcvault.com/play/1024070/Balancing-the-Economy-for-Albion
- EVE pazar tasarımı dersleri: https://pulsegeek.com/articles/case-study-eve-online-market-design-lessons
- EVE bölgesel pazar gözlemi: https://voices.uchicago.edu/202003sosc20224/2020/07/09/participant-observation-the-economy-of-eve-online
- Travian sezon yapısı: https://www.thedailystar.net/shout/game-review/news/slow-steady-and-fun-1829737
- Schedule I incelemesi: https://gamegeeker.com/it/games/schedule-i-3164500/review
