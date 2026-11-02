# Ekonomi Dengesi (v1)

Tüm sayılar tek dosyada: [`src/economy.js`](../src/economy.js).
Bir sayıyı değiştirdikten sonra şu komutu çalıştırıp sonuçların hedeflerin içinde kaldığını kontrol et:

```bash
node scripts/economy-sim.js
```

Simülasyon gerçek oyun kurallarını kullanır: fiyat etkisi, tüccar makası, vergi ve polis riski dahil.

---

## 1. Araştırma: benzer oyunlardan çıkan dersler

| Oyun | Ne bulduk | Bizdeki karşılığı |
|---|---|---|
| **Ticarium / Ticarion** (Yuyuto Games, Türk yapımı ticaret simülasyonu) | Oyuncu rehberlerinden: başlangıçta bedava bir manav veriliyor. Gündelik oynayan biri (3-5 saatte bir giriş) 1 mağazadan 3 mağazaya **yaklaşık bir ayda** çıkıyor. Her yeni mağaza için ayrı lisans alınıyor (para gideri). Rafların bekleme süresi 8 saat (VIP'te 12 saat). Erken dönemde para restoran ve ek işlerden, orta dönemde ihalelerden geliyor. | İşletmeler hızlı değil, **günler içinde** amorti olmalı. Hammadde ambarı en az **8 saat** yetmeli. Yeni işletme kurmak ciddi bir yatırım olmalı. |
| **Ticarium mağaza yorumları** | En sık şikayetler: "parayı veren kazanır" ve "30 dakikada bir girmezsen stok bitiyor, enerji doluyor, yeni oyuncuya düşmanca". | Parayla avantaj satılmayacak. Üretim **saatlerce kendi başına** çalışabilmeli. |
| **TürkMafya** (Venotti Games, metin tabanlı mafya RPG) | Kendi aileni kurup üye topluyor ve gerçek oyuncularla bölge savaşı yapıyorsun. Sayısal ekonomi verisine erişilemedi, mağaza sayfası erişimi engelliyor. | Aile ve bölge sistemi zaten var. Para gelirleri ticaret ve işletmeyle dengelenmeli. |
| **Torn** (20 yılı aşkın metin tabanlı suç MMO'su) | Seyahat ticaretinde kâr **taşıma kapasitesiyle** sınırlı (varsayılan 5 eşya). Şirket ve hisse gelirleri günlük ya da haftalık. Ekonomiyi elden çıkan benzer oyunlar kapanmış. | Sefer başı kâr, sermaye büyüdükçe sınırsız artmamalı. **Piyasa derinliği** bunu sınırlıyor. |
| **EVE Online / Albion** | Bölgesel fiyat farkı ticareti doğuruyor. Vergi ve komisyon paranın oyundan çıkmasını sağlıyor. Dengeyi kısıtlarla kurmak gerekiyor. | Tüccar makası %5 + semt vergisi + kira + rüşvet = para giderleri. |

Kaynaklar:
- Ticarium (App Store): https://apps.apple.com/us/app/-/id1620118127
- Ticarion (App Store): https://apps.apple.com/np/app/ticarion/id1631756903
- Ticarium başlangıç rehberi (video): https://www.youtube.com/watch?v=rOknq4XfxmE
- Ticarium başlangıç rehberi, 2. gün (video): https://www.youtube.com/watch?v=LhENIq-x1Kc
- TürkMafya (Google Play): https://play.google.com/store/apps/details?id=com.hurdijital.turkmafya
- Torn seyahat: https://wiki.torn.com/wiki/Travel
- Albion ekonomi dengesi (GDC): https://gdcvault.com/play/1024070/Balancing-the-Economy-for-Albion

---

## 2. Hedefler

| Ölçüt | Hedef | Neden |
|---|---|---|
| Gündelik oyuncu (günde ~12 sefer), 1. gün sonu | ₺12-15 bin | İlk işletmeyi 1-2 günde açabilsin, ilk gün zengin olmasın |
| Gündelik oyuncu, 7. gün sonu | ₺60-100 bin | Doğrusal büyüme, katlanarak değil |
| Sefer başı en iyi kâr | ₺400-800 (%10-20) | Sermaye büyüdükçe sınırsız artmasın (piyasa derinliği) |
| İşletme Sv1 amorti süresi (taban fiyatlarla) | 48-72 saat | Ticarium'daki gibi günler, saatler değil |
| Yükseltme amorti süresi | 60-100 saat | Azalan getiri |
| Ambar yetme süresi (Sv1) | ≥ 8 saat | "30 dakikada bir gir" şikayetini önlemek için |
| 4 işletmenin pasif geliri | gündelik aktif oyuncuya yakın | Hem aktif hem pasif oyun değerli olsun |
| Soygunun beklenen getirisi (20 enerji) | ≈ 2 ticaret seferi | Soygun ticaretten daha kârlı olmasın |

---

## 3. Önce ve sonra (simülasyon sonucu)

| Ölçüt | Önce | Sonra |
|---|---|---|
| Gündelik oyuncu, 1. gün sonu | **₺103.251** | ₺14.061 |
| Gündelik oyuncu, 7. gün sonu | **₺740.014** | ₺69.597 |
| Çok aktif oyuncu, 7. gün sonu | **₺1.854.350** | ₺166.785 |
| Sefer başı en iyi kâr (₺5 bin sermaye) | ₺4.584 (%98) | ₺679 (%18) |
| Sefer başı en iyi kâr (₺200 bin sermaye) | ₺8.844 | ₺771 |
| İmalathane amorti süresi | 6,3 saat | 51 saat |
| Atölye (radyo) amorti süresi | 7,3 saat | 56 saat |
| Matbaa amorti süresi | 3,0 saat | 58 saat |
| Kahvehane amorti süresi | 4,1 saat | 60 saat |
| Gece Kulübü amorti süresi | 3,9 saat | 61 saat |
| Ambar yetme süresi | 3,8-5 saat | 10-30 saat |

Günlük gelir karşılaştırması (sonra):

| Kaynak | Günlük |
|---|---|
| Ticaret, gündelik oyuncu (12 sefer) | ~₺9.250 |
| Ticaret, çok aktif oyuncu (30 sefer) | ~₺23.100 |
| 1 × İmalathane / Atölye / Matbaa / Kahvehane / Gece Kulübü (Sv1) | ₺1.870 / ₺2.570 / ₺2.080 / ₺1.200 / ₺3.120 |

---

## 4. Ne değişti

**Ticaret**
- Semtler arası fiyat farkı sıkıştırıldı: `çarpan^0.45`. Örneğin mücevher en ucuz ile en pahalı semt arasında 2,5 kat yerine ~1,5 kat fark ediyor.
- Tüccar makası %3'ten %5'e çıktı. Gidiş-dönüş yaklaşık %10 komisyon ediyor.
- **Piyasa derinliği** eklendi: her mal için fiyatı %10 kaydırmak için kaç birim gerektiği. Mücevher 8, silah 12, kahve 150, şeker 200 birim. Lüks malda tek seferde taşınabilecek kârlı miktar artık sınırlı.
- Fiyatların toparlanması yavaşladı: tick başına %8 yerine %1,5, yani yarılanma süresi ~7,5 dakika. Aynı rotayı hemen tekrar kullanmanın kazancı düşük.

**İşletmeler**
- Parti süreleri uzadı, saatlik net kâr maliyetin ~1/60'ı oldu:
  - İmalathane: 3 şeker → 1 içki, 30 dk
  - Atölye: 6 hurda → 1 radyo (1 saat), 6 hurda + 1 radyo → 1 silah (2 saat)
  - Matbaa: 8 kağıt → 1 belge, 4 saat
  - Kahvehane: 4 kahve → ₺255, 1 saat
  - Gece Kulübü: 3 içki → ₺560 + 4 nüfuz, 1 saat
- Kiralar düşürüldü (₺25-70/sa) ama kira hâlâ önemli bir para gideri.
- Malı doğru semtten alıp doğru semtte satan oyuncu amorti süresini 1-2 güne indirebiliyor, yani lojistik hâlâ ödüllendiriliyor.

**Soygun**
- Kurbanın parasının %10-20'si yerine %8-15'i. Üst sınır ₺2.000 + 400 × seviye yerine ₺1.500 + 300 × seviye.

---

## 5. Henüz yapılmadı

- **Gerçek oyuncu verisi:** Simülasyon "her seferde en iyi rotayı bilen" bir oyuncuyu varsayıyor. Kapalı betada gerçek ortalamalar ölçülmeli.
- **Admin ekonomi paneli:** Toplam para arzı, günlük para girişi ve çıkışı, mal başına ortalama fiyat.
- **Çanta yükseltmesi:** Piyasa derinliği kâr üst sınırını belirlediği için çanta büyütmek şu an az değerli. Araç yükseltmeleri eklenirse (daha hızlı yolculuk) bu tekrar değerlendirilmeli.
