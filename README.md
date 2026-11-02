# Underworld City

1931'de, hayali bir liman şehrinde geçen online ticaret ve strateji oyunu. Semtler arasında mal taşıyıp satarsın; yolda polis ve soyguncular seni bekler.

Tasarım planı: [`docs/OYUN_PLANI.md`](docs/OYUN_PLANI.md)

| Giriş | Harita + Pazar | Mobil |
|---|---|---|
| ![](docs/screenshots/login.png) | ![](docs/screenshots/travel.png) | ![](docs/screenshots/mobile_map.png) |

## Yapı
- `server.js`, `src/`: Node.js + Express + Socket.io + PostgreSQL sunucusu
- `client/`: Flutter istemcisi (web, Android, iOS)

## Çalıştırma

```bash
# 1) Sunucu
cp .env.example .env   # DATABASE_URL ve JWT_SECRET'i doldur
npm install
npm start              # tablolar ve dünya verisi otomatik kurulur

# 2) İstemci (geliştirme)
cd client
flutter pub get
flutter run -d chrome --dart-define=API_URL=http://localhost:3000

# 3) Tek sunucudan yayınlama
cd client && flutter build web --release
# server.js, client/build/web klasörünü otomatik servis eder → http://localhost:3000
```

## API
| Metot | Yol | Açıklama |
|---|---|---|
| POST | `/api/register`, `/api/login` | `{username, password}` → `{token}` |
| GET | `/api/world` | Semtler ve mallar |
| GET | `/api/prices` | Tüm semtlerdeki al/sat fiyatları |
| GET | `/api/me` | Oyuncu durumu (para, enerji, çanta, yolculuk, son olay) |
| POST | `/api/trade` | `{goodId, qty, side: "buy"\|"sell"}` |
| POST | `/api/travel` | `{to}`: başka semte yola çık (10 enerji) |
| GET | `/api/leaderboard` | Servet sıralaması |

Socket.io olayları: `prices`, `price`, `chat`, `online`, `arrived`.
