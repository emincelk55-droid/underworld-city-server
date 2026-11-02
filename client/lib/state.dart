import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:socket_io_client/socket_io_client.dart' as io;

import 'models.dart';

class ApiException implements Exception {
  final String message;
  ApiException(this.message);
  @override
  String toString() => message;
}

/// Varsayılan sunucu adresi: `--dart-define=API_URL=...` ile verilebilir.
/// Web'de verilmezse istemciyi servis eden sunucu, mobilde Render adresi kullanılır.
/// Oyuncu giriş ekranından başka bir sunucu seçebilir (kaydedilir).
const defaultMobileServer = 'https://underworld-city.onrender.com';
String resolveApiUrl() {
  const fromEnv = String.fromEnvironment('API_URL');
  if (fromEnv.isNotEmpty) return fromEnv;
  if (kIsWeb && Uri.base.scheme.startsWith('http')) return Uri.base.origin;
  return defaultMobileServer;
}

/// "oyun.com", "192.168.1.5:3000" gibi girişleri tam adrese çevirir
String normalizeServerUrl(String input) {
  var u = input.trim();
  if (u.isEmpty) return resolveApiUrl();
  if (!u.startsWith('http://') && !u.startsWith('https://')) {
    final local = RegExp(r'^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)').hasMatch(u);
    u = '${local ? 'http' : 'https'}://$u';
  }
  while (u.endsWith('/')) {
    u = u.substring(0, u.length - 1);
  }
  return u;
}

class GameState extends ChangeNotifier {
  String baseUrl = resolveApiUrl();
  String? token;
  bool booting = true;

  List<District> districts = [];
  List<Good> goods = [];
  int travelEnergy = 10;
  Map<String, Map<String, Price>> prices = {};
  final Map<String, List<double>> history = {};
  PlayerState? me;
  List<LeaderRow> leaders = [];
  final List<ChatMessage> chat = [];
  int online = 0;

  // Çeteler ve bölgeler
  Map<String, Territory> territory = {};
  int controlMin = 100;
  List<TerritoryAction> territoryActions = [];
  List<GangListItem> gangs = [];
  GangDetail? myGang;
  List<NewsItem> news = [];
  int gangCreateCost = 2500;
  int unreadGangChat = 0;

  // Sokak / soygun
  StreetInfo? street;
  List<RobRecord> robRecords = [];
  Map<String, dynamic>? pendingRobbed;
  Timer? _streetTimer;

  // Borsa
  Map<String, MarketSummary> marketSummary = {};
  String? summaryDistrict;
  OrderBook? openBook;
  List<MyOrder> myOrders = [];
  List<StorageItem> storage = [];

  // İşletmeler
  List<BusinessType> businessTypes = [];
  List<Business> businesses = [];

  BusinessType? businessType(String id) {
    for (final t in businessTypes) {
      if (t.id == id) return t;
    }
    return null;
  }

  /// Ekranda gösterilecek kısa bildirimler (mesaj, hata mı)
  final List<(String, bool)> toasts = [];

  /// Yolculuk bitince gösterilecek olay (UI okur ve temizler).
  Map<String, dynamic>? pendingEvent;

  io.Socket? _socket;
  Timer? _arrivalTimer;

  District? district(String id) {
    for (final d in districts) {
      if (d.id == id) return d;
    }
    return null;
  }

  Good? good(String id) {
    for (final g in goods) {
      if (g.id == id) return g;
    }
    return null;
  }

  Price? price(String districtId, String goodId) => prices[districtId]?[goodId];

  // ====== HTTP ======
  Future<dynamic> _req(String method, String path, [Map<String, dynamic>? body]) async {
    final uri = Uri.parse('$baseUrl$path');
    final headers = {
      'content-type': 'application/json',
      if (token != null) 'authorization': 'Bearer $token',
    };
    late http.Response res;
    try {
      res = method == 'GET'
          ? await http.get(uri, headers: headers)
          : await http.post(uri, headers: headers, body: jsonEncode(body ?? {}));
    } catch (_) {
      throw ApiException('Sunucuya ulaşılamıyor');
    }
    final data = res.body.isEmpty ? null : jsonDecode(res.body);
    if (res.statusCode == 401 && token != null) {
      await logout();
      throw ApiException('Oturum süresi doldu, tekrar giriş yap');
    }
    if (res.statusCode >= 400) {
      throw ApiException(data is Map && data['error'] != null ? data['error'] : 'Hata (${res.statusCode})');
    }
    return data;
  }

  Future<void> boot() async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = prefs.getString('server_url') ?? baseUrl;
    token = prefs.getString('token');
    try {
      await _loadWorld();
      if (token != null) await _enterGame();
    } catch (_) {
      // Sunucu kapalıysa giriş ekranında hata gösterilir.
    }
    booting = false;
    notifyListeners();
  }

  /// Sunucuya ulaşılabiliyor mu? (Render ücretsiz planda ilk açılış ~1 dk sürebilir)
  Future<bool> ping([String? url]) async {
    try {
      final r = await http.get(Uri.parse('${url ?? baseUrl}/healthz')).timeout(const Duration(seconds: 75));
      return r.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Sunucuyu değiştir: bağlantıyı dener, başarılıysa kaydeder ve dünyayı yeniden yükler.
  Future<void> setServer(String input) async {
    final url = normalizeServerUrl(input);
    if (!await ping(url)) throw ApiException('Sunucuya ulaşılamadı: $url');
    final prefs = await SharedPreferences.getInstance();
    if (url != baseUrl) {
      // Hesaplar sunucuya özel: eski oturumu kapat
      await prefs.remove('token');
      token = null;
      me = null;
      _socket?.dispose();
      _socket = null;
    }
    baseUrl = url;
    await prefs.setString('server_url', url);
    districts = [];
    await _loadWorld();
    notifyListeners();
  }

  Future<void> _loadWorld() async {
    final w = await _req('GET', '/api/world');
    districts = (w['districts'] as List).map((e) => District.fromJson(e)).toList();
    goods = (w['goods'] as List).map((e) => Good.fromJson(e)).toList();
    travelEnergy = w['travelEnergy'] ?? 10;
    Price.spread = (w['npcSpread'] as num?)?.toDouble() ?? Price.spread;
    _applyPrices(await _req('GET', '/api/prices'));
  }

  Future<void> login(String username, String password, {bool register = false}) async {
    final r = await _req('POST', register ? '/api/register' : '/api/login',
        {'username': username, 'password': password});
    token = r['token'];
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', token!);
    if (districts.isEmpty) await _loadWorld();
    await _enterGame();
    notifyListeners();
  }

  Future<void> logout() async {
    token = null;
    me = null;
    _socket?.dispose();
    _socket = null;
    _arrivalTimer?.cancel();
    _streetTimer?.cancel();
    street = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
    notifyListeners();
  }

  Future<void> _enterGame() async {
    await refreshMe();
    _connectSocket();
    unawaited(loadLeaderboard());
    unawaited(loadTerritory());
    unawaited(loadNews());
    unawaited(loadGangs());
    unawaited(loadMyGang());
    unawaited(loadStreet());
    unawaited(loadMarketSummary());
    unawaited(loadMyMarket());
    unawaited(loadBusinessTypes());
    unawaited(loadBusinesses());
    _streetTimer?.cancel();
    _streetTimer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (token == null) return;
      unawaited(loadStreet().catchError((_) {}));
      if (businesses.isNotEmpty) unawaited(loadBusinesses().catchError((_) {}));
    });
  }

  // ====== BORSA ======
  Future<void> loadMarketSummary() async {
    final d = me?.districtId;
    if (d == null) return;
    final r = await _req('GET', '/api/market/summary/$d') as List;
    marketSummary = {for (final e in r) e['goodId'] as String: MarketSummary.fromJson(e)};
    summaryDistrict = d;
    notifyListeners();
  }

  Future<void> loadBook(String districtId, String goodId) async {
    openBook = OrderBook.fromJson(await _req('GET', '/api/market/book/$districtId/$goodId'));
    notifyListeners();
  }

  Future<void> loadMyMarket() async {
    final r = await Future.wait([_req('GET', '/api/market/orders'), _req('GET', '/api/storage')]);
    myOrders = (r[0] as List).map((e) => MyOrder.fromJson(e)).toList();
    storage = (r[1] as List).map((e) => StorageItem.fromJson(e)).toList();
    notifyListeners();
  }

  int storageQty(String districtId, String goodId) =>
      storage.where((s) => s.districtId == districtId && s.goodId == goodId).fold(0, (a, s) => a + s.qty);

  Future<void> _afterMarket(String districtId, String goodId) async {
    await refreshMe();
    await Future.wait([
      loadMyMarket(),
      loadMarketSummary(),
      if (openBook?.goodId == goodId && openBook?.districtId == districtId) loadBook(districtId, goodId),
    ]);
  }

  Future<Map<String, dynamic>> placeOrder(String goodId, String side, int price, int qty) async {
    final r = Map<String, dynamic>.from(
        await _req('POST', '/api/market/order', {'goodId': goodId, 'side': side, 'price': price, 'qty': qty}));
    await _afterMarket(r['districtId'], goodId);
    return r;
  }

  Future<void> cancelOrder(MyOrder o, {String? districtId, String? goodId}) async {
    final r = await _req('POST', '/api/market/cancel', {'orderId': o.id});
    await _afterMarket(r['districtId'], r['goodId']);
  }

  Future<int> collect(String goodId, {int? qty}) async {
    final r = await _req('POST', '/api/storage/collect', {'goodId': goodId, 'qty': ?qty});
    await _afterMarket(me!.districtId, goodId);
    return r['collected'] as int;
  }

  // ====== İŞLETMELER ======
  Future<void> loadBusinessTypes() async {
    businessTypes = (await _req('GET', '/api/business/types') as List).map((e) => BusinessType.fromJson(e)).toList();
    notifyListeners();
  }

  Future<void> loadBusinesses() async {
    businesses = (await _req('GET', '/api/businesses') as List).map((e) => Business.fromJson(e)).toList();
    notifyListeners();
  }

  Future<void> _afterBusiness() async {
    await refreshMe();
    await Future.wait([loadBusinesses(), loadMyMarket()]);
  }

  Future<void> buyBusiness(String type) async {
    await _req('POST', '/api/business/buy', {'type': type});
    await _afterBusiness();
  }

  Future<int> loadBusiness(int id, String goodId, int qty) async {
    final r = await _req('POST', '/api/business/$id/load', {'goodId': goodId, 'qty': qty});
    await _afterBusiness();
    return r['loaded'] as int;
  }

  Future<int> collectTill(int id) async {
    final r = await _req('POST', '/api/business/$id/collect');
    await _afterBusiness();
    return r['collected'] as int;
  }

  Future<void> upgradeBusiness(int id) async {
    await _req('POST', '/api/business/$id/upgrade');
    await _afterBusiness();
  }

  Future<void> setRecipe(int id, String recipeId) async {
    await _req('POST', '/api/business/$id/recipe', {'recipeId': recipeId});
    await _afterBusiness();
  }

  Future<int> sellBusiness(int id) async {
    final r = await _req('POST', '/api/business/$id/sell');
    await _afterBusiness();
    return r['received'] as int;
  }

  // ====== SOKAK ======
  Future<void> loadStreet() async {
    street = StreetInfo.fromJson(await _req('GET', '/api/street'));
    notifyListeners();
  }

  Future<void> loadRobRecords() async {
    robRecords = (await _req('GET', '/api/robberies') as List).map((e) => RobRecord.fromJson(e)).toList();
    notifyListeners();
  }

  Future<Map<String, dynamic>> rob(int targetId) async {
    final r = Map<String, dynamic>.from(await _req('POST', '/api/rob', {'targetId': targetId}));
    await refreshMe();
    await Future.wait([loadStreet(), loadRobRecords()]);
    return r;
  }

  // ====== ÇETE / BÖLGE ======
  void _applyTerritory(dynamic data) {
    final m = Map<String, dynamic>.from(data);
    territory = Map<String, dynamic>.from(m['districts'])
        .map((k, v) => MapEntry(k, Territory.fromJson(Map<String, dynamic>.from(v))));
    controlMin = m['controlMin'] ?? 100;
    territoryActions = Map<String, dynamic>.from(m['actions'] ?? {})
        .entries
        .map((e) => TerritoryAction(e.key, Map<String, dynamic>.from(e.value)))
        .toList();
  }

  Future<void> loadTerritory() async {
    _applyTerritory(await _req('GET', '/api/territory'));
    notifyListeners();
  }

  Future<void> loadNews() async {
    news = (await _req('GET', '/api/news') as List).map((e) => NewsItem.fromJson(e)).toList();
    notifyListeners();
  }

  Future<void> loadGangs() async {
    gangs = (await _req('GET', '/api/gangs') as List).map((e) => GangListItem.fromJson(e)).toList();
    final opts = await _req('GET', '/api/gang-options');
    gangCreateCost = opts['cost'] ?? gangCreateCost;
    notifyListeners();
  }

  Future<void> loadMyGang() async {
    final g = me?.gang;
    myGang = g == null ? null : GangDetail.fromJson(await _req('GET', '/api/gangs/${g.id}'));
    notifyListeners();
  }

  Future<void> _afterGangChange() async {
    await refreshMe();
    await Future.wait([loadMyGang(), loadGangs(), loadTerritory()]);
  }

  Future<void> createGang(String name, String tag, String color, String emblem, String motto) async {
    await _req('POST', '/api/gangs', {'name': name, 'tag': tag, 'color': color, 'emblem': emblem, 'motto': motto});
    await _afterGangChange();
  }

  Future<void> joinGang(int id) async {
    await _req('POST', '/api/gangs/$id/join');
    await _afterGangChange();
  }

  Future<void> leaveGang() async {
    await _req('POST', '/api/gang/leave');
    await _afterGangChange();
  }

  Future<void> kickMember(int userId) async {
    await _req('POST', '/api/gang/kick', {'userId': userId});
    await loadMyGang();
  }

  Future<void> setRank(int userId, String rank) async {
    await _req('POST', '/api/gang/rank', {'userId': userId, 'rank': rank});
    await _afterGangChange();
  }

  Future<void> gangBank(bool deposit, int amount) async {
    await _req('POST', deposit ? '/api/gang/deposit' : '/api/gang/withdraw', {'amount': amount});
    await refreshMe();
    await loadMyGang();
  }

  Future<Map<String, dynamic>> territoryAction(String action) async {
    final r = await _req('POST', '/api/territory/action', {'action': action});
    await refreshMe();
    await loadTerritory();
    return Map<String, dynamic>.from(r);
  }


  Future<void> refreshMe() async {
    final prev = me;
    me = PlayerState.fromJson(await _req('GET', '/api/me'));
    // Semt ya da yolculuk durumu değiştiyse sokaktakileri yenile
    if (prev != null && (prev.districtId != me!.districtId || (prev.travel == null) != (me!.travel == null))) {
      unawaited(loadStreet().catchError((_) {}));
      unawaited(loadMarketSummary().catchError((_) {}));
    }
    if (me!.lastEvent != null) pendingEvent = me!.lastEvent;
    if (me!.robbed != null) pendingRobbed = me!.robbed;
    _scheduleArrival();
    notifyListeners();
  }

  void _scheduleArrival() {
    _arrivalTimer?.cancel();
    final t = me?.travel;
    if (t == null) return;
    final wait = t.arriveAt.difference(DateTime.now()) + const Duration(milliseconds: 400);
    _arrivalTimer = Timer(wait.isNegative ? Duration.zero : wait, () => refreshMe());
  }

  Future<Map<String, dynamic>> trade(String goodId, int qty, String side) async {
    final r = await _req('POST', '/api/trade', {'goodId': goodId, 'qty': qty, 'side': side});
    await refreshMe();
    return Map<String, dynamic>.from(r);
  }

  Future<void> travel(String to) async {
    await _req('POST', '/api/travel', {'to': to});
    await refreshMe();
  }

  Future<void> loadLeaderboard() async {
    final r = await _req('GET', '/api/leaderboard') as List;
    leaders = r.map((e) => LeaderRow.fromJson(e)).toList();
    notifyListeners();
  }

  void sendChat(String text, {String channel = 'global'}) {
    if (text.trim().isEmpty) return;
    _socket?.emit('chat', {'text': text.trim(), 'channel': channel});
  }

  // ====== CANLI VERİ ======
  void _connectSocket() {
    _socket?.dispose();
    final s = io.io(
      baseUrl,
      io.OptionBuilder().setTransports(['websocket']).setAuth({'token': token}).disableAutoConnect().build(),
    );
    s.on('prices', (data) {
      _applyPrices(data);
      notifyListeners();
    });
    s.on('price', (data) {
      final d = data['districtId'] as String, g = data['goodId'] as String;
      final old = prices[d]?[g];
      if (old != null) {
        prices[d]![g] = Price.fromRaw((data['price'] as num).toDouble(), old.anchor);
        _pushHistory(d, g, prices[d]![g]!.mid);
        notifyListeners();
      }
    });
    s.on('chat', (data) {
      final channel = data['channel'] ?? 'global';
      chat.add(ChatMessage(data['from'] ?? '?', data['text'] ?? '', DateTime.tryParse(data['at'] ?? '') ?? DateTime.now(),
          channel: channel));
      if (channel == 'gang' && data['from'] != me?.username) unreadGangChat++;
      if (chat.length > 100) chat.removeAt(0);
      notifyListeners();
    });
    s.on('chat_error', (data) {
      toasts.add((data['error'] ?? 'Mesaj gönderilemedi', true));
      notifyListeners();
    });
    s.on('online', (n) {
      online = n is int ? n : 0;
      notifyListeners();
    });
    s.on('arrived', (_) async {
      await refreshMe();
      unawaited(loadStreet());
    });
    s.on('book', (data) {
      final d = data['districtId'], g = data['goodId'];
      if (d == me?.districtId) unawaited(loadMarketSummary().catchError((_) {}));
      if (openBook != null && openBook!.districtId == d && openBook!.goodId == g) {
        unawaited(loadBook(d, g).catchError((_) {}));
      }
    });
    s.on('order_filled', (data) async {
      final where = district(data['districtId'] ?? '')?.name ?? '';
      final verb = data['side'] == 'buy' ? 'Alış' : 'Satış';
      toasts.add(('$verb emrin doldu: ${data['qty']} ${data['goodName']} × ₺${data['avgPrice']} ($where)', false));
      await refreshMe();
      unawaited(loadMyMarket());
    });
    s.on('order_expired', (_) async {
      toasts.add(('Bir borsa emrinin süresi doldu ve iptal edildi', false));
      await refreshMe();
      unawaited(loadMyMarket());
    });
    s.on('business_raid', (data) async {
      final where = district(data['districtId'] ?? '')?.name ?? '';
      toasts.add(('Polis baskını! $where\'daki ${data['name']} 30 dakika kapalı, hammaddenin yarısına el konuldu', true));
      await loadBusinesses();
    });
    s.on('robbed', (_) async {
      await refreshMe();
      unawaited(loadRobRecords());
    });
    s.on('territory', (data) {
      _applyTerritory(data);
      notifyListeners();
    });
    s.on('news', (data) {
      news = (data as List).map((e) => NewsItem.fromJson(Map<String, dynamic>.from(e))).toList();
      unawaited(loadGangs());
      notifyListeners();
    });
    s.on('gang', (_) => _afterGangChange());
    s.connect();
    _socket = s;
  }

  void _applyPrices(dynamic data) {
    final map = Map<String, dynamic>.from(data);
    prices = map.map((d, goodsMap) => MapEntry(
          d,
          Map<String, dynamic>.from(goodsMap).map((g, p) => MapEntry(g, Price.fromJson(Map<String, dynamic>.from(p)))),
        ));
    prices.forEach((d, gm) => gm.forEach((g, p) => _pushHistory(d, g, p.mid)));
  }

  void _pushHistory(String d, String g, double v) {
    final list = history.putIfAbsent('$d:$g', () => []);
    list.add(v);
    if (list.length > 40) list.removeAt(0);
  }

  List<double> historyOf(String d, String g) => history['$d:$g'] ?? const [];
}
