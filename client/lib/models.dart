class District {
  final String id, name, color, description;
  final double police, tax, x, y;
  District.fromJson(Map<String, dynamic> j)
      : id = j['id'],
        name = j['name'],
        color = j['color'],
        description = j['description'] ?? '',
        police = (j['police'] as num).toDouble(),
        tax = (j['tax'] as num).toDouble(),
        x = (j['x'] as num).toDouble(),
        y = (j['y'] as num).toDouble();
}

class Good {
  final String id, name, icon;
  final int basePrice, weight, heat;
  Good.fromJson(Map<String, dynamic> j)
      : id = j['id'],
        name = j['name'],
        icon = j['icon'],
        basePrice = j['basePrice'],
        weight = j['weight'],
        heat = j['heat'];
}

class Price {
  final double buy, sell, anchor;
  const Price(this.buy, this.sell, this.anchor);
  factory Price.fromJson(Map<String, dynamic> j) =>
      Price((j['buy'] as num).toDouble(), (j['sell'] as num).toDouble(), (j['anchor'] as num).toDouble());
  factory Price.fromRaw(double raw, double anchor) => Price(raw * 1.03, raw * 0.97, anchor);
  double get mid => (buy + sell) / 2;
}

class Travel {
  final String from, to;
  final DateTime departAt, arriveAt;
  Travel.fromJson(Map<String, dynamic> j)
      : from = j['from'],
        to = j['to'],
        departAt = DateTime.parse(j['departAt']),
        arriveAt = DateTime.parse(j['arriveAt']);

  double progress(DateTime now) {
    final total = arriveAt.difference(departAt).inMilliseconds;
    if (total <= 0) return 1;
    return (now.difference(departAt).inMilliseconds / total).clamp(0.0, 1.0);
  }

  Duration remaining(DateTime now) {
    final d = arriveAt.difference(now);
    return d.isNegative ? Duration.zero : d;
  }
}

class Holding {
  final String goodId;
  final int qty;
  final double avgCost;
  Holding.fromJson(Map<String, dynamic> j)
      : goodId = j['goodId'],
        qty = j['qty'],
        avgCost = (j['avgCost'] as num).toDouble();
}

class PlayerState {
  final String username, districtId;
  final int money, xp, level, energy, energyMax, capacity, load, heat;
  final List<Holding> inventory;
  final Travel? travel;
  final Map<String, dynamic>? lastEvent;

  PlayerState.fromJson(Map<String, dynamic> j)
      : username = j['username'],
        districtId = j['districtId'],
        money = (j['money'] as num).toInt(),
        xp = j['xp'],
        level = j['level'],
        energy = j['energy'],
        energyMax = j['energyMax'],
        capacity = j['capacity'],
        load = j['load'],
        heat = j['heat'],
        inventory = (j['inventory'] as List).map((e) => Holding.fromJson(e)).toList(),
        travel = j['travel'] == null ? null : Travel.fromJson(j['travel']),
        lastEvent = j['lastEvent'];

  int qtyOf(String goodId) =>
      inventory.where((h) => h.goodId == goodId).fold(0, (s, h) => s + h.qty);
  Holding? holding(String goodId) {
    for (final h in inventory) {
      if (h.goodId == goodId) return h;
    }
    return null;
  }
}

class ChatMessage {
  final String from, text;
  final DateTime at;
  ChatMessage(this.from, this.text, this.at);
}

class LeaderRow {
  final int rank, netWorth, level;
  final String username;
  LeaderRow.fromJson(Map<String, dynamic> j)
      : rank = j['rank'],
        netWorth = (j['netWorth'] as num).toInt(),
        level = j['level'],
        username = j['username'];
}
