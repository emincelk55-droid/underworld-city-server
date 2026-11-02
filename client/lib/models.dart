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
  final MyGang? gang;
  final Map<String, dynamic>? lastEvent;
  final Map<String, dynamic>? robbed;
  final DateTime? protectedUntil;

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
        gang = j['gang'] == null ? null : MyGang.fromJson(j['gang']),
        lastEvent = j['lastEvent'],
        robbed = j['robbed'],
        protectedUntil = j['protectedUntil'] == null ? null : DateTime.parse(j['protectedUntil']);

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
  final String from, text, channel;
  final DateTime at;
  ChatMessage(this.from, this.text, this.at, {this.channel = 'global'});
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

// ====================== ÇETELER ======================
class GangRef {
  final int id;
  final String name, tag, color, emblem;
  GangRef.fromJson(Map<String, dynamic> j)
      : id = j['id'],
        name = j['name'],
        tag = j['tag'],
        color = j['color'],
        emblem = j['emblem'] ?? 'star';
}

class MyGang extends GangRef {
  final String rank;
  final int bank;
  MyGang.fromJson(super.j)
      : rank = j['rank'],
        bank = (j['bank'] as num).toInt(),
        super.fromJson();
  bool get canManage => rank == 'boss' || rank == 'underboss';
  bool get isBoss => rank == 'boss';
}

class GangListItem extends GangRef {
  final String motto;
  final int members, maxMembers, territories, influence;
  GangListItem.fromJson(super.j)
      : motto = j['motto'] ?? '',
        members = j['members'],
        maxMembers = j['maxMembers'],
        territories = j['territories'],
        influence = (j['influence'] as num).round(),
        super.fromJson();
}

class GangMember {
  final int userId, contribution, level;
  final String username, rank, rankName, districtId;
  GangMember.fromJson(Map<String, dynamic> j)
      : userId = j['userId'],
        contribution = j['contribution'],
        level = j['level'],
        username = j['username'],
        rank = j['rank'],
        rankName = j['rankName'],
        districtId = j['districtId'];
}

class GangDetail extends GangRef {
  final String motto;
  final int bank, maxMembers;
  final List<String> territories;
  final List<GangMember> members;
  GangDetail.fromJson(super.j)
      : motto = j['motto'] ?? '',
        bank = (j['bank'] as num).toInt(),
        maxMembers = j['maxMembers'],
        territories = List<String>.from(j['territories']),
        members = (j['members'] as List).map((e) => GangMember.fromJson(e)).toList(),
        super.fromJson();
}

class Influence extends GangRef {
  final int points;
  Influence.fromJson(super.j)
      : points = (j['points'] as num).toInt(),
        super.fromJson();
}

class Territory {
  final DateTime? warEndsAt;
  final GangRef? controller;
  final List<Influence> influence;
  Territory.fromJson(Map<String, dynamic> j)
      : warEndsAt = j['warEndsAt'] == null ? null : DateTime.parse(j['warEndsAt']),
        controller = j['controller'] == null ? null : GangRef.fromJson(j['controller']),
        influence = (j['influence'] as List).map((e) => Influence.fromJson(e)).toList();

  /// İlk iki çete birbirine yakınsa semtte çatışma var.
  bool get contested =>
      influence.length >= 2 && influence[1].points >= 30 && influence[1].points >= influence[0].points * 0.7;
}

class TerritoryAction {
  final String id, name, desc;
  final int energy, money;
  TerritoryAction(this.id, Map<String, dynamic> j)
      : name = j['name'],
        desc = j['desc'],
        energy = j['energy'],
        money = j['money'];
}

class NewsItem {
  final int id;
  final String text, kind;
  final DateTime at;
  NewsItem.fromJson(Map<String, dynamic> j)
      : id = j['id'],
        text = j['text'],
        kind = j['kind'],
        at = DateTime.parse(j['at']);
}

// ====================== SOKAK / SOYGUN ======================
class StreetPerson {
  final int userId, level, odds;
  final String username, wealth;
  final bool online, ally, revenge;
  final GangRef? gang;
  final DateTime? protectedUntil;
  StreetPerson.fromJson(Map<String, dynamic> j)
      : userId = j['userId'],
        level = j['level'],
        odds = j['odds'],
        username = j['username'],
        wealth = j['wealth'],
        online = j['online'] ?? false,
        ally = j['ally'] ?? false,
        revenge = j['revenge'] ?? false,
        gang = j['gang'] == null ? null : GangRef.fromJson(j['gang']),
        protectedUntil = j['protectedUntil'] == null ? null : DateTime.parse(j['protectedUntil']);

  bool get isProtected => protectedUntil != null && protectedUntil!.isAfter(DateTime.now());
  bool get robbable => !ally && !isProtected;
}

class StreetInfo {
  final String districtId;
  final bool traveling;
  final int robEnergy, policeRisk;
  final List<StreetPerson> people;
  StreetInfo.fromJson(Map<String, dynamic> j)
      : districtId = j['districtId'],
        traveling = j['traveling'] ?? false,
        robEnergy = j['robEnergy'],
        policeRisk = j['policeRisk'],
        people = (j['people'] as List).map((e) => StreetPerson.fromJson(e)).toList();
}

class RobRecord {
  final int id, cash;
  final bool mine;
  final String attacker, target, outcome, districtId;
  final List goods;
  final DateTime at;
  RobRecord.fromJson(Map<String, dynamic> j)
      : id = j['id'],
        cash = (j['cash'] as num).toInt(),
        mine = j['mine'],
        attacker = j['attacker'],
        target = j['target'],
        outcome = j['outcome'],
        districtId = j['districtId'],
        goods = j['goods'] ?? const [],
        at = DateTime.parse(j['at']);
}
