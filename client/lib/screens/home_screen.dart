import 'dart:async';

import 'package:flutter/material.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/city_map.dart';
import '../widgets/deco.dart';
import '../widgets/crest.dart';
import 'gang_panel.dart';
import 'panels.dart';

class HomeScreen extends StatefulWidget {
  final GameState game;
  const HomeScreen({super.key, required this.game});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0; // dar ekran: 0 şehir, 1 pazar, 2 çanta, 3 sıralama, 4 sohbet
  int _sideTab = 0; // geniş ekran yan panel: 0 pazar, 1 çanta, 2 sıralama, 3 sohbet
  String? _selected;
  Timer? _ticker;
  bool _showingEvent = false;

  GameState get g => widget.game;

  @override
  void initState() {
    super.initState();
    g.addListener(_onGame);
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (g.me?.travel != null || (g.me?.energy ?? 100) < (g.me?.energyMax ?? 100)) setState(() {});
    });
    WidgetsBinding.instance.addPostFrameCallback((_) => _onGame());
  }

  @override
  void dispose() {
    g.removeListener(_onGame);
    _ticker?.cancel();
    super.dispose();
  }

  void _onGame() {
    final ev = g.pendingEvent;
    if (ev != null && !_showingEvent && mounted) {
      g.pendingEvent = null;
      _showingEvent = true;
      showDialog(context: context, builder: (_) => EventDialog(game: g, event: ev))
          .whenComplete(() => _showingEvent = false);
    }
  }

  void _toast(String msg, {bool error = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Row(children: [
        Icon(error ? Icons.error_outline : Icons.check_circle_outline, color: error ? UW.crimson : UW.emerald, size: 18),
        const SizedBox(width: 10),
        Expanded(child: Text(msg)),
      ]),
      duration: const Duration(seconds: 3),
    ));
  }

  Future<void> _go(District d) async {
    Navigator.of(context).maybePop();
    try {
      await g.travel(d.id);
      _toast('${d.name} yolundasın...');
    } catch (e) {
      _toast(e.toString(), error: true);
    }
  }

  void _openDistrict(District d) {
    setState(() => _selected = d.id);
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (_) => DistrictSheet(game: g, district: d, onGo: () => _go(d), toast: _toast),
    ).whenComplete(() => mounted ? setState(() => _selected = null) : null);
  }

  @override
  Widget build(BuildContext context) {
    final me = g.me!;
    return LayoutBuilder(builder: (context, box) {
      final wide = box.maxWidth >= 980;
      final map = _MapView(game: g, selected: _selected, onTap: _openDistrict);
      final panels = [
        MarketPanel(game: g, toast: _toast),
        InventoryPanel(game: g, toast: _toast),
        GangPanel(game: g, toast: _toast),
        LeaderboardPanel(game: g),
        ChatPanel(game: g),
      ];

      return Scaffold(
        body: Stack(children: [
          Positioned.fill(child: Container(color: UW.ink)),
          SafeArea(
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Hud(game: g, me: me),
              Expanded(
                child: wide
                    ? Row(children: [
                        Expanded(flex: 3, child: Padding(padding: const EdgeInsets.fromLTRB(12, 0, 6, 12), child: map)),
                        SizedBox(
                          width: 440,
                          child: Padding(
                            padding: const EdgeInsets.fromLTRB(6, 0, 12, 12),
                            child: Column(children: [
                              _SideTabs(
                                index: _sideTab,
                                onChanged: (i) => setState(() => _sideTab = i),
                                labels: const ['Pazar', 'Çanta', 'Aile', 'Sıralama', 'Sohbet'],
                                icons: const [Icons.storefront, Icons.work_outline, Icons.shield_outlined, Icons.emoji_events_outlined, Icons.forum_outlined],
                              ),
                              const SizedBox(height: 10),
                              Expanded(child: IndexedStack(index: _sideTab, children: panels)),
                            ]),
                          ),
                        ),
                      ])
                    : Padding(
                        padding: const EdgeInsets.fromLTRB(10, 0, 10, 8),
                        child: IndexedStack(index: _tab, children: [map, ...panels]),
                      ),
              ),
            ]),
          ),
        ]),
        bottomNavigationBar: wide
            ? null
            : _BottomNav(
                index: _tab,
                onChanged: (i) => setState(() => _tab = i),
              ),
      );
    });
  }
}

class _MapView extends StatelessWidget {
  final GameState game;
  final String? selected;
  final ValueChanged<District> onTap;
  const _MapView({required this.game, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    final travel = me.travel;
    final here = game.district(me.districtId);
    return ClipRRect(
      borderRadius: BorderRadius.circular(6),
      child: Container(
        decoration: BoxDecoration(border: Border.all(color: UW.gold.withValues(alpha: 0.35))),
        child: Stack(children: [
          Positioned.fill(
            child: CityMap(
              districts: game.districts,
              currentId: me.districtId,
              selectedId: selected,
              travel: travel,
              territory: game.territory,
              myGangId: me.gang?.id,
              onTap: onTap,
            ),
          ),
          if (game.news.isNotEmpty)
            Positioned(
              right: 12,
              top: 12,
              left: MediaQuery.sizeOf(context).width < 600 ? 12 : null,
              child: Padding(
                padding: EdgeInsets.only(top: MediaQuery.sizeOf(context).width < 600 ? 44 : 0),
                child: Align(alignment: Alignment.topRight, child: NewsTicker(news: game.news)),
              ),
            ),
          Positioned(
            left: 14,
            top: 12,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              GoldText('UNDERWORLD CITY', style: UW.display(15, weight: FontWeight.w900)),
              Text('Şehir Haritası · Semte dokun', style: UW.body(11, color: UW.muted)),
            ]),
          ),
          if (travel != null)
            Positioned(left: 12, right: 12, bottom: 12, child: _TravelBanner(game: game, travel: travel))
          else if (here != null)
            Positioned(
              left: 12,
              bottom: 12,
              child: DecoPanel(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                accent: hexColor(here.color),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  Icon(Icons.place, color: hexColor(here.color), size: 18),
                  const SizedBox(width: 8),
                  Text('Konum: ', style: UW.body(12, color: UW.muted)),
                  Text(here.name, style: UW.serif(14, color: UW.goldLight)),
                ]),
              ),
            ),
        ]),
      ),
    );
  }
}

class _TravelBanner extends StatelessWidget {
  final GameState game;
  final Travel travel;
  const _TravelBanner({required this.game, required this.travel});

  @override
  Widget build(BuildContext context) {
    final now = DateTime.now();
    final rem = travel.remaining(now);
    final to = game.district(travel.to);
    final mm = rem.inMinutes, ss = (rem.inSeconds % 60).toString().padLeft(2, '0');
    return DecoPanel(
      glow: true,
      padding: const EdgeInsets.fromLTRB(14, 10, 14, 12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          const Icon(Icons.directions_car_filled, color: UW.goldLight, size: 18),
          const SizedBox(width: 8),
          Expanded(child: Text('${to?.name ?? ''} yolundasın', style: UW.serif(15, color: UW.goldLight))),
          Text('$mm:$ss', style: UW.number(16, color: UW.goldLight)),
        ]),
        const SizedBox(height: 8),
        ClipRRect(
          borderRadius: BorderRadius.circular(3),
          child: LinearProgressIndicator(
            value: travel.progress(now),
            minHeight: 6,
            backgroundColor: Colors.black54,
            valueColor: const AlwaysStoppedAnimation(UW.gold),
          ),
        ),
      ]),
    );
  }
}

class Hud extends StatelessWidget {
  final GameState game;
  final PlayerState me;
  const Hud({super.key, required this.game, required this.me});

  @override
  Widget build(BuildContext context) {
    final narrow = MediaQuery.sizeOf(context).width < 600;
    return Container(
      margin: const EdgeInsets.fromLTRB(10, 10, 10, 10),
      child: DecoPanel(
        padding: EdgeInsets.symmetric(horizontal: narrow ? 12 : 18, vertical: 10),
        child: Wrap(
          alignment: WrapAlignment.spaceBetween,
          crossAxisAlignment: WrapCrossAlignment.center,
          runSpacing: 10,
          spacing: 16,
          children: [
            Row(mainAxisSize: MainAxisSize.min, children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: UW.goldGradient,
                  boxShadow: [BoxShadow(color: UW.gold.withValues(alpha: 0.4), blurRadius: 12)],
                ),
                alignment: Alignment.center,
                child: Text(me.username.isEmpty ? '?' : me.username[0].toUpperCase(),
                    style: UW.display(18, color: UW.ink, weight: FontWeight.w900)),
              ),
              const SizedBox(width: 10),
              Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
                Row(mainAxisSize: MainAxisSize.min, children: [
                  if (me.gang != null) ...[
                    GangCrest(color: me.gang!.color, emblem: me.gang!.emblem, tag: me.gang!.tag, size: 18),
                    const SizedBox(width: 6),
                    Text('[${me.gang!.tag}] ', style: UW.display(13, color: hexColor(me.gang!.color), weight: FontWeight.w900)),
                  ],
                  Text(me.username, style: UW.serif(16)),
                ]),
                Text('Seviye ${me.level}  ·  ${game.online} çevrimiçi', style: UW.body(11, color: UW.muted)),
              ]),
            ]),
            Row(mainAxisSize: MainAxisSize.min, children: [
              const Icon(Icons.account_balance_wallet_outlined, color: UW.gold, size: 20),
              const SizedBox(width: 8),
              GoldText(formatMoney(me.money), style: UW.number(narrow ? 20 : 24, weight: FontWeight.w800)),
            ]),
            Row(mainAxisSize: MainAxisSize.min, children: [
              Tooltip(message: 'Enerji', child: StatBar(icon: Icons.bolt, label: '${me.energy}/${me.energyMax}', value: me.energy / me.energyMax, color: UW.neon)),
              SizedBox(width: narrow ? 4 : 14),
              StatBar(icon: Icons.inventory_2_outlined, label: '${me.load}/${me.capacity} kg', value: me.load / me.capacity, color: UW.gold),
              SizedBox(width: narrow ? 4 : 14),
              Tooltip(
                message: 'Dikkat: Yanındaki kaçak malın polis riski',
                child: StatBar(
                    icon: Icons.local_fire_department,
                    label: 'Isı ${me.heat}',
                    value: me.heat / 90,
                    color: me.heat > 45 ? UW.crimson : const Color(0xFFE09F3E)),
              ),
              IconButton(
                visualDensity: VisualDensity.compact,
                tooltip: 'Çıkış',
                onPressed: game.logout,
                icon: Icon(Icons.logout, size: 18, color: UW.muted.withValues(alpha: 0.8)),
              ),
            ]),
          ],
        ),
      ),
    );
  }
}

class _SideTabs extends StatelessWidget {
  final int index;
  final ValueChanged<int> onChanged;
  final List<String> labels;
  final List<IconData> icons;
  const _SideTabs({required this.index, required this.onChanged, required this.labels, required this.icons});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: List.generate(labels.length, (i) {
        final sel = i == index;
        return Expanded(
          child: GestureDetector(
            onTap: () => onChanged(i),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              margin: EdgeInsets.only(right: i < labels.length - 1 ? 6 : 0),
              padding: const EdgeInsets.symmetric(vertical: 10),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                gradient: sel ? UW.goldGradient : null,
                color: sel ? null : UW.panel,
                border: Border.all(color: UW.gold.withValues(alpha: sel ? 1 : 0.3)),
              ),
              child: Column(children: [
                Icon(icons[i], size: 18, color: sel ? UW.ink : UW.gold),
                const SizedBox(height: 2),
                Text(labels[i].toUpperCase(), style: UW.display(10, color: sel ? UW.ink : UW.cream, weight: FontWeight.w800)),
              ]),
            ),
          ),
        );
      }),
    );
  }
}

class _BottomNav extends StatelessWidget {
  final int index;
  final ValueChanged<int> onChanged;
  const _BottomNav({required this.index, required this.onChanged});

  static const _items = [
    (Icons.map_outlined, 'Şehir'),
    (Icons.storefront, 'Pazar'),
    (Icons.work_outline, 'Çanta'),
    (Icons.shield_outlined, 'Aile'),
    (Icons.emoji_events_outlined, 'Sıralama'),
    (Icons.forum_outlined, 'Sohbet'),
  ];

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: UW.night,
        border: Border(top: BorderSide(color: UW.gold.withValues(alpha: 0.4))),
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: List.generate(_items.length, (i) {
            final sel = i == index;
            return Expanded(
              child: InkWell(
                onTap: () => onChanged(i),
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 9),
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
                    AnimatedContainer(
                      duration: const Duration(milliseconds: 180),
                      width: sel ? 26 : 0,
                      height: 2,
                      margin: const EdgeInsets.only(bottom: 5),
                      color: UW.gold,
                    ),
                    Icon(_items[i].$1, color: sel ? UW.goldLight : UW.muted, size: 22),
                    const SizedBox(height: 3),
                    Text(_items[i].$2.toUpperCase(),
                        style: UW.display(9, color: sel ? UW.goldLight : UW.muted, weight: FontWeight.w800)),
                  ]),
                ),
              ),
            );
          }),
        ),
      ),
    );
  }
}
