import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/deco.dart';
import '../widgets/crest.dart';
import 'gang_panel.dart';

typedef Toast = void Function(String msg, {bool error});

// ====================== PAZAR ======================
class MarketPanel extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const MarketPanel({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    final d = game.district(me.districtId);
    if (d == null) return const SizedBox();
    final c = hexColor(d.color);
    final traveling = me.travel != null;

    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(6),
          gradient: LinearGradient(colors: [Color.lerp(c, Colors.black, 0.55)!, UW.panel]),
          border: Border.all(color: c.withValues(alpha: 0.6)),
          boxShadow: [BoxShadow(color: c.withValues(alpha: 0.2), blurRadius: 20)],
        ),
        child: Row(children: [
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${d.name.toUpperCase()} PAZARI', style: UW.display(16, color: UW.goldLight, weight: FontWeight.w900)),
            const SizedBox(height: 4),
            Text(d.description, style: UW.serif(12, color: UW.cream.withValues(alpha: 0.75), weight: FontWeight.w400)),
          ]).expanded(),
          Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
            Chip2('Polis %${(d.police * 100).round()}', icon: Icons.local_police, color: UW.crimson),
            const SizedBox(height: 4),
            Chip2('Vergi %${(d.tax * 100).round()}', icon: Icons.account_balance, color: UW.gold),
          ]),
        ]),
      ),
      const SizedBox(height: 10),
      Expanded(
        child: Stack(children: [
          ListView.separated(
            itemCount: game.goods.length,
            separatorBuilder: (_, _) => const SizedBox(height: 8),
            itemBuilder: (_, i) {
              final good = game.goods[i];
              return _GoodRow(
                game: game,
                good: good,
                districtId: d.id,
                onTap: traveling
                    ? null
                    : () => showModalBottomSheet(
                          context: context,
                          isScrollControlled: true,
                          backgroundColor: Colors.transparent,
                          builder: (_) => TradeSheet(game: game, good: good, toast: toast),
                        ),
              );
            },
          ),
          if (traveling)
            Positioned.fill(
              child: Container(
                color: UW.ink.withValues(alpha: 0.75),
                alignment: Alignment.center,
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  const Icon(Icons.directions_car_filled, color: UW.gold, size: 42),
                  const SizedBox(height: 8),
                  Text('Yoldasın', style: UW.display(18, color: UW.goldLight)),
                  Text('Varınca ticaret yapabilirsin', style: UW.body(13, color: UW.muted)),
                ]),
              ),
            ),
        ]),
      ),
    ]);
  }
}

extension on Widget {
  Widget expanded() => Expanded(child: this);
}

class _GoodRow extends StatelessWidget {
  final GameState game;
  final Good good;
  final String districtId;
  final VoidCallback? onTap;
  const _GoodRow({required this.game, required this.good, required this.districtId, this.onTap});

  @override
  Widget build(BuildContext context) {
    final p = game.price(districtId, good.id);
    if (p == null) return const SizedBox();
    final ratio = p.mid / good.basePrice;
    final h = game.me!.holding(good.id);
    final pl = h == null ? null : (p.sell - h.avgCost) / h.avgCost;

    String? tag;
    Color tagColor = UW.muted;
    if (ratio < 0.85) {
      tag = 'UCUZ';
      tagColor = UW.emerald;
    } else if (ratio > 1.2) {
      tag = 'PAHALI';
      tagColor = UW.goldLight;
    }

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(6),
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(6),
            gradient: const LinearGradient(colors: [UW.panelHi, UW.panel]),
            border: Border.all(color: UW.gold.withValues(alpha: 0.18)),
          ),
          child: Row(children: [
            GoodIcon(good.icon),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Flexible(child: Text(good.name, style: UW.serif(15), overflow: TextOverflow.ellipsis)),
                  if (tag != null) ...[const SizedBox(width: 6), Chip2(tag, color: tagColor)],
                ]),
                const SizedBox(height: 5),
                Wrap(spacing: 5, runSpacing: 4, children: [
                  Chip2('${good.weight} kg', icon: Icons.scale),
                  if (good.heat > 0)
                    Chip2('${good.heat}', icon: Icons.local_fire_department, color: good.heat >= 5 ? UW.crimson : const Color(0xFFE09F3E)),
                  if (h != null)
                    Chip2('${h.qty} adet  ${pl! >= 0 ? '+' : ''}${(pl * 100).toStringAsFixed(0)}%',
                        icon: Icons.work_outline, color: pl >= 0 ? UW.emerald : UW.crimson),
                ]),
              ]),
            ),
            const SizedBox(width: 8),
            Sparkline(game.historyOf(districtId, good.id)),
            const SizedBox(width: 10),
            SizedBox(
              width: 82,
              child: Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                Text('AL', style: UW.display(9, color: UW.muted)),
                Text(formatMoney(p.buy), style: UW.number(14, color: UW.goldLight)),
                const SizedBox(height: 3),
                Text('SAT', style: UW.display(9, color: UW.muted)),
                Text(formatMoney(p.sell), style: UW.number(13, color: UW.cream.withValues(alpha: 0.85))),
              ]),
            ),
          ]),
        ),
      ),
    );
  }
}

// ====================== ALIM / SATIM ======================
class TradeSheet extends StatefulWidget {
  final GameState game;
  final Good good;
  final Toast toast;
  final String initialSide;
  const TradeSheet({super.key, required this.game, required this.good, required this.toast, this.initialSide = 'buy'});

  @override
  State<TradeSheet> createState() => _TradeSheetState();
}

class _TradeSheetState extends State<TradeSheet> {
  late String side = widget.initialSide;
  int qty = 1;
  bool busy = false;

  int _max(PlayerState me, Price p) {
    if (side == 'sell') return me.qtyOf(widget.good.id);
    final byMoney = (me.money / (p.buy * 1.02)).floor();
    final free = me.capacity - me.load;
    final byCap = widget.good.weight == 0 ? 1000 : (free / widget.good.weight).floor();
    return math.max(0, math.min(1000, math.min(byMoney, byCap)));
  }

  Future<void> _confirm() async {
    setState(() => busy = true);
    try {
      final r = await widget.game.trade(widget.good.id, qty, side);
      if (!mounted) return;
      Navigator.pop(context);
      final verb = side == 'buy' ? 'aldın' : 'sattın';
      final tax = (r['tax'] ?? 0) as num;
      widget.toast('$qty ${widget.good.name} $verb: ${formatMoney(r['total'] as num)}${tax > 0 ? ' (vergi ${formatMoney(tax)})' : ''}');
    } catch (e) {
      widget.toast(e.toString(), error: true);
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    return ListenableBuilder(
      listenable: g,
      builder: (context, _) {
        final me = g.me!;
        final p = g.price(me.districtId, widget.good.id)!;
        final max = _max(me, p);
        if (qty > max) qty = math.max(1, max);
        final unit = side == 'buy' ? p.buy : p.sell;
        final d = g.district(me.districtId)!;
        final total = unit * qty * (side == 'sell' ? (1 - d.tax) : 1);
        final h = me.holding(widget.good.id);
        final c = side == 'buy' ? UW.emerald : UW.crimson;

        return Padding(
          padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
          child: Center(
            heightFactor: 1,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 520),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: DecoPanel(
                  glow: true,
                  padding: const EdgeInsets.fromLTRB(20, 20, 20, 16),
                  child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    Row(children: [
                      GoodIcon(widget.good.icon, size: 56),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Text(widget.good.name, style: UW.serif(20)),
                          Text('Taban fiyat ${formatMoney(widget.good.basePrice)}  ·  Elinde ${h?.qty ?? 0}',
                              style: UW.body(12, color: UW.muted)),
                          if (h != null) Text('Ortalama maliyetin ${formatMoney(h.avgCost)}', style: UW.body(12, color: UW.muted)),
                        ]),
                      ),
                    ]),
                    const SizedBox(height: 16),
                    SegmentedButton<String>(
                      segments: const [
                        ButtonSegment(value: 'buy', label: Text('AL'), icon: Icon(Icons.add_shopping_cart)),
                        ButtonSegment(value: 'sell', label: Text('SAT'), icon: Icon(Icons.sell_outlined)),
                      ],
                      selected: {side},
                      onSelectionChanged: (s) => setState(() {
                        side = s.first;
                        qty = 1;
                      }),
                      style: ButtonStyle(
                        backgroundColor: WidgetStateProperty.resolveWith(
                            (st) => st.contains(WidgetState.selected) ? c.withValues(alpha: 0.25) : UW.ink),
                        side: WidgetStatePropertyAll(BorderSide(color: UW.gold.withValues(alpha: 0.5))),
                      ),
                    ),
                    const SizedBox(height: 16),
                    Row(children: [
                      _StepBtn(Icons.remove, qty > 1 ? () => setState(() => qty--) : null),
                      Expanded(
                        child: Column(children: [
                          Text('$qty', style: UW.number(30, color: UW.goldLight)),
                          Text('adet  ·  en fazla $max', style: UW.body(11, color: UW.muted)),
                        ]),
                      ),
                      _StepBtn(Icons.add, qty < max ? () => setState(() => qty++) : null),
                    ]),
                    if (max > 1)
                      Slider(
                        value: qty.toDouble().clamp(1, max.toDouble()),
                        min: 1,
                        max: max.toDouble(),
                        activeColor: UW.gold,
                        inactiveColor: UW.gold.withValues(alpha: 0.2),
                        onChanged: (v) => setState(() => qty = v.round()),
                      ),
                    Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                      for (final n in [1, 5, 10])
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 4),
                          child: OutlinedButton(
                            onPressed: max >= n ? () => setState(() => qty = n) : null,
                            child: Text('$n'),
                          ),
                        ),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 4),
                        child: OutlinedButton(onPressed: max > 0 ? () => setState(() => qty = max) : null, child: const Text('MAKS')),
                      ),
                    ]),
                    const SizedBox(height: 14),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.35),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: UW.gold.withValues(alpha: 0.2)),
                      ),
                      child: Row(children: [
                        Text(side == 'buy' ? 'Ödenecek (yaklaşık)' : 'Alınacak (vergi sonrası)', style: UW.body(13, color: UW.muted)),
                        const Spacer(),
                        GoldText(formatMoney(total), style: UW.number(20)),
                      ]),
                    ),
                    const SizedBox(height: 14),
                    DecoButton(
                      side == 'buy' ? 'Satın Al' : 'Sat',
                      icon: side == 'buy' ? Icons.add_shopping_cart : Icons.sell,
                      color: side == 'buy' ? UW.gold : const Color(0xFFE07A5F),
                      loading: busy,
                      onTap: max > 0 ? _confirm : null,
                    ),
                  ]),
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

class _StepBtn extends StatelessWidget {
  final IconData icon;
  final VoidCallback? onTap;
  const _StepBtn(this.icon, this.onTap);

  @override
  Widget build(BuildContext context) => IconButton.outlined(
        onPressed: onTap,
        icon: Icon(icon, color: UW.gold),
        style: IconButton.styleFrom(side: BorderSide(color: UW.gold.withValues(alpha: 0.5))),
      );
}

// ====================== ÇANTA ======================
class InventoryPanel extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const InventoryPanel({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    if (me.inventory.isEmpty) {
      return DecoPanel(
        child: Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.work_outline, size: 48, color: UW.gold.withValues(alpha: 0.6)),
            const SizedBox(height: 10),
            Text('Çantan boş', style: UW.display(18, color: UW.goldLight)),
            const SizedBox(height: 6),
            Text('Pazardan ucuz mal al, başka semtte pahalıya sat.',
                textAlign: TextAlign.center, style: UW.serif(13, color: UW.muted, weight: FontWeight.w400)),
          ]),
        ),
      );
    }
    final here = me.districtId;
    var value = 0.0;
    for (final h in me.inventory) {
      value += (game.price(here, h.goodId)?.sell ?? 0) * h.qty;
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      DecoPanel(
        padding: const EdgeInsets.all(14),
        child: Row(children: [
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('BURADAKİ DEĞERİ', style: UW.display(10, color: UW.muted)),
            GoldText(formatMoney(value), style: UW.number(22)),
          ]),
          const Spacer(),
          Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
            Text('YÜK', style: UW.display(10, color: UW.muted)),
            Text('${me.load} / ${me.capacity} kg', style: UW.number(16)),
          ]),
        ]),
      ),
      const SizedBox(height: 10),
      Expanded(
        child: ListView.separated(
          itemCount: me.inventory.length,
          separatorBuilder: (_, _) => const SizedBox(height: 8),
          itemBuilder: (_, i) {
            final h = me.inventory[i];
            final good = game.good(h.goodId)!;
            // En iyi satış yeri
            String? bestId;
            var best = 0.0;
            game.prices.forEach((d, m) {
              final s = m[h.goodId]?.sell ?? 0;
              if (s > best) {
                best = s;
                bestId = d;
              }
            });
            final bestD = bestId == null ? null : game.district(bestId!);
            final gain = (best - h.avgCost) / h.avgCost;
            return Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(6),
                gradient: const LinearGradient(colors: [UW.panelHi, UW.panel]),
                border: Border.all(color: UW.gold.withValues(alpha: 0.18)),
              ),
              child: Row(children: [
                GoodIcon(good.icon),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('${h.qty} × ${good.name}', style: UW.serif(15)),
                    Text('Maliyet ${formatMoney(h.avgCost)} / adet', style: UW.body(12, color: UW.muted)),
                    if (bestD != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Chip2(
                          'En iyi: ${bestD.name} ${formatMoney(best)} (${gain >= 0 ? '+' : ''}${(gain * 100).toStringAsFixed(0)}%)',
                          icon: Icons.trending_up,
                          color: gain >= 0 ? UW.emerald : UW.crimson,
                        ),
                      ),
                  ]),
                ),
                if (me.travel == null)
                  OutlinedButton(
                    onPressed: () => showModalBottomSheet(
                      context: context,
                      isScrollControlled: true,
                      backgroundColor: Colors.transparent,
                      builder: (_) => TradeSheet(game: game, good: good, toast: toast, initialSide: 'sell'),
                    ),
                    child: const Text('SAT'),
                  ),
              ]),
            );
          },
        ),
      ),
    ]);
  }
}

// ====================== SIRALAMA ======================
class LeaderboardPanel extends StatefulWidget {
  final GameState game;
  const LeaderboardPanel({super.key, required this.game});

  @override
  State<LeaderboardPanel> createState() => _LeaderboardPanelState();
}

class _LeaderboardPanelState extends State<LeaderboardPanel> {
  bool gangsView = false;

  @override
  Widget build(BuildContext context) {
    final game = widget.game;
    const medals = [Color(0xFFF5DE8B), Color(0xFFC9D1D9), Color(0xFFCD7F32)];
    return DecoPanel(
      padding: const EdgeInsets.fromLTRB(14, 16, 14, 8),
      child: Column(children: [
        DecoHeading(gangsView ? 'Şehrin Aileleri' : 'Şehrin Zenginleri'),
        const SizedBox(height: 4),
        Row(children: [
          SegmentedButton<bool>(
            segments: const [
              ButtonSegment(value: false, label: Text('Oyuncu'), icon: Icon(Icons.person, size: 16)),
              ButtonSegment(value: true, label: Text('Aile'), icon: Icon(Icons.shield, size: 16)),
            ],
            showSelectedIcon: false,
            selected: {gangsView},
            onSelectionChanged: (v) => setState(() => gangsView = v.first),
            style: ButtonStyle(
              visualDensity: VisualDensity.compact,
              backgroundColor: WidgetStateProperty.resolveWith(
                  (st) => st.contains(WidgetState.selected) ? UW.gold.withValues(alpha: 0.2) : UW.ink),
              side: WidgetStatePropertyAll(BorderSide(color: UW.gold.withValues(alpha: 0.5))),
            ),
          ),
          const Spacer(),
          IconButton(
            tooltip: 'Yenile',
            onPressed: gangsView ? game.loadGangs : game.loadLeaderboard,
            icon: const Icon(Icons.refresh, size: 18, color: UW.gold),
          ),
        ]),
        const SizedBox(height: 6),
        if (gangsView)
          Expanded(
            child: ListView.builder(
              itemCount: game.gangs.length,
              itemBuilder: (_, i) {
                final gg = game.gangs[i];
                final mine = gg.id == game.me?.gang?.id;
                return Container(
                  margin: const EdgeInsets.only(bottom: 6),
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                  decoration: BoxDecoration(
                    color: mine ? UW.gold.withValues(alpha: 0.12) : Colors.black.withValues(alpha: 0.25),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: hexColor(gg.color).withValues(alpha: mine ? 0.9 : 0.35)),
                  ),
                  child: Row(children: [
                    SizedBox(width: 30, child: Text('#${i + 1}', style: UW.number(13, color: i < 3 ? medals[i] : UW.muted))),
                    GangCrest(color: gg.color, emblem: gg.emblem, tag: gg.tag, size: 30),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(gg.name, style: UW.serif(14)),
                        Text('${gg.members} üye · ${gg.influence} nüfuz', style: UW.body(11, color: UW.muted)),
                      ]),
                    ),
                    Icon(Icons.flag, size: 16, color: hexColor(gg.color)),
                    const SizedBox(width: 4),
                    Text('${gg.territories}', style: UW.number(16, color: UW.goldLight)),
                  ]),
                );
              },
            ),
          )
        else
        Expanded(
          child: ListView.builder(
            itemCount: game.leaders.length,
            itemBuilder: (_, i) {
              final r = game.leaders[i];
              final isMe = r.username == game.me?.username;
              return Container(
                margin: const EdgeInsets.only(bottom: 6),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                decoration: BoxDecoration(
                  color: isMe ? UW.gold.withValues(alpha: 0.12) : Colors.black.withValues(alpha: 0.25),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: UW.gold.withValues(alpha: isMe ? 0.6 : 0.12)),
                ),
                child: Row(children: [
                  SizedBox(
                    width: 34,
                    child: r.rank <= 3
                        ? Icon(Icons.workspace_premium, color: medals[r.rank - 1])
                        : Text('#${r.rank}', style: UW.number(14, color: UW.muted)),
                  ),
                  Expanded(child: Text(r.username, style: UW.serif(15))),
                  Text('Sv ${r.level}   ', style: UW.body(12, color: UW.muted)),
                  Text(formatMoney(r.netWorth), style: UW.number(14, color: UW.goldLight)),
                ]),
              );
            },
          ),
        ),
      ]),
    );
  }
}

// ====================== SOHBET ======================
class ChatPanel extends StatefulWidget {
  final GameState game;
  const ChatPanel({super.key, required this.game});

  @override
  State<ChatPanel> createState() => _ChatPanelState();
}

class _ChatPanelState extends State<ChatPanel> {
  final _c = TextEditingController();
  String channel = 'global';

  void _send() {
    widget.game.sendChat(_c.text, channel: channel);
    _c.clear();
  }

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    final inGang = g.me?.gang != null;
    if (!inGang) channel = 'global';
    if (channel == 'gang') g.unreadGangChat = 0;
    final msgs = g.chat.where((m) => m.channel == channel).toList();
    return DecoPanel(
      padding: const EdgeInsets.fromLTRB(14, 16, 14, 14),
      child: Column(children: [
        DecoHeading(channel == 'gang' ? 'Aile Masası' : 'Kahvehane'),
        if (inGang) ...[
          const SizedBox(height: 10),
          SegmentedButton<String>(
            segments: [
              const ButtonSegment(value: 'global', label: Text('Genel'), icon: Icon(Icons.public, size: 16)),
              ButtonSegment(
                value: 'gang',
                label: Text(g.unreadGangChat > 0 ? 'Aile (${g.unreadGangChat})' : 'Aile'),
                icon: const Icon(Icons.shield, size: 16),
              ),
            ],
            selected: {channel},
            onSelectionChanged: (v) => setState(() => channel = v.first),
            style: ButtonStyle(
              backgroundColor: WidgetStateProperty.resolveWith(
                  (st) => st.contains(WidgetState.selected) ? UW.gold.withValues(alpha: 0.2) : UW.ink),
              side: WidgetStatePropertyAll(BorderSide(color: UW.gold.withValues(alpha: 0.5))),
            ),
          ),
        ],
        const SizedBox(height: 10),
        Expanded(
          child: msgs.isEmpty
              ? Center(child: Text('Henüz kimse konuşmadı...', style: UW.serif(13, color: UW.muted, weight: FontWeight.w400)))
              : ListView.builder(
                  reverse: true,
                  itemCount: msgs.length,
                  itemBuilder: (_, i) {
                    final m = msgs[msgs.length - 1 - i];
                    final mine = m.from == widget.game.me?.username;
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: RichText(
                        text: TextSpan(children: [
                          TextSpan(text: '${m.from}: ', style: UW.body(13, color: mine ? UW.goldLight : UW.neon, weight: FontWeight.w700)),
                          TextSpan(text: m.text, style: UW.body(13)),
                        ]),
                      ),
                    );
                  },
                ),
        ),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(
            child: TextField(
              controller: _c,
              style: UW.body(14),
              decoration: const InputDecoration(hintText: 'Bir şey söyle...', isDense: true),
              onSubmitted: (_) => _send(),
            ),
          ),
          const SizedBox(width: 8),
          IconButton.filled(
            onPressed: _send,
            icon: const Icon(Icons.send, color: UW.ink),
            style: IconButton.styleFrom(backgroundColor: UW.gold),
          ),
        ]),
      ]),
    );
  }
}

// ====================== SEMT DETAYI ======================
class DistrictSheet extends StatelessWidget {
  final GameState game;
  final District district;
  final VoidCallback onGo;
  final Toast toast;
  const DistrictSheet({super.key, required this.game, required this.district, required this.onGo, required this.toast});

  @override
  Widget build(BuildContext context) => ListenableBuilder(listenable: game, builder: (context, _) => _build(context));

  Widget _build(BuildContext context) {
    final me = game.me!;
    final c = hexColor(district.color);
    final isHere = me.districtId == district.id;

    // Buradan al → orada sat kâr fırsatları
    final ops = <(Good, double, double)>[];
    for (final g in game.goods) {
      final buy = game.price(me.districtId, g.id)?.buy;
      final sell = game.price(district.id, g.id)?.sell;
      if (buy == null || sell == null) continue;
      final net = sell * (1 - district.tax);
      ops.add((g, net - buy, (net - buy) / buy));
    }
    ops.sort((a, b) => b.$3.compareTo(a.$3));

    return Center(
      heightFactor: 1,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: DecoPanel(
            accent: c,
            glow: true,
            padding: const EdgeInsets.fromLTRB(20, 20, 20, 16),
            child: ConstrainedBox(
              constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * 0.85),
              child: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Row(children: [
                Container(width: 4, height: 40, color: c),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(district.name.toUpperCase(), style: UW.display(20, color: UW.goldLight, weight: FontWeight.w900)),
                    Text(district.description, style: UW.serif(13, color: UW.cream.withValues(alpha: 0.75), weight: FontWeight.w400)),
                  ]),
                ),
              ]),
              const SizedBox(height: 12),
              Wrap(spacing: 6, runSpacing: 6, children: [
                Chip2('Polis %${(district.police * 100).round()}', icon: Icons.local_police, color: UW.crimson),
                Chip2('Vergi %${(district.tax * 100).round()}', icon: Icons.account_balance, color: UW.gold),
                if (district.id == 'gecekondu') const Chip2('Soygun riski', icon: Icons.warning_amber, color: Color(0xFFE09F3E)),
              ]),
              const SizedBox(height: 14),
              Container(height: 1, color: UW.gold.withValues(alpha: 0.2)),
              const SizedBox(height: 12),
              WarSection(game: game, district: district, toast: toast),
              const SizedBox(height: 4),
              if (!isHere) ...[
                const SizedBox(height: 10),
                Container(height: 1, color: UW.gold.withValues(alpha: 0.2)),
                const SizedBox(height: 16),
                Text('BURADAN AL, ORADA SAT', style: UW.display(11, color: UW.muted)),
                const SizedBox(height: 8),
                for (final o in ops.take(3))
                  Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Row(children: [
                      GoodIcon(o.$1.icon, size: 30),
                      const SizedBox(width: 10),
                      Expanded(child: Text(o.$1.name, style: UW.serif(14))),
                      Text('${o.$2 >= 0 ? '+' : ''}${formatMoney(o.$2)}/adet',
                          style: UW.number(13, color: o.$2 >= 0 ? UW.emerald : UW.crimson)),
                      const SizedBox(width: 8),
                      SizedBox(
                        width: 52,
                        child: Text('${o.$3 >= 0 ? '+' : ''}${(o.$3 * 100).toStringAsFixed(0)}%',
                            textAlign: TextAlign.right, style: UW.number(12, color: o.$3 >= 0 ? UW.emerald : UW.crimson)),
                      ),
                    ]),
                  ),
              ],
              const SizedBox(height: 16),
              DecoButton(
                isHere ? 'Zaten buradasın' : 'Buraya Git  ·  ⚡${game.travelEnergy}',
                icon: Icons.directions_car,
                onTap: isHere || me.travel != null || me.energy < game.travelEnergy ? null : onGo,
              ),
            ]),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ====================== YOLCULUK OLAYI ======================
class EventDialog extends StatelessWidget {
  final GameState game;
  final Map<String, dynamic> event;
  const EventDialog({super.key, required this.game, required this.event});

  @override
  Widget build(BuildContext context) {
    final to = game.district(event['to'] ?? '')?.name ?? '';
    late IconData icon;
    late Color color;
    late String title, text;
    switch (event['type']) {
      case 'police':
        icon = Icons.local_police;
        color = UW.crimson;
        title = 'Polis Araması!';
        final seized = (event['seized'] as List? ?? [])
            .map((s) => '${s['qty']} ${s['name']}')
            .join(', ');
        text = '$to girişinde çevirmeye takıldın. Mallarının yarısına el konuldu:\n$seized';
      case 'robbery':
        icon = Icons.dangerous;
        color = const Color(0xFFE09F3E);
        title = 'Soyuldun!';
        text = 'Karanlık bir sokakta yolunu kestiler. ${formatMoney(event['lost'] ?? 0)} kaybettin.';
      case 'tip':
        icon = Icons.lightbulb;
        color = UW.emerald;
        title = 'Şanslı Gün';
        text = 'Yolda bir muhbir sana iş verdi. ${formatMoney(event['found'] ?? 0)} kazandın.';
      default:
        icon = Icons.verified;
        color = UW.gold;
        title = 'Sorunsuz Varış';
        text = '$to semtine sağ salim ulaştın.';
    }
    return Dialog(
      backgroundColor: Colors.transparent,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 380),
        child: DecoPanel(
          accent: color,
          glow: true,
          padding: const EdgeInsets.fromLTRB(22, 26, 22, 18),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(
              width: 76,
              height: 76,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: color.withValues(alpha: 0.12),
                border: Border.all(color: color, width: 1.6),
                boxShadow: [BoxShadow(color: color.withValues(alpha: 0.45), blurRadius: 26)],
              ),
              child: Icon(icon, size: 38, color: color),
            ),
            const SizedBox(height: 16),
            Text(title.toUpperCase(), style: UW.display(20, color: color, weight: FontWeight.w900)),
            const SizedBox(height: 10),
            Text(text, textAlign: TextAlign.center, style: UW.serif(14, weight: FontWeight.w400)),
            const SizedBox(height: 20),
            DecoButton('Tamam', color: color, onTap: () => Navigator.pop(context)),
          ]),
        ),
      ),
    );
  }
}
