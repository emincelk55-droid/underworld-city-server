import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/deco.dart';
import 'gang_panel.dart' show Countdown;
import 'panels.dart';

// ====================== MÜLK SEKMESİ: ÇANTA / İŞLETMELER ======================
class PropertyTabs extends StatefulWidget {
  final GameState game;
  final Toast toast;
  const PropertyTabs({super.key, required this.game, required this.toast});

  @override
  State<PropertyTabs> createState() => _PropertyTabsState();
}

class _PropertyTabsState extends State<PropertyTabs> {
  bool biz = false;

  @override
  Widget build(BuildContext context) {
    final n = widget.game.businesses.length;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SegmentedButton<bool>(
        segments: [
          const ButtonSegment(value: false, label: Text('Çanta'), icon: Icon(Icons.work_outline, size: 18)),
          ButtonSegment(value: true, label: Text(n > 0 ? 'İşletmeler ($n)' : 'İşletmeler'), icon: const Icon(Icons.storefront, size: 18)),
        ],
        selected: {biz},
        onSelectionChanged: (v) {
          setState(() => biz = v.first);
          if (biz) widget.game.loadBusinesses().catchError((_) {});
        },
        style: ButtonStyle(
          backgroundColor: WidgetStateProperty.resolveWith(
              (st) => st.contains(WidgetState.selected) ? UW.gold.withValues(alpha: 0.18) : UW.panel),
          side: WidgetStatePropertyAll(BorderSide(color: UW.gold.withValues(alpha: 0.5))),
        ),
      ),
      const SizedBox(height: 10),
      Expanded(
        child: biz
            ? BusinessPanel(game: widget.game, toast: widget.toast)
            : InventoryPanel(game: widget.game, toast: widget.toast),
      ),
    ]);
  }
}

// ====================== İŞLETMELER ======================
class BusinessPanel extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const BusinessPanel({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    final here = game.district(me.districtId);
    final mine = game.businesses;
    final available = game.businessTypes
        .where((t) => t.districts.contains(me.districtId))
        .where((t) => !mine.any((b) => b.type == t.id && b.districtId == me.districtId))
        .toList();
    return ListView(children: [
      if (mine.isEmpty)
        DecoPanel(
          padding: const EdgeInsets.all(18),
          child: Column(children: [
            const DecoHeading('İşletmelerin', size: 13),
            const SizedBox(height: 10),
            Text(
              'Henüz bir işletmen yok. Ham maddeyi ucuza al, kendi imalathanende işle, kârını katla. '
              'Ya da bir kahvehane açıp kasanın dolmasını izle.',
              textAlign: TextAlign.center,
              style: UW.serif(13, color: UW.cream.withValues(alpha: 0.8), weight: FontWeight.w400),
            ),
          ]),
        ),
      for (final b in mine)
        Padding(padding: const EdgeInsets.only(bottom: 10), child: BusinessCard(game: game, business: b, toast: toast)),
      const SizedBox(height: 6),
      Row(children: [
        Text('${(here?.name ?? '').toUpperCase()} · AÇILABİLECEK İŞLETMELER', style: UW.display(11, color: UW.muted)),
        const Spacer(),
        Text('${mine.length}/4', style: UW.number(12, color: UW.goldLight)),
      ]),
      const SizedBox(height: 8),
      if (me.travel != null)
        Text('Yoldasın. İşletme açmak için bir semte var.', style: UW.body(12, color: UW.muted))
      else if (available.isEmpty)
        Text(
          'Bu semtte açabileceğin işletme kalmadı. Diğer semtler: ${game.businessTypes.where((t) => !t.districts.contains(me.districtId)).map((t) => '${t.name} (${t.districts.map((d) => game.district(d)?.name ?? d).join(', ')})').join(' · ')}',
          style: UW.body(12, color: UW.muted),
        )
      else
        for (final t in available)
          Padding(padding: const EdgeInsets.only(bottom: 8), child: _BuyCard(game: game, type: t, toast: toast, full: mine.length >= 4)),
    ]);
  }
}

String _dur(int seconds) {
  if (seconds >= 3600) return '${(seconds / 3600).toStringAsFixed(seconds % 3600 == 0 ? 0 : 1)} sa';
  if (seconds >= 60) return '${(seconds / 60).round()} dk';
  return '$seconds sn';
}

String recipeText(GameState g, Recipe r) {
  String goods(Map<String, int> m) => m.entries.map((e) => '${e.value} ${g.good(e.key)?.name ?? e.key}').join(' + ');
  final out = [
    if (r.outputs.isNotEmpty) goods(r.outputs),
    if (r.cash > 0) '₺${r.cash}',
    if (r.influence > 0) '+${r.influence} nüfuz',
  ].join(' + ');
  return '${goods(r.inputs)} → $out';
}

class _BuyCard extends StatefulWidget {
  final GameState game;
  final BusinessType type;
  final Toast toast;
  final bool full;
  const _BuyCard({required this.game, required this.type, required this.toast, required this.full});

  @override
  State<_BuyCard> createState() => _BuyCardState();
}

class _BuyCardState extends State<_BuyCard> {
  bool busy = false;

  @override
  Widget build(BuildContext context) {
    final t = widget.type;
    final g = widget.game;
    final canAfford = g.me!.money >= t.cost + t.rent;
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: const LinearGradient(colors: [UW.panelHi, UW.panel]),
        border: Border.all(color: UW.gold.withValues(alpha: 0.2)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        BusinessFacade(type: t.id, status: 'producing', width: 78, height: 92),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(t.name, style: UW.serif(16))),
              Chip2(t.kind == 'front' ? 'Paravan' : 'Üretim', color: t.kind == 'front' ? UW.neon : UW.gold),
            ]),
            Text(t.desc, style: UW.serif(12, color: UW.muted, weight: FontWeight.w400)),
            const SizedBox(height: 6),
            for (final r in t.recipes)
              Text('• ${recipeText(g, r)} · ${_dur(r.seconds)}', style: UW.body(11.5, color: UW.cream.withValues(alpha: 0.9))),
            const SizedBox(height: 8),
            Row(children: [
              Text(formatMoney(t.cost), style: UW.number(15, color: UW.goldLight)),
              Text('  + ${formatMoney(t.rent)}/saat kira', style: UW.body(11, color: UW.muted)),
              const Spacer(),
              SizedBox(
                width: 118,
                height: 36,
                child: busy
                    ? const Center(child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: UW.gold)))
                    : OutlinedButton(
                        onPressed: canAfford && !widget.full
                            ? () async {
                                setState(() => busy = true);
                                try {
                                  await g.buyBusiness(t.id);
                                  widget.toast('${t.name} açıldı. Hayırlı olsun!');
                                } catch (e) {
                                  widget.toast(e.toString(), error: true);
                                } finally {
                                  if (mounted) setState(() => busy = false);
                                }
                              }
                            : null,
                        style: OutlinedButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 10)),
                        child: const Text('SATIN AL', maxLines: 1, softWrap: false),
                      ),
              ),
            ]),
          ]),
        ),
      ]),
    );
  }
}

class BusinessCard extends StatefulWidget {
  final GameState game;
  final Business business;
  final Toast toast;
  const BusinessCard({super.key, required this.game, required this.business, required this.toast});

  @override
  State<BusinessCard> createState() => _BusinessCardState();
}

class _BusinessCardState extends State<BusinessCard> {
  bool busy = false;

  Future<void> _run(Future<String> Function() f) async {
    setState(() => busy = true);
    try {
      widget.toast(await f());
    } catch (e) {
      widget.toast(e.toString(), error: true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final b = widget.business;
    final g = widget.game;
    final me = g.me!;
    final type = g.businessType(b.type);
    final recipe = type?.recipes.where((r) => r.id == b.recipeId).firstOrNull;
    final d = g.district(b.districtId);
    final here = me.districtId == b.districtId && me.travel == null;
    final (statusText, statusColor, statusIcon) = switch (b.status) {
      'producing' => (b.kind == 'front' ? 'Açık' : 'Üretimde', UW.emerald, Icons.play_circle),
      'starved' => ('Hammadde bekliyor', const Color(0xFFE09F3E), Icons.hourglass_empty),
      'unpaid' => ('Kira ödenmedi', UW.crimson, Icons.money_off),
      'raided' => ('Polis baskını', UW.crimson, Icons.local_police),
      _ => ('Boşta', UW.muted, Icons.pause_circle),
    };
    final dc = hexColor(d?.color ?? '#D4AF37');

    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: LinearGradient(colors: [Color.lerp(dc, UW.panel, 0.85)!, UW.panel, UW.night]),
        border: Border.all(color: statusColor.withValues(alpha: 0.45)),
        boxShadow: [BoxShadow(color: statusColor.withValues(alpha: 0.12), blurRadius: 16)],
      ),
      padding: const EdgeInsets.all(12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          BusinessFacade(type: b.type, status: b.status, width: 96, height: 112),
          const SizedBox(width: 12),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text(b.name, style: UW.serif(17))),
                for (var i = 0; i < b.maxLevel; i++)
                  Icon(i < b.level ? Icons.star : Icons.star_border, size: 14, color: UW.goldLight),
              ]),
              Text('${d?.name ?? b.districtId} · ${formatMoney(b.rent)}/saat kira', style: UW.body(11, color: UW.muted)),
              const SizedBox(height: 6),
              Row(children: [
                Icon(statusIcon, size: 15, color: statusColor),
                const SizedBox(width: 5),
                Text(statusText, style: UW.body(12, color: statusColor, weight: FontWeight.w700)),
                if (b.status == 'raided' && b.closedUntil != null) ...[
                  const SizedBox(width: 6),
                  Countdown(to: b.closedUntil!, style: UW.number(12, color: UW.crimson)),
                ],
              ]),
              const SizedBox(height: 6),
              if (recipe != null) ...[
                Text(recipeText(g, recipe), style: UW.body(11.5, color: UW.cream.withValues(alpha: 0.9))),
                const SizedBox(height: 4),
                _BatchProgress(business: b),
              ],
            ]),
          ),
        ]),
        const SizedBox(height: 10),
        // Ambar ve kasa
        Row(children: [
          Expanded(
            child: Wrap(spacing: 6, runSpacing: 6, children: [
              for (final input in recipe?.inputs.keys ?? const <String>[])
                Container(
                  padding: const EdgeInsets.fromLTRB(4, 3, 8, 3),
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.35),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: UW.gold.withValues(alpha: 0.25)),
                  ),
                  child: Row(mainAxisSize: MainAxisSize.min, children: [
                    GoodIcon(g.good(input)?.icon ?? '', size: 20),
                    const SizedBox(width: 5),
                    Text('${b.stock[input] ?? 0}', style: UW.number(12, color: UW.cream)),
                  ]),
                ),
              Text('Ambar ${b.stockTotal}/${b.stockCap}', style: UW.body(10.5, color: UW.muted)),
              if (b.batchesLeft != null && b.batchesLeft! > 0 && b.batchSeconds != null)
                Text('· ${b.batchesLeft} parti (~${_dur(b.batchesLeft! * b.batchSeconds!)})', style: UW.body(10.5, color: UW.muted)),
            ]),
          ),
          if (b.kind == 'front')
            Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
              Text('KASA', style: UW.display(9, color: UW.muted)),
              GoldText(formatMoney(b.till), style: UW.number(17, weight: FontWeight.w800)),
            ]),
        ]),
        const SizedBox(height: 10),
        if (busy)
          const Center(child: Padding(padding: EdgeInsets.all(8), child: CircularProgressIndicator(color: UW.gold, strokeWidth: 2)))
        else
          Wrap(spacing: 6, runSpacing: 6, children: [
            _Act(
              icon: Icons.move_to_inbox,
              label: here ? 'Hammadde Yükle' : 'Yüklemek için ${d?.name ?? ''}\'a git',
              onTap: here && recipe != null
                  ? () async {
                      final res = await showDialog<(String, int)>(
                        context: context,
                        builder: (_) => _LoadDialog(game: g, business: b, recipe: recipe),
                      );
                      if (res == null) return;
                      await _run(() async {
                        final n = await g.loadBusiness(b.id, res.$1, res.$2);
                        return '$n ${g.good(res.$1)?.name ?? ''} yüklendi';
                      });
                    }
                  : null,
            ),
            if (b.kind == 'front')
              _Act(
                icon: Icons.payments,
                label: 'Kasayı Boşalt',
                highlight: b.till > 0,
                onTap: b.till > 0 ? () => _run(() async => '${formatMoney(await g.collectTill(b.id))} cebine girdi') : null,
              ),
            if ((type?.recipes.length ?? 0) > 1)
              PopupMenuButton<String>(
                color: UW.panelHi,
                onSelected: (rid) => _run(() async {
                  await g.setRecipe(b.id, rid);
                  return 'Üretim değişti';
                }),
                itemBuilder: (_) => [
                  for (final r in type!.recipes)
                    PopupMenuItem(
                      value: r.id,
                      child: Text('${r.id == b.recipeId ? '✓ ' : ''}${r.name}: ${recipeText(g, r)}', style: UW.body(13)),
                    ),
                ],
                child: const _Act(icon: Icons.swap_horiz, label: 'Ürün Seç'),
              ),
            if (b.upgradeCost != null)
              _Act(
                icon: Icons.upgrade,
                label: 'Yükselt · ${formatMoney(b.upgradeCost!)}',
                onTap: me.money >= b.upgradeCost!
                    ? () => _run(() async {
                          await g.upgradeBusiness(b.id);
                          return '${b.name} seviye ${b.level + 1} oldu: daha hızlı, daha büyük ambar';
                        })
                    : null,
              ),
            _Act(
              icon: Icons.sell_outlined,
              label: 'Sat · ${formatMoney(b.sellValue)}',
              danger: true,
              onTap: () async {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (_) => AlertDialog(
                    backgroundColor: UW.panel,
                    title: Text('${b.name} satılsın mı?', style: UW.serif(18)),
                    content: Text(
                      'Yatırımının yarısı (${formatMoney(b.sellValue)}) ve kasadaki para sana döner. '
                      'Ambardaki hammadde ${d?.name ?? ''} deposuna taşınır.',
                      style: UW.body(14),
                    ),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Vazgeç')),
                      TextButton(
                        onPressed: () => Navigator.pop(context, true),
                        child: Text('Sat', style: UW.body(14, color: UW.crimson, weight: FontWeight.w700)),
                      ),
                    ],
                  ),
                );
                if (ok == true) await _run(() async => '${b.name} satıldı: ${formatMoney(await g.sellBusiness(b.id))}');
              },
            ),
          ]),
      ]),
    );
  }
}

/// Mevcut partinin ilerlemesi (saniyede bir yenilenir)
class _BatchProgress extends StatefulWidget {
  final Business business;
  const _BatchProgress({required this.business});

  @override
  State<_BatchProgress> createState() => _BatchProgressState();
}

class _BatchProgressState extends State<_BatchProgress> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 1))..repeat();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final b = widget.business;
    return AnimatedBuilder(
      animation: _c,
      builder: (_, _) {
        final producing = b.status == 'producing' && b.nextBatchAt != null && b.batchSeconds != null;
        double v = 0;
        String label = '—';
        if (producing) {
          final left = b.nextBatchAt!.difference(DateTime.now());
          final total = b.batchSeconds! * 1000;
          v = (1 - left.inMilliseconds / total).clamp(0.0, 1.0);
          final s = math.max(0, left.inSeconds);
          label = s == 0 ? 'parti hazır' : 'sonraki parti ${s ~/ 60}:${(s % 60).toString().padLeft(2, '0')}';
        }
        return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: Stack(children: [
              Container(height: 8, color: Colors.black54),
              FractionallySizedBox(
                widthFactor: v,
                child: Container(
                  height: 8,
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(colors: [UW.goldDark, UW.gold, UW.goldLight]),
                    boxShadow: [BoxShadow(color: UW.gold.withValues(alpha: 0.6), blurRadius: 6)],
                  ),
                ),
              ),
              // Akan ışık
              if (producing)
                Positioned(
                  left: (_c.value * 1.2 - 0.2) * 220,
                  child: Container(
                    width: 30,
                    height: 8,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(colors: [Colors.white.withValues(alpha: 0), Colors.white.withValues(alpha: 0.35), Colors.white.withValues(alpha: 0)]),
                    ),
                  ),
                ),
            ]),
          ),
          const SizedBox(height: 3),
          Text('$label · hız ×${b.speed}', style: UW.number(10.5, color: UW.muted, weight: FontWeight.w500)),
        ]);
      },
    );
  }
}

class _Act extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final bool danger, highlight;
  const _Act({required this.icon, required this.label, this.onTap, this.danger = false, this.highlight = false});

  @override
  Widget build(BuildContext context) {
    final c = danger ? UW.crimson : (highlight ? UW.goldLight : UW.gold);
    final enabled = onTap != null || (onTap == null && !danger && label == 'Ürün Seç');
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Opacity(
        opacity: enabled || onTap != null ? 1 : 0.45,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(4),
            color: highlight ? UW.gold.withValues(alpha: 0.18) : c.withValues(alpha: 0.06),
            border: Border.all(color: c.withValues(alpha: highlight ? 0.9 : 0.45)),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(icon, size: 15, color: c),
            const SizedBox(width: 5),
            Text(label, style: UW.body(11.5, color: c, weight: FontWeight.w700)),
          ]),
        ),
      ),
    );
  }
}

class _LoadDialog extends StatefulWidget {
  final GameState game;
  final Business business;
  final Recipe recipe;
  const _LoadDialog({required this.game, required this.business, required this.recipe});

  @override
  State<_LoadDialog> createState() => _LoadDialogState();
}

class _LoadDialogState extends State<_LoadDialog> {
  late String goodId = widget.recipe.inputs.keys.first;
  final _qty = TextEditingController();

  int _available(String id) =>
      widget.game.me!.qtyOf(id) + widget.game.storageQty(widget.business.districtId, id);

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    final room = widget.business.stockCap - widget.business.stockTotal;
    final avail = _available(goodId);
    final max = math.min(room, avail);
    if (_qty.text.isEmpty) _qty.text = '$max';
    return Dialog(
      backgroundColor: Colors.transparent,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 380),
        child: DecoPanel(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const DecoHeading('Hammadde Yükle', size: 13),
            const SizedBox(height: 14),
            for (final id in widget.recipe.inputs.keys)
              InkWell(
                onTap: () => setState(() {
                  goodId = id;
                  _qty.clear();
                }),
                borderRadius: BorderRadius.circular(4),
                child: Container(
                  margin: const EdgeInsets.only(bottom: 6),
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(4),
                    color: id == goodId ? UW.gold.withValues(alpha: 0.12) : Colors.transparent,
                    border: Border.all(color: UW.gold.withValues(alpha: id == goodId ? 0.8 : 0.2)),
                  ),
                  child: Row(children: [
                    Icon(id == goodId ? Icons.radio_button_checked : Icons.radio_button_off, size: 18, color: UW.gold),
                    const SizedBox(width: 8),
                    GoodIcon(g.good(id)?.icon ?? '', size: 28),
                    const SizedBox(width: 8),
                    Text(g.good(id)?.name ?? id, style: UW.serif(14)),
                    const Spacer(),
                    Text('elinde ${_available(id)}', style: UW.body(11, color: UW.muted)),
                  ]),
                ),
              ),
            const SizedBox(height: 6),
            Text('Çantadan ve bu semtteki depodan alınır · ambarda $room yer var', style: UW.body(11, color: UW.muted)),
            const SizedBox(height: 10),
            TextField(
              controller: _qty,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              style: UW.number(20, color: UW.goldLight),
              decoration: InputDecoration(labelText: 'Miktar (en fazla $max)'),
            ),
            const SizedBox(height: 14),
            DecoButton(
              'Yükle',
              icon: Icons.move_to_inbox,
              onTap: max > 0 ? () => Navigator.pop(context, (goodId, math.min(max, int.tryParse(_qty.text) ?? 0))) : null,
            ),
            if (avail == 0)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text('Elinde bu mal yok. Pazardan ya da borsadan alabilirsin.',
                    textAlign: TextAlign.center, style: UW.body(12, color: UW.crimson)),
              ),
          ]),
        ),
      ),
    );
  }
}

// ====================== BİNA CEPHESİ ======================
/// Her işletme türü için kodla çizilmiş art deco cephe. Üretimde: ışıklar yanar, baca tüter, neon titrer.
class BusinessFacade extends StatefulWidget {
  final String type, status;
  final double width, height;
  const BusinessFacade({super.key, required this.type, required this.status, this.width = 96, this.height = 112});

  @override
  State<BusinessFacade> createState() => _BusinessFacadeState();
}

class _BusinessFacadeState extends State<BusinessFacade> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 4))..repeat();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ClipRRect(
        borderRadius: BorderRadius.circular(4),
        child: RepaintBoundary(
          child: AnimatedBuilder(
            animation: _c,
            builder: (_, _) => CustomPaint(
              size: Size(widget.width, widget.height),
              painter: _FacadePainter(widget.type, widget.status, _c.value),
            ),
          ),
        ),
      );
}

class _FacadePainter extends CustomPainter {
  final String type, status;
  final double t;
  _FacadePainter(this.type, this.status, this.t);

  bool get active => status == 'producing';

  @override
  void paint(Canvas canvas, Size s) {
    final w = s.width, h = s.height;
    final rect = Offset.zero & s;

    // Gece gökyüzü
    canvas.drawRect(
        rect,
        Paint()
          ..shader = const LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF0A0E1C), Color(0xFF1B1730), Color(0xFF2B1F2E)],
          ).createShader(rect));
    for (var i = 0; i < 8; i++) {
      final r = math.Random(i * 13 + type.length);
      canvas.drawCircle(Offset(r.nextDouble() * w, r.nextDouble() * h * 0.3), 0.7,
          Paint()..color = Colors.white.withValues(alpha: 0.4 + 0.3 * math.sin(t * 6.28 + i)));
    }

    final (wall, trim, accent) = switch (type) {
      'imalathane' => (const Color(0xFF4A2A1E), const Color(0xFF7A4A33), const Color(0xFFC0485A)),
      'atolye' => (const Color(0xFF3A4048), const Color(0xFF5E6872), const Color(0xFFE09F3E)),
      'matbaa' => (const Color(0xFF203A30), const Color(0xFF3E6455), const Color(0xFFE3C67B)),
      'kahvehane' => (const Color(0xFF5A3A22), const Color(0xFF8C5E3C), const Color(0xFFD4AF37)),
      _ => (const Color(0xFF15121E), const Color(0xFF2E2840), const Color(0xFFE84393)),
    };

    final top = h * 0.3, bottom = h * 0.92;
    final left = w * 0.1, right = w * 0.9;

    // Baca ve duman (üretim işletmeleri)
    if (type == 'imalathane' || type == 'atolye') {
      final cx = right - w * 0.16;
      canvas.drawRect(Rect.fromLTWH(cx, top - h * 0.16, w * 0.09, h * 0.18), Paint()..color = trim);
      canvas.drawRect(Rect.fromLTWH(cx - 2, top - h * 0.17, w * 0.09 + 4, 3), Paint()..color = wall);
      if (active) {
        for (var i = 0; i < 5; i++) {
          final ph = (t * 1.5 + i / 5) % 1.0;
          final p = Offset(cx + w * 0.045 + math.sin(ph * 6 + i) * 4 + ph * 10, top - h * 0.18 - ph * h * 0.22);
          canvas.drawCircle(p, 3 + ph * 7, Paint()..color = Colors.grey.withValues(alpha: (1 - ph) * 0.45));
        }
      }
    }

    // Çatı
    final roof = Paint()..color = trim;
    if (type == 'atolye') {
      // Testere dişli fabrika çatısı
      final path = Path()..moveTo(left, top);
      const teeth = 3;
      final tw = (right - left) / teeth;
      for (var i = 0; i < teeth; i++) {
        path.lineTo(left + i * tw, top - h * 0.1);
        path.lineTo(left + (i + 1) * tw, top);
      }
      path.close();
      canvas.drawPath(path, roof);
      for (var i = 0; i < teeth; i++) {
        canvas.drawLine(Offset(left + i * tw, top - h * 0.1), Offset(left + i * tw, top),
            Paint()..color = (active ? const Color(0xFFFFD27A) : Colors.black).withValues(alpha: 0.6)..strokeWidth = 2);
      }
    } else {
      // Basamaklı art deco tepe
      canvas.drawRect(Rect.fromLTRB(left + w * 0.06, top - h * 0.05, right - w * 0.06, top), roof);
      canvas.drawRect(Rect.fromLTRB(left + w * 0.2, top - h * 0.09, right - w * 0.2, top - h * 0.05), roof);
      canvas.drawRect(Rect.fromLTRB(w * 0.47, top - h * 0.14, w * 0.53, top - h * 0.09), roof);
    }

    // Duvar
    canvas.drawRect(
        Rect.fromLTRB(left, top, right, bottom),
        Paint()
          ..shader = LinearGradient(colors: [Color.lerp(wall, Colors.white, 0.08)!, wall, Color.lerp(wall, Colors.black, 0.35)!])
              .createShader(Rect.fromLTRB(left, top, right, bottom)));
    // Tuğla dokusu
    final brick = Paint()
      ..color = Colors.black.withValues(alpha: 0.18)
      ..strokeWidth = 0.6;
    for (var y = top + 6; y < bottom; y += 6) {
      canvas.drawLine(Offset(left, y), Offset(right, y), brick);
    }
    // Dikey art deco şeritler
    for (final x in [left + 3, right - 3]) {
      canvas.drawLine(Offset(x, top), Offset(x, bottom), Paint()..color = trim..strokeWidth = 3);
    }

    // Tabela
    final signRect = Rect.fromLTRB(left + w * 0.08, top + h * 0.04, right - w * 0.08, top + h * 0.16);
    final neon = type == 'gece_kulubu';
    final flicker = neon ? (0.65 + 0.35 * (math.sin(t * 6.28 * 7) > -0.6 ? 1 : 0.2)) : 1.0;
    final signOn = active || status == 'starved';
    canvas.drawRRect(RRect.fromRectAndRadius(signRect, const Radius.circular(2)), Paint()..color = const Color(0xFF0B0B0F));
    if (signOn) {
      canvas.drawRRect(
          RRect.fromRectAndRadius(signRect.inflate(2), const Radius.circular(3)),
          Paint()
            ..color = accent.withValues(alpha: 0.35 * flicker)
            ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 5));
    }
    canvas.drawRRect(
        RRect.fromRectAndRadius(signRect, const Radius.circular(2)),
        Paint()
          ..color = accent.withValues(alpha: signOn ? flicker : 0.35)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.2);
    final label = switch (type) {
      'imalathane' => 'İMALAT',
      'atolye' => 'ATÖLYE',
      'matbaa' => 'MATBAA',
      'kahvehane' => 'KAHVE',
      _ => 'CLUB',
    };
    final tp = TextPainter(
      text: TextSpan(
        text: label,
        style: UW.display(signRect.height * 0.62, color: accent.withValues(alpha: signOn ? flicker : 0.4), weight: FontWeight.w900)
            .copyWith(letterSpacing: 1.2, shadows: signOn ? [Shadow(color: accent, blurRadius: 6)] : null),
      ),
      textDirection: TextDirection.ltr,
    )..layout(maxWidth: signRect.width);
    tp.paint(canvas, Offset(signRect.center.dx - tp.width / 2, signRect.center.dy - tp.height / 2));

    // Pencereler
    final winTop = top + h * 0.21;
    final cols = 3, rows = 2;
    final ww = (right - left - w * 0.2) / cols;
    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        final wr = Rect.fromLTWH(left + w * 0.1 + c * ww + ww * 0.18, winTop + r * h * 0.15, ww * 0.64, h * 0.1);
        final lit = active && ((c + r + (t * 3).floor()) % 5 != 0);
        final arch = type == 'matbaa';
        final path = arch
            ? (Path()
              ..moveTo(wr.left, wr.bottom)
              ..lineTo(wr.left, wr.top + wr.width / 2)
              ..arcToPoint(Offset(wr.right, wr.top + wr.width / 2), radius: Radius.circular(wr.width / 2))
              ..lineTo(wr.right, wr.bottom)
              ..close())
            : (Path()..addRect(wr));
        canvas.drawPath(
            path,
            Paint()
              ..color = lit
                  ? (type == 'gece_kulubu' ? const Color(0xFFFF7AC6) : const Color(0xFFFFC870)).withValues(alpha: 0.85)
                  : const Color(0xFF0D0F16));
        if (lit) {
          canvas.drawPath(path, Paint()..color = const Color(0xFFFFC870).withValues(alpha: 0.25)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 4));
        }
        canvas.drawLine(Offset(wr.center.dx, wr.top + (arch ? wr.width / 2 : 0)), Offset(wr.center.dx, wr.bottom),
            Paint()..color = trim..strokeWidth = 1);
      }
    }

    // Tente (kahvehane, kulüp)
    final doorTop = bottom - h * 0.2;
    if (type == 'kahvehane' || type == 'gece_kulubu') {
      final aw = Path()
        ..moveTo(w * 0.3, doorTop - 4)
        ..lineTo(w * 0.7, doorTop - 4)
        ..lineTo(w * 0.76, doorTop + 4)
        ..lineTo(w * 0.24, doorTop + 4)
        ..close();
      canvas.drawPath(aw, Paint()..color = accent.withValues(alpha: 0.9));
      for (var i = 0; i < 6; i++) {
        final x = w * 0.26 + i * w * 0.09;
        canvas.drawLine(Offset(x, doorTop - 3), Offset(x + w * 0.02, doorTop + 4), Paint()..color = Colors.white.withValues(alpha: 0.35)..strokeWidth = 2);
      }
    }

    // Kapı
    final door = Rect.fromLTRB(w * 0.4, doorTop + 6, w * 0.6, bottom);
    canvas.drawRect(door, Paint()..color = active ? const Color(0xFF2A1B10) : const Color(0xFF0B0B0F));
    if (active) {
      canvas.drawRect(Rect.fromLTRB(door.left + 2, door.top + 2, door.right - 2, door.top + 6),
          Paint()..color = const Color(0xFFFFC870).withValues(alpha: 0.7));
    }
    canvas.drawRect(door, Paint()..color = trim..style = PaintingStyle.stroke..strokeWidth = 1);

    // Kaldırım
    canvas.drawRect(Rect.fromLTRB(0, bottom, w, h), Paint()..color = const Color(0xFF14151B));
    // Sokak lambası ışığı
    canvas.drawCircle(Offset(w * 0.08, bottom - 2), w * 0.25,
        Paint()..shader = RadialGradient(colors: [const Color(0xFFFFD27A).withValues(alpha: 0.18), Colors.transparent])
            .createShader(Rect.fromCircle(center: Offset(w * 0.08, bottom - 2), radius: w * 0.25)));

    // Durum katmanları
    if (status == 'raided') {
      final flash = (t * 8).floor() % 2 == 0;
      canvas.drawRect(rect, Paint()..color = (flash ? const Color(0xFFD9475B) : const Color(0xFF3F7BFF)).withValues(alpha: 0.18));
      canvas.save();
      canvas.translate(w / 2, h * 0.62);
      canvas.rotate(-0.35);
      final tape = Rect.fromCenter(center: Offset.zero, width: w * 1.6, height: h * 0.1);
      canvas.drawRect(tape, Paint()..color = const Color(0xFFF2C94C));
      final tt = TextPainter(
        text: TextSpan(text: 'POLİS · GİRMEYİN · POLİS', style: UW.body(h * 0.055, color: Colors.black, weight: FontWeight.w900)),
        textDirection: TextDirection.ltr,
      )..layout();
      tt.paint(canvas, Offset(-tt.width / 2, -tt.height / 2));
      canvas.restore();
    } else if (status == 'unpaid' || status == 'idle') {
      final sign = Rect.fromCenter(center: Offset(w / 2, door.center.dy - 4), width: w * 0.34, height: h * 0.08);
      canvas.drawRect(sign, Paint()..color = const Color(0xFFEDE3C8));
      final tt = TextPainter(
        text: TextSpan(text: 'KAPALI', style: UW.body(h * 0.05, color: const Color(0xFF8B1E2D), weight: FontWeight.w900)),
        textDirection: TextDirection.ltr,
      )..layout();
      tt.paint(canvas, Offset(sign.center.dx - tt.width / 2, sign.center.dy - tt.height / 2));
    }

    // Çerçeve
    canvas.drawRect(rect.deflate(0.5), Paint()..color = UW.gold.withValues(alpha: 0.45)..style = PaintingStyle.stroke);
  }

  @override
  bool shouldRepaint(covariant _FacadePainter old) => old.t != t || old.status != status || old.type != type;
}
