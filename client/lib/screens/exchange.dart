import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/deco.dart';
import 'panels.dart';

// ====================== PAZAR SEKMESİ: TÜCCAR / BORSA ======================
class MarketTabs extends StatefulWidget {
  final GameState game;
  final Toast toast;
  const MarketTabs({super.key, required this.game, required this.toast});

  @override
  State<MarketTabs> createState() => _MarketTabsState();
}

class _MarketTabsState extends State<MarketTabs> {
  bool exchange = false;

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Expanded(
          child: _ModeTab(
            icon: Icons.storefront,
            title: 'Tüccar',
            subtitle: 'Anında al/sat',
            selected: !exchange,
            onTap: () => setState(() => exchange = false),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _ModeTab(
            icon: Icons.candlestick_chart,
            title: 'Borsa',
            subtitle: 'Oyunculara emir ver',
            selected: exchange,
            onTap: () {
              setState(() => exchange = true);
              widget.game.loadMarketSummary().catchError((_) {});
            },
          ),
        ),
      ]),
      const SizedBox(height: 10),
      Expanded(
        child: exchange
            ? ExchangePanel(game: widget.game, toast: widget.toast)
            : MarketPanel(game: widget.game, toast: widget.toast),
      ),
    ]);
  }
}

class _ModeTab extends StatelessWidget {
  final IconData icon;
  final String title, subtitle;
  final bool selected;
  final VoidCallback onTap;
  const _ModeTab({required this.icon, required this.title, required this.subtitle, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(5),
            color: selected ? UW.gold.withValues(alpha: 0.14) : UW.panel,
            border: Border.all(color: UW.gold.withValues(alpha: selected ? 0.9 : 0.25)),
            boxShadow: selected ? [BoxShadow(color: UW.gold.withValues(alpha: 0.2), blurRadius: 14)] : null,
          ),
          child: Row(children: [
            Icon(icon, color: selected ? UW.goldLight : UW.muted, size: 22),
            const SizedBox(width: 10),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(title.toUpperCase(), style: UW.display(13, color: selected ? UW.goldLight : UW.cream, weight: FontWeight.w900)),
                Text(subtitle, style: UW.body(10.5, color: UW.muted), overflow: TextOverflow.ellipsis),
              ]),
            ),
          ]),
        ),
      );
}

// ====================== BORSA LİSTESİ ======================
class ExchangePanel extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const ExchangePanel({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    final d = game.district(me.districtId);
    if (me.travel != null) {
      return DecoPanel(
        child: Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.directions_car_filled, color: UW.gold, size: 42),
            const SizedBox(height: 8),
            Text('Yoldasın', style: UW.display(18, color: UW.goldLight)),
            Text('Borsa, vardığın semtte açılır', style: UW.body(13, color: UW.muted)),
          ]),
        ),
      );
    }
    final openHere = game.myOrders.where((o) => o.districtId == me.districtId).length;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      // Borsa tabelası
      Container(
        padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(5),
          color: const Color(0xFF0B0F18),
          border: Border.all(color: UW.gold.withValues(alpha: 0.5)),
        ),
        child: Row(children: [
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${(d?.name ?? '').toUpperCase()} BORSASI', style: UW.display(14, color: UW.goldLight, weight: FontWeight.w900)),
            Text('Satıcı %${((d?.tax ?? 0) * 100).round()} vergi öder · alınan mal depoya gelir',
                style: UW.body(10.5, color: UW.muted)),
          ]).expandedX(),
          Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
            Text('EMİRLERİN', style: UW.display(9, color: UW.muted)),
            Text('${game.myOrders.length}/10', style: UW.number(15, color: UW.goldLight)),
            if (openHere > 0) Text('$openHere burada', style: UW.body(10, color: UW.muted)),
          ]),
        ]),
      ),
      const SizedBox(height: 6),
      // Sütun başlıkları
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Row(children: [
          const SizedBox(width: 46),
          Expanded(child: Text('MAL', style: UW.display(9, color: UW.muted))),
          SizedBox(width: 62, child: Text('ALIŞ', textAlign: TextAlign.right, style: UW.display(9, color: UW.emerald))),
          SizedBox(width: 62, child: Text('SATIŞ', textAlign: TextAlign.right, style: UW.display(9, color: UW.crimson))),
          SizedBox(width: 50, child: Text('HACİM', textAlign: TextAlign.right, style: UW.display(9, color: UW.muted))),
        ]),
      ),
      const SizedBox(height: 6),
      Expanded(
        child: ListView.separated(
          itemCount: game.goods.length,
          separatorBuilder: (_, _) => const SizedBox(height: 6),
          itemBuilder: (_, i) {
            final g = game.goods[i];
            final s = game.marketSummary[g.id];
            final stored = game.storageQty(me.districtId, g.id);
            return Material(
              color: Colors.transparent,
              child: InkWell(
                borderRadius: BorderRadius.circular(5),
                onTap: () => openOrderBook(context, game, g, toast),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(5),
                    gradient: const LinearGradient(colors: [UW.panelHi, UW.panel]),
                    border: Border.all(color: UW.gold.withValues(alpha: 0.16)),
                  ),
                  child: Row(children: [
                    GoodIcon(g.icon, size: 36),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(g.name, style: UW.serif(14), overflow: TextOverflow.ellipsis),
                        Row(children: [
                          if (s?.last != null) Text('Son ₺${s!.last}', style: UW.body(10.5, color: UW.muted)),
                          if (stored > 0) ...[
                            const SizedBox(width: 6),
                            Chip2('Depo $stored', icon: Icons.warehouse, color: UW.neon),
                          ],
                        ]),
                      ]),
                    ),
                    _PriceCell(s?.bestBid, s?.bidQty ?? 0, UW.emerald),
                    _PriceCell(s?.bestAsk, s?.askQty ?? 0, UW.crimson),
                    SizedBox(
                      width: 50,
                      child: Text('${s?.vol24 ?? 0}', textAlign: TextAlign.right, style: UW.number(12, color: UW.cream)),
                    ),
                  ]),
                ),
              ),
            );
          },
        ),
      ),
    ]);
  }
}

class _PriceCell extends StatelessWidget {
  final int? price;
  final int qty;
  final Color color;
  const _PriceCell(this.price, this.qty, this.color);

  @override
  Widget build(BuildContext context) => SizedBox(
        width: 62,
        child: Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
          Text(price == null ? '—' : '₺$price', style: UW.number(13, color: price == null ? UW.muted : color)),
          if (price != null) Text('$qty adet', style: UW.body(9.5, color: UW.muted)),
        ]),
      );
}

extension on Widget {
  Widget expandedX() => Expanded(child: this);
}

void openOrderBook(BuildContext context, GameState game, Good good, Toast toast) {
  final d = game.me!.districtId;
  game.openBook = null;
  game.loadBook(d, good.id).catchError((_) {});
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    constraints: const BoxConstraints(maxWidth: 900),
    builder: (_) => OrderBookSheet(game: game, good: good, toast: toast),
  ).whenComplete(() => game.openBook = null);
}

// ====================== EMİR DEFTERİ ======================
class OrderBookSheet extends StatefulWidget {
  final GameState game;
  final Good good;
  final Toast toast;
  const OrderBookSheet({super.key, required this.game, required this.good, required this.toast});

  @override
  State<OrderBookSheet> createState() => _OrderBookSheetState();
}

class _OrderBookSheetState extends State<OrderBookSheet> {
  String side = 'buy';
  final _price = TextEditingController();
  final _qty = TextEditingController(text: '1');
  bool busy = false;
  String? error;
  bool _seeded = false;

  int get price => int.tryParse(_price.text) ?? 0;
  int get qty => int.tryParse(_qty.text) ?? 0;

  void _setPrice(int p) => setState(() => _price.text = '$p');
  void _setQty(int q) => setState(() => _qty.text = '${math.max(1, q)}');

  // Formdaki emir hemen ne kadar eşleşir? (istemci tarafı tahmin)
  (int, int) _instantFill(OrderBook b) {
    var left = qty, filled = 0, cost = 0;
    final levels = side == 'buy' ? b.asks.where((l) => l.price <= price) : b.bids.where((l) => l.price >= price);
    for (final l in levels) {
      if (left <= 0) break;
      final take = math.min(left, l.qty);
      filled += take;
      cost += take * l.price;
      left -= take;
    }
    return (filled, cost);
  }

  int _maxQty(OrderBook b) {
    final me = widget.game.me!;
    if (side == 'sell') return me.qtyOf(widget.good.id) + b.storage;
    if (price <= 0) return 0;
    return math.min(1000, me.money ~/ price);
  }

  Future<void> _submit() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final r = await widget.game.placeOrder(widget.good.id, side, price, qty);
      final filled = r['filledQty'] as int;
      final resting = r['restingQty'] as int;
      final parts = <String>[
        if (filled > 0) '$filled adet ₺${r['avgPrice']} ortalamayla ${side == 'buy' ? 'alındı (depoya)' : 'satıldı'}',
        if (resting > 0) '$resting adet deftere yazıldı',
      ];
      widget.toast(parts.join(' · '));
    } catch (e) {
      setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    return ListenableBuilder(
      listenable: g,
      builder: (context, _) {
        final b = g.openBook;
        final me = g.me!;
        final npc = g.price(me.districtId, widget.good.id);
        if (b != null && !_seeded) {
          _seeded = true;
          _price.text = '${b.bestAsk ?? b.bestBid ?? npc?.mid.round() ?? widget.good.basePrice}';
        }
        return Padding(
          padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
          child: Center(
            heightFactor: 1,
            child: ConstrainedBox(
              constraints: BoxConstraints(maxWidth: 760, maxHeight: MediaQuery.sizeOf(context).height * 0.92),
              child: Padding(
                padding: const EdgeInsets.all(10),
                child: DecoPanel(
                  glow: true,
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
                  child: b == null
                      ? const SizedBox(height: 240, child: Center(child: CircularProgressIndicator(color: UW.gold)))
                      : SingleChildScrollView(
                          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                            _header(b, npc),
                            const SizedBox(height: 12),
                            LayoutBuilder(builder: (context, box) {
                              final wide = box.maxWidth > 600;
                              final bookW = _BookView(book: b, onPick: (p, s) {
                                _setPrice(p);
                                setState(() => side = s);
                              });
                              final form = _form(b);
                              return wide
                                  ? Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                                      Expanded(child: bookW),
                                      const SizedBox(width: 14),
                                      Expanded(child: form),
                                    ])
                                  : Column(children: [bookW, const SizedBox(height: 12), form]);
                            }),
                            if (b.myOrders.isNotEmpty) ...[
                              const SizedBox(height: 14),
                              Text('BU DEFTERDEKİ EMİRLERİN', style: UW.display(10, color: UW.muted)),
                              const SizedBox(height: 6),
                              for (final o in b.myOrders) OrderRow(game: g, order: o, toast: widget.toast, compact: true),
                            ],
                            const SizedBox(height: 14),
                            _TradeTape(trades: b.trades),
                          ]),
                        ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _header(OrderBook b, Price? npc) {
    final g = widget.game;
    return Row(children: [
      GoodIcon(widget.good.icon, size: 48),
      const SizedBox(width: 12),
      Expanded(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(widget.good.name, style: UW.serif(19)),
          Wrap(spacing: 6, runSpacing: 4, children: [
            if (npc != null) Chip2('Tüccar: al ₺${npc.buy.round()} · sat ₺${npc.sell.round()}', icon: Icons.storefront),
            Chip2('Sınır ₺${b.minPrice}–₺${b.maxPrice}', icon: Icons.straighten, color: UW.muted),
          ]),
        ]),
      ),
      if (b.storage > 0)
        Container(
          padding: const EdgeInsets.fromLTRB(10, 6, 6, 6),
          decoration: BoxDecoration(
            color: UW.neon.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: UW.neon.withValues(alpha: 0.5)),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.warehouse, color: UW.neon, size: 18),
            const SizedBox(width: 6),
            Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
              Text('DEPODA', style: UW.display(8.5, color: UW.muted)),
              Text('${b.storage}', style: UW.number(14, color: UW.neon)),
            ]),
            const SizedBox(width: 6),
            TextButton(
              onPressed: () async {
                try {
                  final n = await g.collect(widget.good.id);
                  widget.toast('$n ${widget.good.name} çantana alındı');
                } catch (e) {
                  widget.toast(e.toString(), error: true);
                }
              },
              child: Text('ÇANTAYA AL', style: UW.display(10, color: UW.neon, weight: FontWeight.w800)),
            ),
          ]),
        ),
    ]);
  }

  Widget _form(OrderBook b) {
    final max = _maxQty(b);
    final (fillNow, fillCost) = _instantFill(b);
    final total = price * qty;
    final c = side == 'buy' ? UW.emerald : UW.crimson;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(5),
        border: Border.all(color: c.withValues(alpha: 0.45)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: 'buy', label: Text('ALIŞ EMRİ'), icon: Icon(Icons.call_received, size: 16)),
            ButtonSegment(value: 'sell', label: Text('SATIŞ EMRİ'), icon: Icon(Icons.call_made, size: 16)),
          ],
          selected: {side},
          onSelectionChanged: (v) => setState(() => side = v.first),
          style: ButtonStyle(
            backgroundColor: WidgetStateProperty.resolveWith(
                (st) => st.contains(WidgetState.selected) ? c.withValues(alpha: 0.22) : UW.ink),
            side: WidgetStatePropertyAll(BorderSide(color: UW.gold.withValues(alpha: 0.4))),
          ),
        ),
        const SizedBox(height: 12),
        Text('BİRİM FİYAT', style: UW.display(9, color: UW.muted)),
        const SizedBox(height: 4),
        Row(children: [
          _Step(Icons.remove, () => _setPrice(math.max(b.minPrice, price - 1))),
          const SizedBox(width: 6),
          Expanded(
            child: TextField(
              controller: _price,
              textAlign: TextAlign.center,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              style: UW.number(20, color: UW.goldLight),
              decoration: const InputDecoration(isDense: true, prefixText: '₺ '),
              onChanged: (_) => setState(() {}),
            ),
          ),
          const SizedBox(width: 6),
          _Step(Icons.add, () => _setPrice(math.min(b.maxPrice, price + 1))),
        ]),
        const SizedBox(height: 6),
        Wrap(spacing: 6, runSpacing: 6, children: [
          if (b.bestBid != null) _Quick('En iyi alış ₺${b.bestBid}', () => _setPrice(b.bestBid!)),
          if (b.bestAsk != null) _Quick('En iyi satış ₺${b.bestAsk}', () => _setPrice(b.bestAsk!)),
          if (b.bestBid != null && b.bestAsk != null && b.bestAsk! - b.bestBid! > 1)
            _Quick('Araya gir', () => _setPrice(side == 'buy' ? b.bestBid! + 1 : b.bestAsk! - 1)),
        ]),
        const SizedBox(height: 12),
        Text('MİKTAR  ·  en fazla $max', style: UW.display(9, color: UW.muted)),
        const SizedBox(height: 4),
        Row(children: [
          _Step(Icons.remove, () => _setQty(qty - 1)),
          const SizedBox(width: 6),
          Expanded(
            child: TextField(
              controller: _qty,
              textAlign: TextAlign.center,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              style: UW.number(18),
              decoration: const InputDecoration(isDense: true),
              onChanged: (_) => setState(() {}),
            ),
          ),
          const SizedBox(width: 6),
          _Step(Icons.add, () => _setQty(qty + 1)),
          const SizedBox(width: 6),
          OutlinedButton(onPressed: max > 0 ? () => _setQty(max) : null, child: const Text('MAKS')),
        ]),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(color: UW.ink, borderRadius: BorderRadius.circular(4)),
          child: Column(children: [
            Row(children: [
              Text(side == 'buy' ? 'En fazla ödenecek' : 'Brüt değer', style: UW.body(12, color: UW.muted)),
              const Spacer(),
              GoldText(formatMoney(total), style: UW.number(17)),
            ]),
            const SizedBox(height: 4),
            Row(children: [
              Icon(fillNow > 0 ? Icons.flash_on : Icons.schedule, size: 14, color: fillNow > 0 ? UW.goldLight : UW.muted),
              const SizedBox(width: 4),
              Expanded(
                child: Text(
                  fillNow > 0
                      ? 'Hemen eşleşir: $fillNow adet (ort. ₺${(fillCost / fillNow).round()})${fillNow < qty ? ', kalanı deftere' : ''}'
                      : 'Deftere yazılır, karşı taraf gelince dolar',
                  style: UW.body(11, color: fillNow > 0 ? UW.goldLight : UW.muted),
                ),
              ),
            ]),
          ]),
        ),
        if (error != null) ...[
          const SizedBox(height: 8),
          Text(error!, style: UW.body(12, color: UW.crimson)),
        ],
        const SizedBox(height: 10),
        DecoButton(
          side == 'buy' ? 'Alış Emri Ver' : 'Satış Emri Ver',
          icon: side == 'buy' ? Icons.call_received : Icons.call_made,
          color: side == 'buy' ? UW.gold : const Color(0xFFE07A5F),
          loading: busy,
          onTap: price > 0 && qty > 0 && qty <= max ? _submit : null,
        ),
      ]),
    );
  }
}

class _Step extends StatelessWidget {
  final IconData icon;
  final VoidCallback onTap;
  const _Step(this.icon, this.onTap);

  @override
  Widget build(BuildContext context) => SizedBox(
        width: 36,
        height: 36,
        child: IconButton.outlined(
          padding: EdgeInsets.zero,
          onPressed: onTap,
          icon: Icon(icon, size: 18, color: UW.gold),
          style: IconButton.styleFrom(side: BorderSide(color: UW.gold.withValues(alpha: 0.4))),
        ),
      );
}

class _Quick extends StatelessWidget {
  final String label;
  final VoidCallback onTap;
  const _Quick(this.label, this.onTap);

  @override
  Widget build(BuildContext context) => InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(3),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(3),
            border: Border.all(color: UW.gold.withValues(alpha: 0.35)),
          ),
          child: Text(label, style: UW.body(11, color: UW.goldLight)),
        ),
      );
}

/// Derinlik çubuklu emir defteri: üstte satışlar (kırmızı), ortada makas, altta alışlar (yeşil).
class _BookView extends StatelessWidget {
  final OrderBook book;
  final void Function(int price, String side) onPick;
  const _BookView({required this.book, required this.onPick});

  @override
  Widget build(BuildContext context) {
    final maxQty = math.max(
      1,
      [...book.bids, ...book.asks].fold<int>(0, (m, l) => math.max(m, l.qty)),
    );
    final asks = book.asks.take(6).toList().reversed.toList();
    final bids = book.bids.take(6).toList();
    final spread = (book.bestAsk != null && book.bestBid != null) ? book.bestAsk! - book.bestBid! : null;
    final last = book.trades.isEmpty ? null : book.trades.first.price;

    Widget level(BookLevel l, bool ask) {
      final c = ask ? UW.crimson : UW.emerald;
      return InkWell(
        // Satış seviyesine tıklamak o fiyattan almaya hazırlar
        onTap: () => onPick(l.price, ask ? 'buy' : 'sell'),
        child: SizedBox(
          height: 24,
          child: Stack(children: [
            Align(
              alignment: Alignment.centerRight,
              child: FractionallySizedBox(
                widthFactor: l.qty / maxQty,
                child: Container(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(colors: [c.withValues(alpha: 0.05), c.withValues(alpha: 0.28)]),
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Row(children: [
                Text('₺${l.price}', style: UW.number(13, color: c)),
                const Spacer(),
                Text('${l.qty}', style: UW.number(12, color: UW.cream)),
                SizedBox(
                  width: 34,
                  child: Text('×${l.orders}', textAlign: TextAlign.right, style: UW.body(10, color: UW.muted)),
                ),
              ]),
            ),
          ]),
        ),
      );
    }

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF080B12),
        borderRadius: BorderRadius.circular(5),
        border: Border.all(color: UW.gold.withValues(alpha: 0.3)),
      ),
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Row(children: [
            Text('FİYAT', style: UW.display(9, color: UW.muted)),
            const Spacer(),
            Text('MİKTAR', style: UW.display(9, color: UW.muted)),
            const SizedBox(width: 34),
          ]),
        ),
        const SizedBox(height: 4),
        if (asks.isEmpty)
          Padding(
            padding: const EdgeInsets.all(8),
            child: Text('Satış emri yok', textAlign: TextAlign.center, style: UW.body(11, color: UW.muted)),
          ),
        for (final l in asks) level(l, true),
        // Makas çizgisi
        Container(
          margin: const EdgeInsets.symmetric(vertical: 6),
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
          decoration: BoxDecoration(
            border: Border.symmetric(horizontal: BorderSide(color: UW.gold.withValues(alpha: 0.5))),
            gradient: LinearGradient(colors: [UW.gold.withValues(alpha: 0.0), UW.gold.withValues(alpha: 0.12), UW.gold.withValues(alpha: 0.0)]),
          ),
          child: Row(children: [
            GoldText(last == null ? '—' : '₺$last', style: UW.number(16, weight: FontWeight.w800)),
            const SizedBox(width: 6),
            Text('son işlem', style: UW.body(10, color: UW.muted)),
            const Spacer(),
            Text(spread == null ? 'makas —' : 'makas ₺$spread', style: UW.body(11, color: UW.muted)),
          ]),
        ),
        for (final l in bids) level(l, false),
        if (bids.isEmpty)
          Padding(
            padding: const EdgeInsets.all(8),
            child: Text('Alış emri yok', textAlign: TextAlign.center, style: UW.body(11, color: UW.muted)),
          ),
        const SizedBox(height: 4),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Text('Bir satıra dokun: fiyatı forma taşır', style: UW.body(9.5, color: UW.muted)),
        ),
      ]),
    );
  }
}

class _TradeTape extends StatelessWidget {
  final List<BookTrade> trades;
  const _TradeTape({required this.trades});

  @override
  Widget build(BuildContext context) {
    final prices = trades.reversed.map((t) => t.price.toDouble()).toList();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Text('SON İŞLEMLER', style: UW.display(10, color: UW.muted)),
        const Spacer(),
        if (prices.length >= 2) Sparkline(prices, width: 120, height: 22),
      ]),
      const SizedBox(height: 6),
      if (trades.isEmpty)
        Text('Bu defterde henüz işlem olmadı. İlk emri sen ver.',
            style: UW.serif(12, color: UW.muted, weight: FontWeight.w400))
      else
        for (final t in trades.take(8))
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Row(children: [
              SizedBox(width: 52, child: Text(_ago(t.at), style: UW.body(10.5, color: UW.muted))),
              SizedBox(width: 60, child: Text('₺${t.price}', style: UW.number(12, color: UW.goldLight))),
              SizedBox(width: 50, child: Text('×${t.qty}', style: UW.number(12))),
              Expanded(
                child: Text('${t.seller ?? '?'} → ${t.buyer ?? '?'}',
                    overflow: TextOverflow.ellipsis, style: UW.body(11, color: UW.cream.withValues(alpha: 0.75))),
              ),
            ]),
          ),
    ]);
  }
}

String _ago(DateTime t) {
  final d = DateTime.now().difference(t);
  if (d.inMinutes < 1) return 'şimdi';
  if (d.inHours < 1) return '${d.inMinutes} dk';
  if (d.inDays < 1) return '${d.inHours} sa';
  return '${d.inDays} g';
}

// ====================== EMİR SATIRI (çanta ve defterde) ======================
class OrderRow extends StatefulWidget {
  final GameState game;
  final MyOrder order;
  final Toast toast;
  final bool compact;
  const OrderRow({super.key, required this.game, required this.order, required this.toast, this.compact = false});

  @override
  State<OrderRow> createState() => _OrderRowState();
}

class _OrderRowState extends State<OrderRow> {
  bool busy = false;

  @override
  Widget build(BuildContext context) {
    final o = widget.order;
    final g = widget.game;
    final good = o.goodId == null ? null : g.good(o.goodId!);
    final where = o.districtId == null ? null : g.district(o.districtId!);
    final c = o.side == 'buy' ? UW.emerald : UW.crimson;
    final filled = o.qtyTotal - o.qtyLeft;
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.25),
        borderRadius: BorderRadius.circular(4),
        border: Border(left: BorderSide(color: c, width: 3)),
      ),
      child: Row(children: [
        if (!widget.compact && good != null) ...[GoodIcon(good.icon, size: 30), const SizedBox(width: 8)],
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(
              '${o.side == 'buy' ? 'ALIŞ' : 'SATIŞ'}  ${o.qtyLeft} × ₺${o.price}${widget.compact ? '' : '  ·  ${good?.name ?? ''}'}',
              style: UW.body(13, color: c, weight: FontWeight.w700),
            ),
            Text(
              [
                if (!widget.compact && where != null) where.name,
                if (filled > 0) '$filled/${o.qtyTotal} doldu',
                if (o.expiresAt != null) 'bitiş ${_left(o.expiresAt!)}',
              ].join(' · '),
              style: UW.body(10.5, color: UW.muted),
            ),
          ]),
        ),
        busy
            ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: UW.gold))
            : TextButton(
                onPressed: () async {
                  setState(() => busy = true);
                  try {
                    await g.cancelOrder(o);
                    widget.toast(o.side == 'buy' ? 'Emir iptal edildi, emanet para iade edildi' : 'Emir iptal edildi, mal depoya döndü');
                  } catch (e) {
                    widget.toast(e.toString(), error: true);
                  } finally {
                    if (mounted) setState(() => busy = false);
                  }
                },
                child: Text('İPTAL', style: UW.display(10, color: UW.crimson, weight: FontWeight.w800)),
              ),
      ]),
    );
  }
}

String _left(DateTime t) {
  final d = t.difference(DateTime.now());
  if (d.isNegative) return 'şimdi';
  if (d.inHours >= 1) return '${d.inHours} sa';
  return '${d.inMinutes} dk';
}

// ====================== ÇANTA: DEPOLAR VE EMİRLER ======================
class MarketHoldings extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const MarketHoldings({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    final me = game.me!;
    if (game.storage.isEmpty && game.myOrders.isEmpty) return const SizedBox();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      if (game.storage.isNotEmpty) ...[
        const SizedBox(height: 12),
        Text('DEPOLARIM', style: UW.display(11, color: UW.muted)),
        const SizedBox(height: 6),
        for (final s in game.storage)
          Builder(builder: (context) {
            final good = game.good(s.goodId);
            final d = game.district(s.districtId);
            final here = s.districtId == me.districtId && me.travel == null;
            return Container(
              margin: const EdgeInsets.only(bottom: 6),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: UW.neon.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: UW.neon.withValues(alpha: 0.25)),
              ),
              child: Row(children: [
                if (good != null) GoodIcon(good.icon, size: 30),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('${s.qty} × ${good?.name ?? s.goodId}', style: UW.serif(14)),
                    Text('${d?.name ?? s.districtId} deposu · maliyet ₺${s.avgCost}', style: UW.body(10.5, color: UW.muted)),
                  ]),
                ),
                if (here)
                  TextButton(
                    onPressed: () async {
                      try {
                        final n = await game.collect(s.goodId);
                        toast('$n ${good?.name ?? ''} çantana alındı');
                      } catch (e) {
                        toast(e.toString(), error: true);
                      }
                    },
                    child: Text('ÇANTAYA AL', style: UW.display(10, color: UW.neon, weight: FontWeight.w800)),
                  )
                else
                  const Icon(Icons.lock_outline, size: 16, color: UW.muted),
              ]),
            );
          }),
      ],
      if (game.myOrders.isNotEmpty) ...[
        const SizedBox(height: 12),
        Text('AÇIK BORSA EMİRLERİM  ${game.myOrders.length}/10', style: UW.display(11, color: UW.muted)),
        const SizedBox(height: 6),
        for (final o in game.myOrders) OrderRow(game: game, order: o, toast: toast),
      ],
    ]);
  }
}
