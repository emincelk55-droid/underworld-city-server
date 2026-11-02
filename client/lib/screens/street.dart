import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/crest.dart';
import '../widgets/deco.dart';
import 'gang_panel.dart' show Countdown;

// ====================== FÖTR ŞAPKALI SİLÜET ======================
/// 1930'lar gangster silüeti: fötr şapka, palto yakası. Şapka bandı aile renginde.
class NoirAvatar extends StatelessWidget {
  final double size;
  final Color? band;
  final bool online;
  final bool dim;
  final int seed;
  const NoirAvatar({super.key, this.size = 56, this.band, this.online = false, this.dim = false, this.seed = 0});

  @override
  Widget build(BuildContext context) => SizedBox(
        width: size,
        height: size,
        child: CustomPaint(painter: _AvatarPainter(band ?? UW.muted, online, dim, seed)),
      );
}

class _AvatarPainter extends CustomPainter {
  final Color band;
  final bool online, dim;
  final int seed;
  _AvatarPainter(this.band, this.online, this.dim, this.seed);

  @override
  void paint(Canvas canvas, Size s) {
    final w = s.width, h = s.height;
    final c = Offset(w / 2, h / 2);
    final r = w / 2;
    final rnd = math.Random(seed);

    // Arka plan: sokak lambası ışığı
    canvas.drawCircle(
        c,
        r,
        Paint()
          ..shader = RadialGradient(
            center: const Alignment(0.3, -0.5),
            colors: [
              Color.lerp(band, UW.goldLight, 0.4)!.withValues(alpha: dim ? 0.25 : 0.55),
              Color.lerp(band, Colors.black, 0.6)!,
              UW.ink,
            ],
            stops: const [0, 0.55, 1],
          ).createShader(Rect.fromCircle(center: c, radius: r)));

    canvas.save();
    canvas.clipPath(Path()..addOval(Rect.fromCircle(center: c, radius: r - 1)));
    final ink = Paint()..color = const Color(0xFF07080C);

    // Palto ve omuzlar
    final coat = Path()
      ..moveTo(w * 0.05, h * 1.05)
      ..quadraticBezierTo(w * 0.08, h * 0.74, w * 0.36, h * 0.68)
      ..lineTo(w * 0.64, h * 0.68)
      ..quadraticBezierTo(w * 0.92, h * 0.74, w * 0.95, h * 1.05)
      ..close();
    canvas.drawPath(coat, ink);
    // Yaka (V)
    final lapel = Paint()
      ..color = Color.lerp(band, Colors.black, 0.55)!.withValues(alpha: 0.9)
      ..style = PaintingStyle.stroke
      ..strokeWidth = w * 0.025;
    canvas.drawLine(Offset(w * 0.4, h * 0.69), Offset(w * 0.5, h * 0.9), lapel);
    canvas.drawLine(Offset(w * 0.6, h * 0.69), Offset(w * 0.5, h * 0.9), lapel);
    // Kravat (rastgele: kravat ya da papyon)
    if (rnd.nextBool()) {
      canvas.drawPath(
          Path()
            ..moveTo(w * 0.47, h * 0.71)
            ..lineTo(w * 0.53, h * 0.71)
            ..lineTo(w * 0.55, h * 0.95)
            ..lineTo(w * 0.5, h * 1.0)
            ..lineTo(w * 0.45, h * 0.95)
            ..close(),
          Paint()..color = band.withValues(alpha: 0.85));
    } else {
      canvas.drawPath(
          Path()
            ..moveTo(w * 0.42, h * 0.7)
            ..lineTo(w * 0.5, h * 0.74)
            ..lineTo(w * 0.58, h * 0.7)
            ..lineTo(w * 0.58, h * 0.78)
            ..lineTo(w * 0.5, h * 0.74)
            ..lineTo(w * 0.42, h * 0.78)
            ..close(),
          Paint()..color = band.withValues(alpha: 0.85));
    }

    // Boyun ve baş
    canvas.drawRect(Rect.fromLTWH(w * 0.44, h * 0.55, w * 0.12, h * 0.16), ink);
    canvas.drawOval(Rect.fromCenter(center: Offset(w * 0.5, h * 0.48), width: w * 0.3, height: h * 0.34), ink);

    // Fötr şapka: siper + tepe
    canvas.drawOval(Rect.fromCenter(center: Offset(w * 0.5, h * 0.36), width: w * 0.62, height: h * 0.11), ink);
    final crown = Path()
      ..moveTo(w * 0.33, h * 0.36)
      ..quadraticBezierTo(w * 0.32, h * 0.18, w * 0.42, h * 0.16)
      ..quadraticBezierTo(w * 0.5, h * 0.21, w * 0.58, h * 0.16)
      ..quadraticBezierTo(w * 0.68, h * 0.18, w * 0.67, h * 0.36)
      ..close();
    canvas.drawPath(crown, ink);
    // Şapka bandı
    canvas.drawRect(Rect.fromLTWH(w * 0.335, h * 0.3, w * 0.33, h * 0.04), Paint()..color = band);
    // Kenar ışığı (rim light)
    canvas.drawPath(
        crown,
        Paint()
          ..color = UW.goldLight.withValues(alpha: dim ? 0.1 : 0.35)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1);
    // Sigara dumanı (bazılarında)
    if (rnd.nextDouble() < 0.4) {
      final smoke = Paint()
        ..color = Colors.white.withValues(alpha: 0.25)
        ..style = PaintingStyle.stroke
        ..strokeWidth = w * 0.02
        ..strokeCap = StrokeCap.round;
      canvas.drawLine(Offset(w * 0.6, h * 0.56), Offset(w * 0.7, h * 0.55), Paint()
        ..color = Colors.white.withValues(alpha: 0.7)
        ..strokeWidth = w * 0.025);
      canvas.drawCircle(Offset(w * 0.71, h * 0.55), w * 0.012, Paint()..color = const Color(0xFFFF8A3D));
      canvas.drawPath(
          Path()
            ..moveTo(w * 0.72, h * 0.53)
            ..quadraticBezierTo(w * 0.78, h * 0.45, w * 0.72, h * 0.38)
            ..quadraticBezierTo(w * 0.68, h * 0.3, w * 0.76, h * 0.22),
          smoke);
    }
    canvas.restore();

    // Çerçeve
    canvas.drawCircle(
        c,
        r - 1,
        Paint()
          ..color = dim ? UW.muted.withValues(alpha: 0.4) : UW.gold
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.6);
    if (online) {
      final p = Offset(w * 0.85, h * 0.85);
      canvas.drawCircle(p, w * 0.09, Paint()..color = UW.ink);
      canvas.drawCircle(p, w * 0.065, Paint()..color = UW.emerald);
    }
  }

  @override
  bool shouldRepaint(covariant _AvatarPainter old) =>
      old.band != band || old.online != online || old.dim != dim || old.seed != seed;
}

// ====================== SOKAK EKRANI ======================
class StreetSheet extends StatefulWidget {
  final GameState game;
  final void Function(Map<String, dynamic> result) onResult;
  const StreetSheet({super.key, required this.game, required this.onResult});

  @override
  State<StreetSheet> createState() => _StreetSheetState();
}

class _StreetSheetState extends State<StreetSheet> {
  int? busyId;
  String? error;
  bool showRecord = false;

  @override
  void initState() {
    super.initState();
    widget.game.loadStreet().catchError((_) {});
    widget.game.loadRobRecords().catchError((_) {});
  }

  Future<void> _rob(StreetPerson p) async {
    setState(() {
      busyId = p.userId;
      error = null;
    });
    try {
      final r = await widget.game.rob(p.userId);
      if (!mounted) return;
      Navigator.pop(context);
      widget.onResult(r);
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busyId = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    return ListenableBuilder(
      listenable: g,
      builder: (context, _) {
        final st = g.street;
        final me = g.me!;
        final d = g.district(me.districtId);
        return Center(
          heightFactor: 1,
          child: ConstrainedBox(
            constraints: BoxConstraints(maxWidth: 560, maxHeight: MediaQuery.sizeOf(context).height * 0.88),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: DecoPanel(
                accent: UW.crimson,
                glow: true,
                padding: const EdgeInsets.fromLTRB(18, 18, 18, 14),
                child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    const Icon(Icons.nightlife, color: UW.crimson, size: 22),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text('SOKAK', style: UW.display(18, color: UW.goldLight, weight: FontWeight.w900)),
                        Text('${d?.name ?? ''} · karanlık köşeler', style: UW.serif(12, color: UW.muted, weight: FontWeight.w400)),
                      ]),
                    ),
                    if (st != null) ...[
                      Chip2('⚡${st.robEnergy}', color: UW.neon),
                      const SizedBox(width: 6),
                      Chip2('Polis %${st.policeRisk}', icon: Icons.local_police, color: UW.crimson),
                    ],
                  ]),
                  const SizedBox(height: 10),
                  if (me.protectedUntil != null && me.protectedUntil!.isAfter(DateTime.now()))
                    _Notice(
                      icon: Icons.shield,
                      color: UW.neon,
                      child: Row(children: [
                        Text('Korumadasın: ', style: UW.body(12, color: UW.neon)),
                        Countdown(to: me.protectedUntil!, style: UW.number(12, color: UW.neon)),
                        Expanded(
                          child: Text('  · Soygun yaparsan koruman biter.',
                              style: UW.body(12, color: UW.muted), overflow: TextOverflow.ellipsis),
                        ),
                      ]),
                    ),
                  if (error != null) _Notice(icon: Icons.error_outline, color: UW.crimson, child: Text(error!, style: UW.body(12, color: UW.crimson))),
                  Flexible(
                    child: st == null
                        ? const Padding(
                            padding: EdgeInsets.all(30),
                            child: Center(child: CircularProgressIndicator(color: UW.gold)),
                          )
                        : (me.travel != null)
                            ? _Empty(icon: Icons.directions_car_filled, text: 'Yoldasın. Sokakta kimseyi göremezsin.')
                            : st.people.isEmpty
                                ? _Empty(icon: Icons.nights_stay, text: 'Sokaklar sessiz. Burada senden başka kimse yok.')
                                : ListView.separated(
                                    shrinkWrap: true,
                                    itemCount: st.people.length,
                                    separatorBuilder: (_, _) => const SizedBox(height: 8),
                                    itemBuilder: (_, i) => _PersonCard(
                                      person: st.people[i],
                                      busy: busyId == st.people[i].userId,
                                      canAfford: me.energy >= st.robEnergy,
                                      onRob: busyId == null ? () => _rob(st.people[i]) : null,
                                    ),
                                  ),
                  ),
                  const SizedBox(height: 10),
                  InkWell(
                    onTap: () => setState(() => showRecord = !showRecord),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 6),
                      child: Row(children: [
                        const Icon(Icons.menu_book, size: 16, color: UW.gold),
                        const SizedBox(width: 6),
                        Text('SİCİL', style: UW.display(11, color: UW.gold)),
                        const Spacer(),
                        Icon(showRecord ? Icons.expand_less : Icons.expand_more, color: UW.gold),
                      ]),
                    ),
                  ),
                  if (showRecord)
                    ConstrainedBox(
                      constraints: const BoxConstraints(maxHeight: 180),
                      child: g.robRecords.isEmpty
                          ? Text('Temiz sicil. Şimdilik.', style: UW.serif(12, color: UW.muted, weight: FontWeight.w400))
                          : ListView(shrinkWrap: true, children: [for (final r in g.robRecords) _RecordRow(r: r, game: g)]),
                    ),
                ]),
              ),
            ),
          ),
        );
      },
    );
  }
}

class _Notice extends StatelessWidget {
  final IconData icon;
  final Color color;
  final Widget child;
  const _Notice({required this.icon, required this.color, required this.child});

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withValues(alpha: 0.4)),
        ),
        child: Row(children: [Icon(icon, size: 16, color: color), const SizedBox(width: 8), Expanded(child: child)]),
      );
}

class _Empty extends StatelessWidget {
  final IconData icon;
  final String text;
  const _Empty({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 30),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, size: 40, color: UW.gold.withValues(alpha: 0.5)),
          const SizedBox(height: 8),
          Text(text, textAlign: TextAlign.center, style: UW.serif(14, color: UW.muted, weight: FontWeight.w400)),
        ]),
      );
}

class _PersonCard extends StatelessWidget {
  final StreetPerson person;
  final bool busy, canAfford;
  final VoidCallback? onRob;
  const _PersonCard({required this.person, required this.busy, required this.canAfford, this.onRob});

  @override
  Widget build(BuildContext context) {
    final p = person;
    final gc = p.gang == null ? null : hexColor(p.gang!.color);
    final oddsColor = p.odds >= 60 ? UW.emerald : (p.odds >= 40 ? UW.gold : UW.crimson);
    final (wealthText, wealthN) = switch (p.wealth) {
      'rich' => ('Zengin', 3),
      'comfortable' => ('Orta halli', 2),
      _ => ('Cebi boş', 1),
    };
    final dim = !p.robbable;
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: LinearGradient(colors: [
          p.revenge ? UW.crimson.withValues(alpha: 0.18) : UW.panelHi,
          UW.panel,
        ]),
        border: Border.all(
            color: p.revenge ? UW.crimson.withValues(alpha: 0.8) : (gc ?? UW.gold).withValues(alpha: dim ? 0.15 : 0.35)),
      ),
      child: Row(children: [
        Opacity(
          opacity: dim ? 0.55 : 1,
          child: NoirAvatar(size: 54, band: gc, online: p.online, dim: dim, seed: p.userId),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              if (p.gang != null) ...[
                GangCrest(color: p.gang!.color, emblem: p.gang!.emblem, tag: p.gang!.tag, size: 16),
                const SizedBox(width: 5),
              ],
              Flexible(child: Text(p.username, style: UW.serif(15), overflow: TextOverflow.ellipsis)),
              const SizedBox(width: 6),
              Text('Sv ${p.level}', style: UW.body(11, color: UW.muted)),
            ]),
            const SizedBox(height: 5),
            Wrap(spacing: 5, runSpacing: 4, children: [
              if (p.revenge) const Chip2('İNTİKAM +%15', icon: Icons.whatshot, color: UW.crimson),
              if (p.ally) const Chip2('Aileden', icon: Icons.handshake, color: UW.emerald),
              if (p.isProtected)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: UW.neon.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(3),
                    border: Border.all(color: UW.neon.withValues(alpha: 0.4), width: 0.8),
                  ),
                  child: Row(mainAxisSize: MainAxisSize.min, children: [
                    const Icon(Icons.shield, size: 12, color: UW.neon),
                    const SizedBox(width: 4),
                    Countdown(to: p.protectedUntil!, style: UW.number(11, color: UW.neon, weight: FontWeight.w600)),
                  ]),
                ),
              Chip2('$wealthText ${'₺' * wealthN}', color: wealthN == 3 ? UW.goldLight : UW.muted),
            ]),
          ]),
        ),
        const SizedBox(width: 8),
        if (p.robbable)
          Column(mainAxisSize: MainAxisSize.min, children: [
            Text('%${p.odds}', style: UW.number(18, color: oddsColor, weight: FontWeight.w800)),
            Text('şans', style: UW.body(10, color: UW.muted)),
            const SizedBox(height: 4),
            SizedBox(
              width: 76,
              child: _RobButton(busy: busy, onTap: canAfford ? onRob : null),
            ),
          ]),
      ]),
    );
  }
}

class _RobButton extends StatelessWidget {
  final bool busy;
  final VoidCallback? onTap;
  const _RobButton({required this.busy, this.onTap});

  @override
  Widget build(BuildContext context) => Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: busy ? null : onTap,
          borderRadius: BorderRadius.circular(4),
          child: Opacity(
            opacity: onTap == null ? 0.4 : 1,
            child: Container(
              height: 32,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                gradient: const LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [Color(0xFFF07080), UW.crimson, Color(0xFF7A1F2B)],
                ),
                boxShadow: [BoxShadow(color: UW.crimson.withValues(alpha: 0.45), blurRadius: 10)],
              ),
              child: busy
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : Row(mainAxisSize: MainAxisSize.min, children: [
                      const Icon(Icons.back_hand, size: 14, color: Colors.white),
                      const SizedBox(width: 5),
                      Text('SOY', style: UW.display(12, color: Colors.white, weight: FontWeight.w900)),
                    ]),
            ),
          ),
        ),
      );
}

class _RecordRow extends StatelessWidget {
  final RobRecord r;
  final GameState game;
  const _RecordRow({required this.r, required this.game});

  @override
  Widget build(BuildContext context) {
    final where = game.district(r.districtId)?.name ?? '';
    final (icon, color, text) = switch ((r.mine, r.outcome)) {
      (true, 'success') => (Icons.back_hand, UW.emerald, '${r.target} soyuldu: +${formatMoney(r.cash)}'),
      (true, 'escaped') => (Icons.directions_run, UW.muted, '${r.target} kaçtı'),
      (true, 'caught') => (Icons.local_police, UW.crimson, '${r.target} soyulurken polise yakalandın'),
      (false, 'success') => (Icons.money_off, UW.crimson, '${r.attacker} seni soydu: -${formatMoney(r.cash)}'),
      _ => (Icons.shield, UW.neon, '${r.attacker} seni soymaya çalıştı, kaçtın'),
    };
    final ago = DateTime.now().difference(r.at);
    final agoText = ago.inMinutes < 1 ? 'az önce' : (ago.inHours < 1 ? '${ago.inMinutes} dk' : '${ago.inHours} sa');
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(children: [
        Icon(icon, size: 16, color: color),
        const SizedBox(width: 8),
        Expanded(child: Text(text, style: UW.body(12, color: UW.cream.withValues(alpha: 0.9)))),
        Text('$where · $agoText', style: UW.body(10, color: UW.muted)),
      ]),
    );
  }
}

// ====================== SONUÇ PENCERELERİ ======================
class RobResultDialog extends StatelessWidget {
  final Map<String, dynamic> result;
  const RobResultDialog({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final outcome = result['outcome'];
    final goods = (result['goods'] as List? ?? []);
    late final Color color;
    late final IconData icon;
    late final String title, text;
    switch (outcome) {
      case 'success':
        color = UW.goldLight;
        icon = Icons.back_hand;
        title = result['revenge'] == true ? 'İntikam Alındı' : 'Soygun Başarılı';
        text = '${result['target']} karanlık bir köşede köşeye sıkıştı.';
      case 'caught':
        color = UW.crimson;
        icon = Icons.local_police;
        title = 'Polise Yakalandın';
        text = 'Daha elini cebine atamadan düdük çaldı. ${formatMoney(result['fine'] ?? 0)} ceza ödedin.';
      default:
        color = UW.muted;
        icon = Icons.directions_run;
        title = 'Kaçtı!';
        text = '${result['target']} seni fark etti ve kalabalığa karıştı.';
    }
    return _DramaDialog(
      color: color,
      icon: icon,
      title: title,
      text: text,
      extra: outcome == 'success'
          ? Column(children: [
              GoldText('+${formatMoney(result['cash'] ?? 0)}', style: UW.number(30, weight: FontWeight.w900)),
              for (final g in goods)
                Text('+${g['qty']} ${g['name']}', style: UW.body(14, color: UW.emerald, weight: FontWeight.w700)),
              const SizedBox(height: 4),
              Text('Başarı şansı %${result['chance']}', style: UW.body(11, color: UW.muted)),
            ])
          : Text('Başarı şansı %${result['chance']}', style: UW.body(11, color: UW.muted)),
    );
  }
}

class RobbedDialog extends StatelessWidget {
  final GameState game;
  final Map<String, dynamic> data;
  const RobbedDialog({super.key, required this.game, required this.data});

  @override
  Widget build(BuildContext context) {
    final success = data['success'] == true;
    final where = game.district(data['districtId'] ?? '')?.name ?? '';
    final goods = (data['goods'] as List? ?? []);
    return _DramaDialog(
      color: success ? UW.crimson : UW.neon,
      icon: success ? Icons.money_off : Icons.shield,
      title: success ? 'Soyuldun!' : 'Kıl Payı Kurtuldun',
      text: success
          ? '$where sokaklarında ${data['attacker']} seni soydu.'
          : '${data['attacker']} $where sokaklarında seni soymaya kalktı ama elinden kaçtın.',
      extra: success
          ? Column(children: [
              Text('-${formatMoney(data['cash'] ?? 0)}', style: UW.number(28, color: UW.crimson, weight: FontWeight.w900)),
              for (final g in goods) Text('-${g['qty']} ${g['name']}', style: UW.body(14, color: UW.crimson)),
              const SizedBox(height: 8),
              const Chip2('24 saat boyunca intikam bonusu: +%15', icon: Icons.whatshot, color: UW.goldLight),
              const SizedBox(height: 4),
              Text('30 dakika boyunca koruma altındasın.', style: UW.body(11, color: UW.muted)),
            ])
          : null,
    );
  }
}

class _DramaDialog extends StatelessWidget {
  final Color color;
  final IconData icon;
  final String title, text;
  final Widget? extra;
  const _DramaDialog({required this.color, required this.icon, required this.title, required this.text, this.extra});

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: Colors.transparent,
      child: TweenAnimationBuilder<double>(
        tween: Tween(begin: 0, end: 1),
        duration: const Duration(milliseconds: 520),
        curve: Curves.easeOutBack,
        builder: (context, v, child) => Transform.scale(scale: 0.7 + 0.3 * v, child: Opacity(opacity: v.clamp(0, 1), child: child)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 380),
          child: DecoPanel(
            accent: color,
            glow: true,
            padding: const EdgeInsets.fromLTRB(22, 26, 22, 18),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Stack(alignment: Alignment.center, children: [
                // Patlama efekti
                CustomPaint(size: const Size(120, 120), painter: _BurstPainter(color)),
                Container(
                  width: 78,
                  height: 78,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: UW.ink,
                    border: Border.all(color: color, width: 2),
                    boxShadow: [BoxShadow(color: color.withValues(alpha: 0.5), blurRadius: 26)],
                  ),
                  child: Icon(icon, size: 38, color: color),
                ),
              ]),
              const SizedBox(height: 8),
              Text(title.toUpperCase(), textAlign: TextAlign.center, style: UW.display(21, color: color, weight: FontWeight.w900)),
              const SizedBox(height: 8),
              Text(text, textAlign: TextAlign.center, style: UW.serif(14, weight: FontWeight.w400)),
              if (extra != null) ...[const SizedBox(height: 14), extra!],
              const SizedBox(height: 18),
              DecoButton('Tamam', color: color == UW.muted ? UW.gold : color, onTap: () => Navigator.pop(context)),
            ]),
          ),
        ),
      ),
    );
  }
}

class _BurstPainter extends CustomPainter {
  final Color color;
  _BurstPainter(this.color);

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final p = Paint()..color = color.withValues(alpha: 0.35);
    final path = Path();
    for (var i = 0; i < 24; i++) {
      final a = i * math.pi / 12;
      final r = i.isEven ? size.width / 2 : size.width / 2 * 0.62;
      final pt = c + Offset(math.cos(a), math.sin(a)) * r;
      i == 0 ? path.moveTo(pt.dx, pt.dy) : path.lineTo(pt.dx, pt.dy);
    }
    canvas.drawPath(path..close(), p);
  }

  @override
  bool shouldRepaint(covariant _BurstPainter old) => old.color != color;
}
