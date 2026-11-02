import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import '../models.dart';
import '../theme.dart';

const _roads = [
  ['liman', 'fabrika'],
  ['liman', 'carsi'],
  ['liman', 'gecekondu'],
  ['fabrika', 'carsi'],
  ['fabrika', 'merkez'],
  ['carsi', 'merkez'],
  ['carsi', 'villalar'],
  ['carsi', 'gecekondu'],
  ['merkez', 'villalar'],
  ['villalar', 'gecekondu'],
];

/// Kuşbakışı, art deco tarzı şehir haritası.
class CityMap extends StatefulWidget {
  final List<District> districts;
  final String? currentId;
  final String? selectedId;
  final Travel? travel;
  final Map<String, Territory> territory;
  final int? myGangId;
  final Map<String, int> businessCounts;
  final ValueChanged<District> onTap;
  const CityMap({
    super.key,
    this.businessCounts = const {},
    this.territory = const {},
    this.myGangId,
    required this.districts,
    required this.currentId,
    required this.selectedId,
    required this.travel,
    required this.onTap,
  });

  @override
  State<CityMap> createState() => _CityMapState();
}

class _CityMapState extends State<CityMap> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 6))..repeat();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  Rect _area(Size s) => Rect.fromLTWH(s.width * 0.08, s.height * 0.1, s.width * 0.84, s.height * 0.78);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, box) {
      final size = Size(box.maxWidth, box.maxHeight);
      final area = _area(size);
      return GestureDetector(
        onTapUp: (d) {
          District? best;
          var bestDist = double.infinity;
          for (final dist in widget.districts) {
            final p = Offset(area.left + dist.x * area.width, area.top + dist.y * area.height);
            final dd = (p - d.localPosition).distance;
            if (dd < bestDist) {
              bestDist = dd;
              best = dist;
            }
          }
          if (best != null && bestDist < 70) widget.onTap(best);
        },
        child: RepaintBoundary(
          child: AnimatedBuilder(
            animation: _c,
            builder: (_, _) => CustomPaint(
              size: size,
              painter: _MapPainter(
                t: _c.value,
                area: area,
                districts: widget.districts,
                currentId: widget.currentId,
                selectedId: widget.selectedId,
                travel: widget.travel,
                territory: widget.territory,
                myGangId: widget.myGangId,
                businessCounts: widget.businessCounts,
                now: DateTime.now(),
              ),
            ),
          ),
        ),
      );
    });
  }
}

class _MapPainter extends CustomPainter {
  final double t;
  final Rect area;
  final List<District> districts;
  final String? currentId, selectedId;
  final Travel? travel;
  final Map<String, Territory> territory;
  final int? myGangId;
  final Map<String, int> businessCounts;
  final DateTime now;

  _MapPainter({
    required this.businessCounts,
    required this.territory,
    required this.myGangId,
    required this.t,
    required this.area,
    required this.districts,
    required this.currentId,
    required this.selectedId,
    required this.travel,
    required this.now,
  });

  Offset pos(District d) => Offset(area.left + d.x * area.width, area.top + d.y * area.height);

  District? byId(String? id) {
    for (final d in districts) {
      if (d.id == id) return d;
    }
    return null;
  }

  @override
  void paint(Canvas canvas, Size size) {
    final full = Offset.zero & size;
    final w = size.width, h = size.height;

    // Zemin
    canvas.drawRect(
        full,
        Paint()
          ..shader = const RadialGradient(
            center: Alignment(0.1, -0.1),
            radius: 1.1,
            colors: [Color(0xFF24304A), Color(0xFF141C2E), Color(0xFF0A0E18)],
          ).createShader(full));

    // Sokak ızgarası
    final grid = Paint()
      ..color = const Color(0xFF3A4868).withValues(alpha: 0.4)
      ..strokeWidth = 0.6;
    const step = 22.0;
    canvas.save();
    canvas.translate(w / 2, h / 2);
    canvas.rotate(-0.08);
    for (var x = -w; x < w; x += step) {
      canvas.drawLine(Offset(x, -h), Offset(x, h), grid);
    }
    for (var y = -h; y < h; y += step) {
      canvas.drawLine(Offset(-w, y), Offset(w, y), grid);
    }
    canvas.restore();

    // Bina blokları
    final rnd = math.Random(7);
    for (var i = 0; i < 520; i++) {
      final p = Offset(rnd.nextDouble() * w, rnd.nextDouble() * h);
      District? near;
      var nd = double.infinity;
      for (final d in districts) {
        final dd = (pos(d) - p).distance;
        if (dd < nd) {
          nd = dd;
          near = d;
        }
      }
      final influence = (1 - nd / (math.min(w, h) * 0.28)).clamp(0.0, 1.0);
      final c = Color.lerp(const Color(0xFF2A3550), hexColor(near!.color), influence * 0.5)!;
      final bw = 6 + rnd.nextDouble() * 14, bh = 6 + rnd.nextDouble() * 14;
      canvas.save();
      canvas.translate(p.dx, p.dy);
      canvas.rotate(-0.08);
      canvas.drawRect(Rect.fromCenter(center: Offset.zero, width: bw, height: bh),
          Paint()..color = c.withValues(alpha: 0.5 + influence * 0.4));
      if (rnd.nextDouble() < 0.15) {
        canvas.drawRect(Rect.fromCenter(center: Offset.zero, width: 2, height: 2),
            Paint()..color = UW.goldLight.withValues(alpha: 0.5));
      }
      canvas.restore();
    }

    // Su (liman körfezi)
    final water = Path()
      ..moveTo(0, h * 0.52)
      ..cubicTo(w * 0.1, h * 0.55, w * 0.06, h * 0.7, w * 0.14, h * 0.78)
      ..cubicTo(w * 0.22, h * 0.86, w * 0.36, h * 0.88, w * 0.42, h)
      ..lineTo(0, h)
      ..close();
    canvas.drawPath(
        water,
        Paint()
          ..shader = const LinearGradient(
            begin: Alignment.topRight,
            end: Alignment.bottomLeft,
            colors: [Color(0xFF15506B), Color(0xFF0A2636)],
          ).createShader(full));
    canvas.drawPath(
        water,
        Paint()
          ..color = UW.neon.withValues(alpha: 0.35)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.4
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 2));
    canvas.save();
    canvas.clipPath(water);
    final wave = Paint()
      ..color = UW.neon.withValues(alpha: 0.2)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    for (var i = 0; i < 14; i++) {
      final y = h * 0.5 + i * 18.0;
      final path = Path()..moveTo(0, y);
      for (var x = 0.0; x <= w * 0.5; x += 10) {
        path.lineTo(x, y + math.sin(x / 26 + t * math.pi * 2 + i) * 3);
      }
      canvas.drawPath(path, wave);
    }
    // İskeleler
    for (var i = 0; i < 4; i++) {
      final p = Offset(w * (0.06 + i * 0.035), h * (0.6 + i * 0.05));
      canvas.drawRect(Rect.fromLTWH(p.dx - 26, p.dy, 30, 4), Paint()..color = const Color(0xFF3A3020));
    }
    canvas.restore();

    // Çete bölgeleri: kontrol eden çetenin renginde alan
    for (final d in districts) {
      final ter = territory[d.id];
      final ctrl = ter?.controller;
      if (ctrl == null) continue;
      final gc = hexColor(ctrl.color);
      final p = pos(d);
      final rad = math.min(w, h) * 0.17;
      canvas.drawCircle(
          p,
          rad,
          Paint()
            ..shader = RadialGradient(colors: [gc.withValues(alpha: 0.38), gc.withValues(alpha: 0.12), gc.withValues(alpha: 0)], stops: const [0, 0.7, 1])
                .createShader(Rect.fromCircle(center: p, radius: rad)));
      final ring = Paint()
        ..color = gc.withValues(alpha: 0.75)
        ..style = PaintingStyle.stroke
        ..strokeWidth = ctrl.id == myGangId ? 2 : 1.2;
      // kesikli sınır çizgisi (yavaşça döner)
      const segs = 36;
      for (var i = 0; i < segs; i += 2) {
        final a0 = i * 2 * math.pi / segs + t * 0.6;
        canvas.drawArc(Rect.fromCircle(center: p, radius: rad * 0.72), a0, 2 * math.pi / segs, false, ring);
      }
    }

    // Yollar
    final roadDark = Paint()
      ..color = const Color(0xFF05070C)
      ..strokeWidth = 9
      ..strokeCap = StrokeCap.round;
    final roadGold = Paint()
      ..color = UW.gold.withValues(alpha: 0.28)
      ..strokeWidth = 1.4
      ..strokeCap = StrokeCap.round;
    for (final r in _roads) {
      final a = byId(r[0]), b = byId(r[1]);
      if (a == null || b == null) continue;
      canvas.drawLine(pos(a), pos(b), roadDark);
    }
    for (final r in _roads) {
      final a = byId(r[0]), b = byId(r[1]);
      if (a == null || b == null) continue;
      _dashed(canvas, pos(a), pos(b), roadGold, 6, 6, 0);
    }

    // Yolculuk rotası
    final tr = travel;
    if (tr != null) {
      final a = byId(tr.from), b = byId(tr.to);
      if (a != null && b != null) {
        final pa = pos(a), pb = pos(b);
        canvas.drawLine(
            pa,
            pb,
            Paint()
              ..color = UW.goldLight.withValues(alpha: 0.35)
              ..strokeWidth = 8
              ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 6));
        _dashed(
            canvas,
            pa,
            pb,
            Paint()
              ..color = UW.goldLight
              ..strokeWidth = 2.4
              ..strokeCap = StrokeCap.round,
            10,
            8,
            -t * 18 * 6);
        final prog = tr.progress(now);
        final car = Offset.lerp(pa, pb, prog)!;
        for (var i = 1; i <= 6; i++) {
          final tp = Offset.lerp(pa, pb, (prog - i * 0.012).clamp(0.0, 1.0))!;
          canvas.drawCircle(tp, 5 - i * 0.6, Paint()..color = UW.goldLight.withValues(alpha: 0.25 - i * 0.03));
        }
        canvas.drawCircle(
            car,
            18,
            Paint()
              ..color = UW.goldLight.withValues(alpha: 0.4)
              ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10));
        _drawCar(canvas, car, math.atan2(pb.dy - pa.dy, pb.dx - pa.dx));
      }
    }

    // Semtler
    for (final d in districts) {
      _drawDistrict(canvas, d);
    }

    // Pusula
    _compass(canvas, Offset(w - 44, h - 108), 26);

    // Kenar karartma
    canvas.drawRect(
        full,
        Paint()
          ..shader = RadialGradient(
            radius: 1.05,
            colors: [Colors.transparent, Colors.black.withValues(alpha: 0.45)],
            stops: const [0.65, 1],
          ).createShader(full));
  }

  void _drawCar(Canvas canvas, Offset c, double angle) {
    canvas.save();
    canvas.translate(c.dx, c.dy);
    canvas.rotate(angle);
    final body = RRect.fromRectAndRadius(Rect.fromCenter(center: Offset.zero, width: 22, height: 11), const Radius.circular(4));
    canvas.drawRRect(body, Paint()..color = const Color(0xFF111111));
    canvas.drawRRect(
        body,
        Paint()
          ..color = UW.gold
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.4);
    canvas.drawRect(Rect.fromCenter(center: const Offset(-1, 0), width: 8, height: 7), Paint()..color = const Color(0xFF2B3A55));
    // Farlar
    final beam = Path()
      ..moveTo(11, -3)
      ..lineTo(40, -12)
      ..lineTo(40, 12)
      ..lineTo(11, 3)
      ..close();
    canvas.drawPath(
        beam,
        Paint()
          ..shader = ui.Gradient.linear(const Offset(11, 0), const Offset(40, 0),
              [UW.goldLight.withValues(alpha: 0.55), UW.goldLight.withValues(alpha: 0)]));
    canvas.restore();
  }

  void _drawDistrict(Canvas canvas, District d) {
    final p = pos(d);
    final c = hexColor(d.color);
    final isHere = d.id == currentId && travel == null;
    final isSel = d.id == selectedId;
    final isDest = travel?.to == d.id;
    const r = 26.0;

    // Bölge ışığı
    canvas.drawCircle(
        p,
        r * 3.2,
        Paint()
          ..shader = RadialGradient(colors: [c.withValues(alpha: isSel ? 0.4 : 0.24), c.withValues(alpha: 0)])
              .createShader(Rect.fromCircle(center: p, radius: r * 3.2)));

    // Bulunduğun semtte nabız halkaları
    if (isHere || isDest) {
      for (var i = 0; i < 2; i++) {
        final ph = (t * 3 + i * 0.5) % 1.0;
        canvas.drawCircle(
            p,
            r + ph * 34,
            Paint()
              ..color = (isDest ? UW.goldLight : c).withValues(alpha: (1 - ph) * 0.6)
              ..style = PaintingStyle.stroke
              ..strokeWidth = 2);
      }
    }

    // Sekizgen madalyon
    Path octagon(double rad) {
      final path = Path();
      for (var i = 0; i < 8; i++) {
        final a = math.pi / 8 + i * math.pi / 4;
        final pt = p + Offset(math.cos(a), math.sin(a)) * rad;
        i == 0 ? path.moveTo(pt.dx, pt.dy) : path.lineTo(pt.dx, pt.dy);
      }
      return path..close();
    }

    canvas.drawPath(octagon(r + 4), Paint()..color = Colors.black.withValues(alpha: 0.6)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 6));
    canvas.drawPath(
        octagon(r),
        Paint()
          ..shader = RadialGradient(colors: [Color.lerp(c, Colors.black, 0.45)!, const Color(0xFF0A0D16)])
              .createShader(Rect.fromCircle(center: p, radius: r)));
    canvas.drawPath(
        octagon(r),
        Paint()
          ..color = isSel ? UW.goldLight : UW.gold
          ..style = PaintingStyle.stroke
          ..strokeWidth = isSel ? 2.4 : 1.5);
    canvas.drawPath(
        octagon(r - 5),
        Paint()
          ..color = c.withValues(alpha: 0.8)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1);

    // Ortadaki işaret: semt rengine göre ışın deseni (art deco güneşi)
    final rays = Paint()
      ..color = c.withValues(alpha: 0.9)
      ..strokeWidth = 1.2;
    for (var i = 0; i < 12; i++) {
      final a = i * math.pi / 6;
      canvas.drawLine(p + Offset(math.cos(a), math.sin(a)) * 5, p + Offset(math.cos(a), math.sin(a)) * 13, rays);
    }
    canvas.drawCircle(p, 4.5, Paint()..color = isHere ? UW.goldLight : c);

    // Çatışma halkası
    final ter = territory[d.id];
    if (ter != null && ter.contested) {
      final ph = (t * 4) % 1.0;
      canvas.drawCircle(
          p,
          r + 10 + ph * 6,
          Paint()
            ..color = UW.crimson.withValues(alpha: 0.9 - ph * 0.6)
            ..style = PaintingStyle.stroke
            ..strokeWidth = 2.5);
    }

    // Kontrol eden çetenin bayrağı
    final ctrl = ter?.controller;
    if (ctrl != null) _pennant(canvas, p + Offset(r + 4, -r + 2), hexColor(ctrl.color), ctrl.tag, ctrl.id == myGangId);

    // Sahip olduğun işletmeler: küçük bina simgesi
    final bc = businessCounts[d.id] ?? 0;
    if (bc > 0) _buildingBadge(canvas, p + Offset(-r - 20, -r + 4), bc);

    // Polis yıldızları
    final stars = (d.police * 5).round().clamp(0, 5);
    for (var i = 0; i < stars; i++) {
      final sp = p + Offset((i - (stars - 1) / 2) * 8, -r - 9);
      _star(canvas, sp, 3.2, UW.crimson.withValues(alpha: 0.9));
    }

    // Etiket
    final tp = TextPainter(
      text: TextSpan(
        text: d.name.toUpperCase(),
        style: UW.display(11.5, color: isHere ? UW.goldLight : UW.cream).copyWith(shadows: const [
          Shadow(color: Colors.black, blurRadius: 6),
          Shadow(color: Colors.black, blurRadius: 2),
        ]),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    final labelPos = p + Offset(-tp.width / 2, r + 8);
    final bg = RRect.fromRectAndRadius(
        Rect.fromLTWH(labelPos.dx - 8, labelPos.dy - 3, tp.width + 16, tp.height + 6), const Radius.circular(2));
    canvas.drawRRect(bg, Paint()..color = Colors.black.withValues(alpha: 0.65));
    canvas.drawRRect(
        bg,
        Paint()
          ..color = UW.gold.withValues(alpha: isSel || isHere ? 0.8 : 0.3)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 0.8);
    tp.paint(canvas, labelPos);

    if (isHere) {
      final pin = TextPainter(
        text: TextSpan(text: 'BURADASIN', style: UW.body(9, color: UW.ink, weight: FontWeight.w800)),
        textDirection: TextDirection.ltr,
      )..layout();
      final pr = RRect.fromRectAndRadius(
          Rect.fromLTWH(p.dx - pin.width / 2 - 6, labelPos.dy + tp.height + 6, pin.width + 12, pin.height + 4),
          const Radius.circular(2));
      canvas.drawRRect(pr, Paint()..color = UW.gold);
      pin.paint(canvas, Offset(pr.left + 6, pr.top + 2));
    }
  }

  void _buildingBadge(Canvas canvas, Offset c, int count) {
    // Art deco mini bina: basamaklı tepe, yanan pencereler
    final body = Rect.fromCenter(center: c + const Offset(0, 3), width: 16, height: 16);
    canvas.drawRect(body.inflate(3), Paint()..color = Colors.black54..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3));
    canvas.drawRect(Rect.fromLTWH(body.left + 4, body.top - 4, 8, 4), Paint()..color = UW.gold);
    canvas.drawRect(Rect.fromLTWH(body.left + 7, body.top - 7, 2, 3), Paint()..color = UW.gold);
    canvas.drawRect(body, Paint()..color = const Color(0xFF231A10));
    canvas.drawRect(body, Paint()..color = UW.gold..style = PaintingStyle.stroke..strokeWidth = 1.2);
    final glow = 0.6 + 0.4 * math.sin(t * math.pi * 2 * 2);
    for (var i = 0; i < 2; i++) {
      for (var j = 0; j < 2; j++) {
        canvas.drawRect(Rect.fromLTWH(body.left + 3 + i * 6, body.top + 3 + j * 6, 4, 3),
            Paint()..color = const Color(0xFFFFC870).withValues(alpha: glow));
      }
    }
    if (count > 1) {
      final bp = body.topRight + const Offset(1, -1);
      canvas.drawCircle(bp, 6, Paint()..color = UW.crimson);
      final tp = TextPainter(
        text: TextSpan(text: '$count', style: UW.body(8.5, color: Colors.white, weight: FontWeight.w900)),
        textDirection: TextDirection.ltr,
      )..layout();
      tp.paint(canvas, bp - Offset(tp.width / 2, tp.height / 2));
    }
  }

  void _pennant(Canvas canvas, Offset base, Color color, String tag, bool mine) {
    // Direk
    canvas.drawLine(base, base + const Offset(0, -26), Paint()
      ..color = UW.goldLight
      ..strokeWidth = 1.6);
    canvas.drawCircle(base + const Offset(0, -27), 2, Paint()..color = UW.goldLight);
    final tp = TextPainter(
      text: TextSpan(text: tag, style: UW.display(9.5, color: Colors.white, weight: FontWeight.w900)),
      textDirection: TextDirection.ltr,
    )..layout();
    final wave = math.sin(t * math.pi * 2 * 3) * 1.5;
    final fw = tp.width + 16, fh = 15.0;
    final top = base + const Offset(0, -26);
    final flag = Path()
      ..moveTo(top.dx, top.dy)
      ..quadraticBezierTo(top.dx + fw / 2, top.dy + wave, top.dx + fw, top.dy)
      ..lineTo(top.dx + fw - 5, top.dy + fh / 2)
      ..lineTo(top.dx + fw, top.dy + fh)
      ..quadraticBezierTo(top.dx + fw / 2, top.dy + fh + wave, top.dx, top.dy + fh)
      ..close();
    canvas.drawPath(flag.shift(const Offset(1, 2)), Paint()..color = Colors.black54);
    canvas.drawPath(flag, Paint()..color = color);
    canvas.drawPath(
        flag,
        Paint()
          ..color = mine ? UW.goldLight : UW.gold.withValues(alpha: 0.7)
          ..style = PaintingStyle.stroke
          ..strokeWidth = mine ? 1.4 : 0.8);
    tp.paint(canvas, top + Offset(5, (fh - tp.height) / 2 + wave / 2));
  }

  void _star(Canvas canvas, Offset c, double r, Color color) {
    final path = Path();
    for (var i = 0; i < 10; i++) {
      final rad = i.isEven ? r : r * 0.45;
      final a = -math.pi / 2 + i * math.pi / 5;
      final pt = c + Offset(math.cos(a), math.sin(a)) * rad;
      i == 0 ? path.moveTo(pt.dx, pt.dy) : path.lineTo(pt.dx, pt.dy);
    }
    canvas.drawPath(path..close(), Paint()..color = color);
  }

  void _compass(Canvas canvas, Offset c, double r) {
    final p = Paint()
      ..color = UW.gold.withValues(alpha: 0.6)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    canvas.drawCircle(c, r, p);
    canvas.drawCircle(c, r * 0.7, p..strokeWidth = 0.6);
    for (var i = 0; i < 4; i++) {
      final a = -math.pi / 2 + i * math.pi / 2;
      final tip = c + Offset(math.cos(a), math.sin(a)) * r;
      final l = c + Offset(math.cos(a - math.pi / 2), math.sin(a - math.pi / 2)) * 4;
      final rr = c + Offset(math.cos(a + math.pi / 2), math.sin(a + math.pi / 2)) * 4;
      canvas.drawPath(
          Path()
            ..moveTo(tip.dx, tip.dy)
            ..lineTo(l.dx, l.dy)
            ..lineTo(rr.dx, rr.dy)
            ..close(),
          Paint()..color = i == 0 ? UW.gold : UW.gold.withValues(alpha: 0.4));
    }
    final n = TextPainter(
      text: TextSpan(text: 'K', style: UW.display(9, color: UW.gold)),
      textDirection: TextDirection.ltr,
    )..layout();
    n.paint(canvas, c + Offset(-n.width / 2, -r - 13));
  }

  void _dashed(Canvas canvas, Offset a, Offset b, Paint p, double dash, double gap, double offset) {
    final total = (b - a).distance;
    if (total == 0) return;
    final dir = (b - a) / total;
    var d = offset % (dash + gap);
    if (d > 0) d -= dash + gap;
    while (d < total) {
      final s = math.max(0.0, d), e = math.min(total, d + dash);
      if (e > s) canvas.drawLine(a + dir * s, a + dir * e, p);
      d += dash + gap;
    }
  }

  @override
  bool shouldRepaint(covariant _MapPainter old) => true;
}
