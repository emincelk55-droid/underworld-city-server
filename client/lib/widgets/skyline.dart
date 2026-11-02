import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

/// Hareketli noir şehir silüeti: ay, projektörler, ışıklı pencereler, yağmur, sis.
class NoirSkyline extends StatefulWidget {
  const NoirSkyline({super.key});

  @override
  State<NoirSkyline> createState() => _NoirSkylineState();
}

class _NoirSkylineState extends State<NoirSkyline> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 20))..repeat();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => RepaintBoundary(
        child: AnimatedBuilder(
          animation: _c,
          builder: (_, _) => CustomPaint(painter: _SkylinePainter(_c.value), size: Size.infinite),
        ),
      );
}

class _Building {
  final double x, w, h;
  final int seed;
  final int top; // 0 düz, 1 sivri, 2 basamaklı (art deco), 3 kubbe
  _Building(this.x, this.w, this.h, this.seed, this.top);
}

class _SkylinePainter extends CustomPainter {
  final double t;
  _SkylinePainter(this.t);

  static final List<List<_Building>> _layers = List.generate(3, (layer) {
    final r = math.Random(42 + layer * 7);
    final list = <_Building>[];
    var x = -0.02;
    while (x < 1.05) {
      final w = 0.035 + r.nextDouble() * (0.05 + layer * 0.015);
      final h = (0.18 + r.nextDouble() * 0.32) * (1.0 - layer * 0.18) + (r.nextDouble() < 0.12 ? 0.18 : 0);
      list.add(_Building(x, w, h, r.nextInt(1 << 30), r.nextInt(4)));
      x += w + r.nextDouble() * 0.008;
    }
    return list;
  });

  static final List<Offset> _stars = List.generate(90, (i) {
    final r = math.Random(i * 31 + 5);
    return Offset(r.nextDouble(), r.nextDouble() * 0.55);
  });

  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width, h = size.height;
    final rect = Offset.zero & size;

    // Gökyüzü
    canvas.drawRect(
      rect,
      Paint()
        ..shader = const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xFF05060B), Color(0xFF121735), Color(0xFF2A1E3D), Color(0xFF3B2632)],
          stops: [0, 0.45, 0.75, 1],
        ).createShader(rect),
    );

    // Yıldızlar
    for (var i = 0; i < _stars.length; i++) {
      final tw = 0.35 + 0.65 * (0.5 + 0.5 * math.sin(t * math.pi * 2 * 3 + i));
      canvas.drawCircle(Offset(_stars[i].dx * w, _stars[i].dy * h), i % 7 == 0 ? 1.4 : 0.8,
          Paint()..color = Colors.white.withValues(alpha: 0.5 * tw));
    }

    // Ay
    final moon = Offset(w * 0.78, h * 0.2);
    final mr = math.min(w, h) * 0.075;
    canvas.drawCircle(
        moon,
        mr * 4,
        Paint()
          ..shader = RadialGradient(colors: [
            const Color(0xFFF5DE8B).withValues(alpha: 0.22),
            const Color(0xFFF5DE8B).withValues(alpha: 0),
          ]).createShader(Rect.fromCircle(center: moon, radius: mr * 4)));
    canvas.drawCircle(
        moon,
        mr,
        Paint()
          ..shader = const RadialGradient(
            center: Alignment(-0.3, -0.3),
            colors: [Color(0xFFFFF6D8), Color(0xFFE8CF8A)],
          ).createShader(Rect.fromCircle(center: moon, radius: mr)));
    canvas.drawCircle(moon.translate(mr * 0.3, -mr * 0.2), mr * 0.18, Paint()..color = const Color(0x22000000));
    canvas.drawCircle(moon.translate(-mr * 0.35, mr * 0.3), mr * 0.12, Paint()..color = const Color(0x1A000000));

    // Projektör ışıkları
    for (var i = 0; i < 2; i++) {
      final base = Offset(w * (0.28 + i * 0.4), h * 0.82);
      final ang = -math.pi / 2 + math.sin(t * math.pi * 2 + i * 2.1) * 0.55;
      final len = h * 0.95;
      final spread = 0.07;
      final p1 = base + Offset(math.cos(ang - spread), math.sin(ang - spread)) * len;
      final p2 = base + Offset(math.cos(ang + spread), math.sin(ang + spread)) * len;
      canvas.drawPath(
        Path()
          ..moveTo(base.dx, base.dy)
          ..lineTo(p1.dx, p1.dy)
          ..lineTo(p2.dx, p2.dy)
          ..close(),
        Paint()
          ..shader = RadialGradient(
            center: Alignment((base.dx / w) * 2 - 1, (base.dy / h) * 2 - 1),
            radius: 1.0,
            colors: [UW.goldLight.withValues(alpha: 0.18), UW.goldLight.withValues(alpha: 0)],
          ).createShader(rect),
      );
    }

    // Bina katmanları (arkadan öne)
    const layerColors = [Color(0xFF1A1830), Color(0xFF110F20), Color(0xFF07070E)];
    for (var layer = 0; layer < 3; layer++) {
      final baseY = h * (0.88 + layer * 0.04);
      final paint = Paint()..color = layerColors[layer];
      for (final b in _layers[layer]) {
        final bx = b.x * w, bw = b.w * w, bh = b.h * h;
        final top = baseY - bh;
        final path = Path()..addRect(Rect.fromLTWH(bx, top, bw, h - top));
        switch (b.top) {
          case 1:
            path.addPolygon([Offset(bx + bw * 0.35, top), Offset(bx + bw / 2, top - bh * 0.18), Offset(bx + bw * 0.65, top)], true);
          case 2:
            path.addRect(Rect.fromLTWH(bx + bw * 0.15, top - bh * 0.06, bw * 0.7, bh * 0.06));
            path.addRect(Rect.fromLTWH(bx + bw * 0.3, top - bh * 0.11, bw * 0.4, bh * 0.05));
            path.addRect(Rect.fromLTWH(bx + bw * 0.47, top - bh * 0.2, bw * 0.06, bh * 0.09));
          case 3:
            path.addArc(Rect.fromLTWH(bx + bw * 0.2, top - bw * 0.3, bw * 0.6, bw * 0.6), math.pi, math.pi);
        }
        canvas.drawPath(path, paint);

        // Pencereler
        if (layer > 0) {
          final r = math.Random(b.seed);
          final cols = math.max(2, (bw / 9).floor());
          final rows = math.max(3, (bh / 12).floor());
          final cw = bw / cols;
          for (var ry = 1; ry < rows; ry++) {
            for (var cx = 0; cx < cols; cx++) {
              final lit = r.nextDouble();
              if (lit > 0.22) continue;
              final flicker = (r.nextDouble() < 0.1) ? (0.5 + 0.5 * math.sin(t * math.pi * 40 + cx)) : 1.0;
              final warm = r.nextBool();
              canvas.drawRect(
                Rect.fromLTWH(bx + cx * cw + cw * 0.3, top + ry * 12.0, cw * 0.4, 5),
                Paint()
                  ..color = (warm ? const Color(0xFFFFC870) : const Color(0xFFBFE6FF))
                      .withValues(alpha: (layer == 1 ? 0.45 : 0.8) * flicker),
              );
            }
          }
        }
      }
    }

    // Neon tabela
    final signPulse = 0.6 + 0.4 * math.sin(t * math.pi * 2 * 6).abs();
    final signRect = Rect.fromLTWH(w * 0.08, h * 0.66, w * 0.07, h * 0.022);
    canvas.drawRRect(
        RRect.fromRectAndRadius(signRect.inflate(6), const Radius.circular(4)),
        Paint()
          ..color = UW.crimson.withValues(alpha: 0.25 * signPulse)
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10));
    canvas.drawRRect(
        RRect.fromRectAndRadius(signRect, const Radius.circular(3)),
        Paint()
          ..color = UW.crimson.withValues(alpha: 0.9 * signPulse)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2);

    // Sis
    canvas.drawRect(
      Rect.fromLTWH(0, h * 0.7, w, h * 0.3),
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Colors.transparent, const Color(0xFF6B5A7A).withValues(alpha: 0.18), UW.ink.withValues(alpha: 0.9)],
        ).createShader(Rect.fromLTWH(0, h * 0.7, w, h * 0.3)),
    );

    // Yağmur
    final rain = Paint()
      ..color = const Color(0xFFAFC3E0).withValues(alpha: 0.18)
      ..strokeWidth = 1;
    for (var i = 0; i < 160; i++) {
      final r = math.Random(i * 977);
      final speed = 0.6 + r.nextDouble() * 0.6;
      final x = (r.nextDouble() * 1.2 - 0.1) * w;
      final y = ((r.nextDouble() + t * 18 * speed) % 1.0) * (h + 40) - 20;
      canvas.drawLine(Offset(x, y), Offset(x - 4, y + 14 + r.nextDouble() * 8), rain);
    }

    // Kenar karartma
    canvas.drawRect(
      rect,
      Paint()
        ..shader = RadialGradient(
          radius: 1.1,
          colors: [Colors.transparent, Colors.black.withValues(alpha: 0.65)],
          stops: const [0.55, 1],
        ).createShader(rect),
    );
  }

  @override
  bool shouldRepaint(covariant _SkylinePainter old) => old.t != t;
}
