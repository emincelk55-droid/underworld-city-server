import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

const emblemNames = {
  'star': 'Yıldız',
  'rose': 'Gül',
  'crown': 'Nişan',
  'flame': 'Alev',
  'anchor': 'Çapa',
  'dice': 'Zar',
  'eye': 'Göz',
  'bolt': 'Şimşek',
};

IconData emblemIcon(String key) => switch (key) {
      'rose' => Icons.local_florist,
      'crown' => Icons.military_tech,
      'flame' => Icons.whatshot,
      'anchor' => Icons.anchor,
      'dice' => Icons.casino,
      'eye' => Icons.visibility,
      'bolt' => Icons.bolt,
      _ => Icons.star,
    };

/// Çete arması: art deco kalkan, amblem ve kısaltma şeridi.
class GangCrest extends StatelessWidget {
  final String color, emblem, tag;
  final double size;
  final bool glow;
  const GangCrest({super.key, required this.color, required this.emblem, required this.tag, this.size = 56, this.glow = false});

  @override
  Widget build(BuildContext context) {
    final c = hexColor(color);
    return SizedBox(
      width: size,
      height: size * 1.18,
      child: CustomPaint(
        painter: _CrestPainter(c, glow),
        child: Column(children: [
          SizedBox(height: size * 0.3),
          Icon(emblemIcon(emblem), size: size * 0.42, color: Color.lerp(c, Colors.white, 0.75)),
          const Spacer(),
          SizedBox(
            height: size * 0.26,
            child: Center(
              child: Text(tag,
                  style: UW.display(size * 0.16, color: UW.ink, weight: FontWeight.w900).copyWith(letterSpacing: 1)),
            ),
          ),
          SizedBox(height: size * 0.14),
        ]),
      ),
    );
  }
}

class _CrestPainter extends CustomPainter {
  final Color c;
  final bool glow;
  _CrestPainter(this.c, this.glow);

  Path _shield(Size s, double inset) {
    final w = s.width, h = s.height;
    final l = inset, r = w - inset, t = h * 0.1 + inset;
    return Path()
      ..moveTo(l, t + h * 0.06)
      ..lineTo(w * 0.22, t)
      ..lineTo(w * 0.36, t + h * 0.04)
      ..lineTo(w * 0.5, t - h * 0.07)
      ..lineTo(w * 0.64, t + h * 0.04)
      ..lineTo(w * 0.78, t)
      ..lineTo(r, t + h * 0.06)
      ..lineTo(r, h * 0.58)
      ..quadraticBezierTo(r, h * 0.82, w * 0.5, h - inset * 1.4)
      ..quadraticBezierTo(l, h * 0.82, l, h * 0.58)
      ..close();
  }

  @override
  void paint(Canvas canvas, Size size) {
    final outer = _shield(size, 1);
    if (glow) {
      canvas.drawPath(
          outer,
          Paint()
            ..color = c.withValues(alpha: 0.55)
            ..maskFilter = MaskFilter.blur(BlurStyle.normal, size.width * 0.12));
    }
    canvas.drawPath(outer.shift(const Offset(0, 2)), Paint()..color = Colors.black54);
    canvas.drawPath(
        outer,
        Paint()
          ..shader = LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color.lerp(c, Colors.white, 0.15)!, c, Color.lerp(c, Colors.black, 0.65)!],
          ).createShader(Offset.zero & size));

    // Art deco ışın deseni
    canvas.save();
    canvas.clipPath(outer);
    final center = Offset(size.width / 2, size.height * 0.48);
    final ray = Paint()
      ..color = Colors.white.withValues(alpha: 0.07)
      ..strokeWidth = size.width * 0.05;
    for (var i = 0; i < 12; i++) {
      final a = i * math.pi / 6;
      canvas.drawLine(center, center + Offset(math.cos(a), math.sin(a)) * size.height, ray);
    }
    canvas.restore();

    // Altın çift kenar
    canvas.drawPath(
        outer,
        Paint()
          ..shader = UW.goldGradient.createShader(Offset.zero & size)
          ..style = PaintingStyle.stroke
          ..strokeWidth = math.max(1.5, size.width * 0.045));
    canvas.drawPath(
        _shield(size, size.width * 0.1),
        Paint()
          ..color = UW.goldLight.withValues(alpha: 0.5)
          ..style = PaintingStyle.stroke
          ..strokeWidth = math.max(0.6, size.width * 0.015));

    // Kısaltma şeridi
    final w = size.width, h = size.height;
    final band = Path()
      ..moveTo(-w * 0.04, h * 0.66)
      ..lineTo(w * 1.04, h * 0.66)
      ..lineTo(w * 0.96, h * 0.77)
      ..lineTo(w * 1.04, h * 0.88)
      ..lineTo(-w * 0.04, h * 0.88)
      ..lineTo(w * 0.04, h * 0.77)
      ..close();
    canvas.drawPath(band.shift(const Offset(0, 1.5)), Paint()..color = Colors.black45);
    canvas.drawPath(band, Paint()..shader = UW.goldGradient.createShader(Rect.fromLTWH(0, h * 0.66, w, h * 0.22)));
  }

  @override
  bool shouldRepaint(covariant _CrestPainter old) => old.c != c || old.glow != glow;
}
