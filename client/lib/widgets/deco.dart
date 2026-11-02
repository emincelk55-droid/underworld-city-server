import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

/// Altın kenarlı, köşeleri art deco süslü panel.
class DecoPanel extends StatelessWidget {
  final Widget child;
  final EdgeInsets padding;
  final Color? accent;
  final bool glow;
  const DecoPanel({super.key, required this.child, this.padding = const EdgeInsets.all(16), this.accent, this.glow = false});

  @override
  Widget build(BuildContext context) {
    final a = accent ?? UW.gold;
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [UW.panelHi.withValues(alpha: 0.95), UW.panel.withValues(alpha: 0.95), UW.night.withValues(alpha: 0.95)],
        ),
        border: Border.all(color: a.withValues(alpha: 0.45), width: 1),
        boxShadow: [
          BoxShadow(color: Colors.black.withValues(alpha: 0.55), blurRadius: 18, offset: const Offset(0, 8)),
          if (glow) BoxShadow(color: a.withValues(alpha: 0.25), blurRadius: 28, spreadRadius: 1),
        ],
      ),
      child: CustomPaint(
        painter: _CornerPainter(a),
        child: Padding(padding: padding, child: child),
      ),
    );
  }
}

class _CornerPainter extends CustomPainter {
  final Color color;
  _CornerPainter(this.color);

  @override
  void paint(Canvas canvas, Size size) {
    final p = Paint()
      ..color = color.withValues(alpha: 0.85)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.2;
    const l = 14.0, inset = 4.0;
    for (final c in [
      [inset, inset, 1.0, 1.0],
      [size.width - inset, inset, -1.0, 1.0],
      [inset, size.height - inset, 1.0, -1.0],
      [size.width - inset, size.height - inset, -1.0, -1.0],
    ]) {
      final x = c[0], y = c[1], sx = c[2], sy = c[3];
      canvas.drawPath(
        Path()
          ..moveTo(x, y + sy * l)
          ..lineTo(x, y)
          ..lineTo(x + sx * l, y),
        p,
      );
      canvas.drawPath(
        Path()
          ..moveTo(x + sx * 4, y + sy * (l - 4))
          ..lineTo(x + sx * 4, y + sy * 4)
          ..lineTo(x + sx * (l - 4), y + sy * 4),
        p..strokeWidth = 0.7,
      );
      p.strokeWidth = 1.2;
      canvas.drawCircle(Offset(x + sx * 8, y + sy * 8), 1.2, Paint()..color = color);
    }
  }

  @override
  bool shouldRepaint(covariant _CornerPainter old) => old.color != color;
}

/// Altın degrade metin.
class GoldText extends StatelessWidget {
  final String text;
  final TextStyle style;
  final TextAlign? align;
  const GoldText(this.text, {super.key, required this.style, this.align});

  @override
  Widget build(BuildContext context) => ShaderMask(
        blendMode: BlendMode.srcIn,
        shaderCallback: (r) => UW.goldGradient.createShader(r),
        child: Text(text, style: style, textAlign: align),
      );
}

/// Art deco başlık: ◆ ── BAŞLIK ── ◆
class DecoHeading extends StatelessWidget {
  final String text;
  final double size;
  const DecoHeading(this.text, {super.key, this.size = 15});

  @override
  Widget build(BuildContext context) {
    Widget line(bool flip) => Expanded(
          child: Container(
            height: 1,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: flip
                    ? [UW.gold.withValues(alpha: 0.7), UW.gold.withValues(alpha: 0)]
                    : [UW.gold.withValues(alpha: 0), UW.gold.withValues(alpha: 0.7)],
              ),
            ),
          ),
        );
    return Row(children: [
      line(false),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10),
        child: Row(children: [
          Transform.rotate(angle: math.pi / 4, child: Container(width: 5, height: 5, color: UW.gold)),
          const SizedBox(width: 10),
          GoldText(text.toUpperCase(), style: UW.display(size)),
          const SizedBox(width: 10),
          Transform.rotate(angle: math.pi / 4, child: Container(width: 5, height: 5, color: UW.gold)),
        ]),
      ),
      line(true),
    ]);
  }
}

class DecoButton extends StatefulWidget {
  final String label;
  final VoidCallback? onTap;
  final IconData? icon;
  final bool primary;
  final Color? color;
  final bool loading;
  const DecoButton(this.label,
      {super.key, this.onTap, this.icon, this.primary = true, this.color, this.loading = false});

  @override
  State<DecoButton> createState() => _DecoButtonState();
}

class _DecoButtonState extends State<DecoButton> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final enabled = widget.onTap != null && !widget.loading;
    final c = widget.color ?? UW.gold;
    return MouseRegion(
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
      child: GestureDetector(
        onTap: enabled ? widget.onTap : null,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 160),
          height: 48,
          padding: const EdgeInsets.symmetric(horizontal: 18),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(4),
            gradient: widget.primary
                ? LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      Color.lerp(c, Colors.white, _hover ? 0.45 : 0.3)!,
                      c,
                      Color.lerp(c, Colors.black, 0.4)!,
                    ],
                  )
                : null,
            color: widget.primary ? null : (_hover ? c.withValues(alpha: 0.12) : Colors.transparent),
            border: Border.all(color: c.withValues(alpha: widget.primary ? 1 : 0.7)),
            boxShadow: enabled && widget.primary
                ? [BoxShadow(color: c.withValues(alpha: _hover ? 0.5 : 0.25), blurRadius: _hover ? 22 : 12)]
                : null,
          ),
          child: Opacity(
            opacity: enabled ? 1 : 0.45,
            child: Center(
              child: widget.loading
                  ? SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2, color: widget.primary ? UW.ink : c))
                  : Row(mainAxisSize: MainAxisSize.min, children: [
                      if (widget.icon != null) ...[
                        Icon(widget.icon, size: 18, color: widget.primary ? UW.ink : c),
                        const SizedBox(width: 8),
                      ],
                      Text(widget.label.toUpperCase(),
                          style: UW.display(13, color: widget.primary ? UW.ink : c, weight: FontWeight.w800)),
                    ]),
            ),
          ),
        ),
      ),
    );
  }
}

/// Mal ikonu: altın madalyon içinde.
class GoodIcon extends StatelessWidget {
  final String icon;
  final double size;
  const GoodIcon(this.icon, {super.key, this.size = 46});

  static IconData iconData(String key) => switch (key) {
        'wine' => Icons.wine_bar,
        'smoke' => Icons.smoking_rooms,
        'coffee' => Icons.coffee,
        'medical' => Icons.medication,
        'radio' => Icons.radio,
        'gun' => Icons.gps_fixed,
        'diamond' => Icons.diamond,
        'document' => Icons.badge,
        _ => Icons.inventory_2,
      };

  static Color tint(String key) => switch (key) {
        'wine' => const Color(0xFFC0485A),
        'smoke' => const Color(0xFFB08968),
        'coffee' => const Color(0xFF9C6644),
        'medical' => const Color(0xFF5FB4A2),
        'radio' => const Color(0xFF7FA7D9),
        'gun' => const Color(0xFF9AA5B1),
        'diamond' => const Color(0xFF8BE0F0),
        'document' => const Color(0xFFE3C67B),
        _ => UW.gold,
      };

  @override
  Widget build(BuildContext context) {
    final t = tint(icon);
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: RadialGradient(colors: [Color.lerp(t, Colors.black, 0.35)!, UW.ink], stops: const [0, 1]),
        border: Border.all(color: UW.gold.withValues(alpha: 0.8), width: 1.4),
        boxShadow: [BoxShadow(color: t.withValues(alpha: 0.35), blurRadius: 14)],
      ),
      child: Container(
        margin: const EdgeInsets.all(3),
        decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: UW.gold.withValues(alpha: 0.25))),
        child: Icon(iconData(icon), color: Color.lerp(t, Colors.white, 0.35), size: size * 0.48),
      ),
    );
  }
}

/// Küçük fiyat grafiği.
class Sparkline extends StatelessWidget {
  final List<double> values;
  final double width, height;
  const Sparkline(this.values, {super.key, this.width = 70, this.height = 26});

  @override
  Widget build(BuildContext context) =>
      CustomPaint(size: Size(width, height), painter: _SparkPainter(values));
}

class _SparkPainter extends CustomPainter {
  final List<double> v;
  _SparkPainter(this.v);

  @override
  void paint(Canvas canvas, Size size) {
    if (v.length < 2) {
      canvas.drawLine(Offset(0, size.height / 2), Offset(size.width, size.height / 2),
          Paint()..color = UW.muted.withValues(alpha: 0.4));
      return;
    }
    final lo = v.reduce(math.min), hi = v.reduce(math.max);
    final span = (hi - lo).abs() < 1e-6 ? 1 : hi - lo;
    final up = v.last >= v.first;
    final c = up ? UW.emerald : UW.crimson;
    final path = Path();
    for (var i = 0; i < v.length; i++) {
      final x = i / (v.length - 1) * size.width;
      final y = size.height - ((v[i] - lo) / span) * (size.height - 4) - 2;
      i == 0 ? path.moveTo(x, y) : path.lineTo(x, y);
    }
    final fill = Path.from(path)
      ..lineTo(size.width, size.height)
      ..lineTo(0, size.height)
      ..close();
    canvas.drawPath(
        fill,
        Paint()
          ..shader = LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [c.withValues(alpha: 0.35), c.withValues(alpha: 0)],
          ).createShader(Offset.zero & size));
    canvas.drawPath(
        path,
        Paint()
          ..color = c
          ..style = PaintingStyle.stroke
          ..strokeWidth = 1.6
          ..strokeCap = StrokeCap.round);
  }

  @override
  bool shouldRepaint(covariant _SparkPainter old) => true;
}

/// Etiketli ilerleme çubuğu (enerji, yük).
class StatBar extends StatelessWidget {
  final IconData icon;
  final String label;
  final double value; // 0-1
  final Color color;
  const StatBar({super.key, required this.icon, required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) {
    return Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, size: 16, color: color),
      const SizedBox(width: 6),
      SizedBox(
        width: 78,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          Text(label, style: UW.number(11, color: UW.cream.withValues(alpha: 0.85), weight: FontWeight.w600)),
          const SizedBox(height: 3),
          Container(
            height: 6,
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(3),
              border: Border.all(color: color.withValues(alpha: 0.35), width: 0.6),
            ),
            child: FractionallySizedBox(
              alignment: Alignment.centerLeft,
              widthFactor: value.clamp(0.0, 1.0),
              child: Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(3),
                  gradient: LinearGradient(colors: [Color.lerp(color, Colors.black, 0.3)!, color]),
                  boxShadow: [BoxShadow(color: color.withValues(alpha: 0.6), blurRadius: 6)],
                ),
              ),
            ),
          ),
        ]),
      ),
    ]);
  }
}

class Chip2 extends StatelessWidget {
  final String text;
  final IconData? icon;
  final Color color;
  const Chip2(this.text, {super.key, this.icon, this.color = UW.muted});

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(3),
          border: Border.all(color: color.withValues(alpha: 0.4), width: 0.8),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          if (icon != null) ...[Icon(icon, size: 12, color: color), const SizedBox(width: 4)],
          Text(text, style: UW.body(11, color: color, weight: FontWeight.w600)),
        ]),
      );
}
