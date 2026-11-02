import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// 1930'lar noir + art deco paleti.
class UW {
  static const ink = Color(0xFF07090E);
  static const night = Color(0xFF0E1320);
  static const panel = Color(0xFF141B2B);
  static const panelHi = Color(0xFF1C2538);
  static const gold = Color(0xFFD4AF37);
  static const goldLight = Color(0xFFF5DE8B);
  static const goldDark = Color(0xFF8C6A1C);
  static const cream = Color(0xFFF3E9D2);
  static const muted = Color(0xFF8A93A8);
  static const crimson = Color(0xFFD9475B);
  static const emerald = Color(0xFF4CC38A);
  static const neon = Color(0xFF3FD0E0);

  static const goldGradient = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [goldLight, gold, goldDark],
  );

  static TextStyle display(double size, {Color color = cream, FontWeight weight = FontWeight.w700}) =>
      GoogleFonts.cinzel(fontSize: size, color: color, fontWeight: weight, letterSpacing: size * 0.08);

  static TextStyle serif(double size, {Color color = cream, FontWeight weight = FontWeight.w600}) =>
      GoogleFonts.playfairDisplay(fontSize: size, color: color, fontWeight: weight);

  static TextStyle body(double size, {Color color = cream, FontWeight weight = FontWeight.w500}) =>
      GoogleFonts.inter(fontSize: size, color: color, fontWeight: weight);

  static TextStyle number(double size, {Color color = cream, FontWeight weight = FontWeight.w700}) =>
      GoogleFonts.robotoMono(fontSize: size, color: color, fontWeight: weight);

  static ThemeData theme() {
    final base = ThemeData.dark(useMaterial3: true);
    return base.copyWith(
      scaffoldBackgroundColor: ink,
      colorScheme: const ColorScheme.dark(
        primary: gold,
        secondary: neon,
        surface: panel,
        error: crimson,
      ),
      textTheme: base.textTheme.apply(fontFamily: GoogleFonts.inter().fontFamily, bodyColor: cream, displayColor: cream),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: ButtonStyle(
          foregroundColor: WidgetStateProperty.resolveWith((st) => st.contains(WidgetState.selected) ? goldLight : muted),
          textStyle: WidgetStatePropertyAll(body(13, weight: FontWeight.w700)),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: panelHi,
        contentTextStyle: body(14),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side: BorderSide(color: gold.withValues(alpha: 0.5)),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: ink.withValues(alpha: 0.6),
        labelStyle: body(14, color: muted),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: gold.withValues(alpha: 0.25)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: gold, width: 1.4),
        ),
      ),
    );
  }
}

String formatMoney(num v) {
  final s = v.round().abs().toString();
  final b = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 == 0) b.write('.');
    b.write(s[i]);
  }
  return '${v < 0 ? '-' : ''}₺${b.toString()}';
}

Color hexColor(String hex) {
  final h = hex.replaceAll('#', '');
  return Color(int.parse(h.length == 6 ? 'FF$h' : h, radix: 16));
}
