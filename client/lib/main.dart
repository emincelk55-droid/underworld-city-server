import 'package:flutter/material.dart';

import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'state.dart';
import 'theme.dart';
import 'widgets/skyline.dart';

void main() {
  runApp(const UnderworldApp());
}

class UnderworldApp extends StatefulWidget {
  const UnderworldApp({super.key});

  @override
  State<UnderworldApp> createState() => _UnderworldAppState();
}

class _UnderworldAppState extends State<UnderworldApp> {
  final game = GameState();

  @override
  void initState() {
    super.initState();
    game.boot();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Underworld City',
      debugShowCheckedModeBanner: false,
      theme: UW.theme(),
      home: ListenableBuilder(
        listenable: game,
        builder: (context, _) {
          if (game.booting) {
            return const Scaffold(
              body: Stack(fit: StackFit.expand, children: [
                NoirSkyline(),
                Center(child: CircularProgressIndicator(color: UW.gold)),
              ]),
            );
          }
          if (game.token == null || game.me == null) return LoginScreen(game: game);
          return HomeScreen(game: game);
        },
      ),
    );
  }
}
