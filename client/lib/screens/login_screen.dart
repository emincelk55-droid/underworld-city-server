import 'package:flutter/material.dart';

import '../state.dart';
import '../theme.dart';
import '../widgets/deco.dart';
import '../widgets/skyline.dart';

class LoginScreen extends StatefulWidget {
  final GameState game;
  const LoginScreen({super.key, required this.game});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _user = TextEditingController();
  final _pass = TextEditingController();
  bool _register = false;
  bool _loading = false;
  String? _error;

  Future<void> _submit() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await widget.game.login(_user.text.trim(), _pass.text, register: _register);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(fit: StackFit.expand, children: [
        const NoirSkyline(),
        SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 400),
                child: Column(children: [
                  Text('— 1931 —', style: UW.display(12, color: UW.gold.withValues(alpha: 0.8))),
                  const SizedBox(height: 6),
                  GoldText('UNDERWORLD',
                      align: TextAlign.center,
                      style: UW.display(40, weight: FontWeight.w900).copyWith(shadows: [
                        Shadow(color: UW.gold.withValues(alpha: 0.6), blurRadius: 24),
                      ])),
                  GoldText('C I T Y', style: UW.display(20, weight: FontWeight.w700)),
                  const SizedBox(height: 8),
                  Text('Liman şehrinde sıfırdan başla. Al, taşı, sat.\nŞehrin Babası ol.',
                      textAlign: TextAlign.center, style: UW.serif(14, color: UW.cream.withValues(alpha: 0.75), weight: FontWeight.w400)),
                  const SizedBox(height: 28),
                  DecoPanel(
                    glow: true,
                    padding: const EdgeInsets.fromLTRB(22, 22, 22, 18),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                      DecoHeading(_register ? 'Aileye Katıl' : 'Giriş'),
                      const SizedBox(height: 20),
                      TextField(
                        controller: _user,
                        style: UW.body(15),
                        decoration: const InputDecoration(labelText: 'Takma ad', prefixIcon: Icon(Icons.person_outline, color: UW.gold)),
                        textInputAction: TextInputAction.next,
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _pass,
                        obscureText: true,
                        style: UW.body(15),
                        decoration: const InputDecoration(labelText: 'Şifre', prefixIcon: Icon(Icons.lock_outline, color: UW.gold)),
                        onSubmitted: (_) => _submit(),
                      ),
                      if (_error != null) ...[
                        const SizedBox(height: 12),
                        Text(_error!, style: UW.body(13, color: UW.crimson), textAlign: TextAlign.center),
                      ],
                      const SizedBox(height: 20),
                      DecoButton(_register ? 'Kayıt Ol' : 'Şehre Gir',
                          icon: Icons.login, loading: _loading, onTap: _submit),
                      const SizedBox(height: 10),
                      TextButton(
                        onPressed: () => setState(() {
                          _register = !_register;
                          _error = null;
                        }),
                        child: Text(_register ? 'Zaten hesabın var mı? Giriş yap' : 'Yeni misin? Hesap oluştur',
                            style: UW.body(13, color: UW.goldLight)),
                      ),
                    ]),
                  ),
                ]),
              ),
            ),
          ),
        ),
      ]),
    );
  }
}
