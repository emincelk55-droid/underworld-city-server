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
                      const SizedBox(height: 4),
                      _ServerRow(game: widget.game),
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

/// Giriş ekranının altında: hangi sunucuya bağlı olduğunu gösterir, değiştirmeye izin verir.
class _ServerRow extends StatelessWidget {
  final GameState game;
  const _ServerRow({required this.game});

  @override
  Widget build(BuildContext context) {
    final host = Uri.tryParse(game.baseUrl)?.host ?? game.baseUrl;
    return InkWell(
      onTap: () => showDialog(context: context, builder: (_) => _ServerDialog(game: game)),
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 4),
        child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(Icons.dns_outlined, size: 14, color: UW.muted.withValues(alpha: 0.9)),
          const SizedBox(width: 6),
          Flexible(
            child: Text('Sunucu: $host', overflow: TextOverflow.ellipsis, style: UW.body(11.5, color: UW.muted)),
          ),
          const SizedBox(width: 6),
          Text('Değiştir', style: UW.body(11.5, color: UW.goldLight, weight: FontWeight.w700)),
        ]),
      ),
    );
  }
}

class _ServerDialog extends StatefulWidget {
  final GameState game;
  const _ServerDialog({required this.game});

  @override
  State<_ServerDialog> createState() => _ServerDialogState();
}

class _ServerDialogState extends State<_ServerDialog> {
  late final _c = TextEditingController(text: widget.game.baseUrl);
  bool busy = false;
  String? error;

  Future<void> _connect() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await widget.game.setServer(_c.text);
      if (mounted) Navigator.pop(context);
    } catch (e) {
      setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Dialog(
        backgroundColor: Colors.transparent,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 400),
          child: DecoPanel(
            padding: const EdgeInsets.all(20),
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const DecoHeading('Sunucu', size: 13),
              const SizedBox(height: 12),
              Text(
                'Oyunun çalıştığı sunucunun adresi. Örnek: underworld-city.onrender.com ya da '
                'aynı Wi-Fi ağındaki bilgisayar için 192.168.1.20:3000',
                style: UW.body(12, color: UW.muted),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _c,
                keyboardType: TextInputType.url,
                autocorrect: false,
                style: UW.body(14),
                decoration: const InputDecoration(labelText: 'Adres', prefixIcon: Icon(Icons.dns_outlined, color: UW.gold)),
                onSubmitted: (_) => _connect(),
              ),
              if (busy) ...[
                const SizedBox(height: 10),
                Text('Bağlanılıyor... Sunucu uykudaysa uyanması bir dakika sürebilir.',
                    style: UW.body(11.5, color: UW.goldLight)),
              ],
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!, style: UW.body(12, color: UW.crimson)),
              ],
              const SizedBox(height: 14),
              DecoButton('Bağlan', icon: Icons.link, loading: busy, onTap: _connect),
            ]),
          ),
        ),
      );
}
