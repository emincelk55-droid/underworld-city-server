import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models.dart';
import '../state.dart';
import '../theme.dart';
import '../widgets/crest.dart';
import '../widgets/deco.dart';
import 'panels.dart' show Toast;


const gangColors = ['#C0392B', '#8E44AD', '#2980B9', '#16A085', '#D4AF37', '#E67E22', '#7F8C8D', '#E84393'];
const rankNames = {'boss': 'Baba', 'underboss': 'Sağ Kol', 'capo': 'Kaptan', 'soldier': 'Asker'};
const rankIcons = {
  'boss': Icons.workspace_premium,
  'underboss': Icons.shield,
  'capo': Icons.military_tech,
  'soldier': Icons.person,
};

// ====================== AİLE SEKMESİ ======================
class GangPanel extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const GangPanel({super.key, required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    if (game.me?.gang == null) return _NoGang(game: game, toast: toast);
    final g = game.myGang;
    if (g == null) return const Center(child: CircularProgressIndicator(color: UW.gold));
    return _MyGangView(game: game, gang: g, toast: toast);
  }
}

class _NoGang extends StatelessWidget {
  final GameState game;
  final Toast toast;
  const _NoGang({required this.game, required this.toast});

  @override
  Widget build(BuildContext context) {
    return ListView(children: [
      DecoPanel(
        glow: true,
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const DecoHeading('Aileni Kur'),
          const SizedBox(height: 10),
          Text(
            'Bu şehirde yalnız kurt uzun yaşamaz. Bir aile kur ya da birine katıl. Semtleri ele geçir, vergiden pay al, '
            'polisi yanına çek.',
            textAlign: TextAlign.center,
            style: UW.serif(13, color: UW.cream.withValues(alpha: 0.8), weight: FontWeight.w400),
          ),
          const SizedBox(height: 14),
          DecoButton(
            'Yeni Aile Kur  ·  ${formatMoney(game.gangCreateCost)}',
            icon: Icons.add_moderator,
            onTap: () => showModalBottomSheet(
              context: context,
              isScrollControlled: true,
              backgroundColor: Colors.transparent,
              builder: (_) => CreateGangSheet(game: game, toast: toast),
            ),
          ),
        ]),
      ),
      const SizedBox(height: 14),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4),
        child: Text('ŞEHRİN AİLELERİ', style: UW.display(12, color: UW.muted)),
      ),
      const SizedBox(height: 8),
      if (game.gangs.isEmpty)
        Padding(
          padding: const EdgeInsets.all(24),
          child: Text('Henüz kimse aile kurmadı. İlk sen ol.',
              textAlign: TextAlign.center, style: UW.serif(14, color: UW.muted, weight: FontWeight.w400)),
        ),
      for (final g in game.gangs)
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: _GangCard(
            gang: g,
            trailing: OutlinedButton(
              onPressed: g.members >= g.maxMembers
                  ? null
                  : () async {
                      try {
                        await game.joinGang(g.id);
                        toast('[${g.tag}] ${g.name} ailesine katıldın');
                      } catch (e) {
                        toast(e.toString(), error: true);
                      }
                    },
              child: Text(g.members >= g.maxMembers ? 'DOLU' : 'KATIL'),
            ),
          ),
        ),
    ]);
  }
}

class _GangCard extends StatelessWidget {
  final GangListItem gang;
  final Widget? trailing;
  const _GangCard({required this.gang, this.trailing});

  @override
  Widget build(BuildContext context) {
    final c = hexColor(gang.color);
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: LinearGradient(colors: [Color.lerp(c, UW.panel, 0.8)!, UW.panel]),
        border: Border.all(color: c.withValues(alpha: 0.45)),
      ),
      child: Row(children: [
        GangCrest(color: gang.color, emblem: gang.emblem, tag: gang.tag, size: 46),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(gang.name, style: UW.serif(16)),
            if (gang.motto.isNotEmpty)
              Text('“${gang.motto}”',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: UW.serif(12, color: UW.muted, weight: FontWeight.w400).copyWith(fontStyle: FontStyle.italic)),
            const SizedBox(height: 6),
            Wrap(spacing: 5, runSpacing: 4, children: [
              Chip2('${gang.members}/${gang.maxMembers}', icon: Icons.group),
              Chip2('${gang.territories} semt', icon: Icons.flag, color: c),
              Chip2('${gang.influence} nüfuz', icon: Icons.trending_up, color: UW.gold),
            ]),
          ]),
        ),
        ?trailing,
      ]),
    );
  }
}

class _MyGangView extends StatelessWidget {
  final GameState game;
  final GangDetail gang;
  final Toast toast;
  const _MyGangView({required this.game, required this.gang, required this.toast});

  Future<void> _bank(BuildContext context, bool deposit) async {
    final amount = await showDialog<int>(context: context, builder: (_) => _AmountDialog(deposit: deposit));
    if (amount == null || amount <= 0) return;
    try {
      await game.gangBank(deposit, amount);
      toast(deposit ? '${formatMoney(amount)} kasaya yatırıldı' : '${formatMoney(amount)} kasadan çekildi');
    } catch (e) {
      toast(e.toString(), error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final my = game.me!.gang!;
    final c = hexColor(gang.color);
    return ListView(children: [
      // Afiş
      Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: c.withValues(alpha: 0.7)),
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color.lerp(c, Colors.black, 0.45)!, UW.panel, UW.night],
          ),
          boxShadow: [BoxShadow(color: c.withValues(alpha: 0.3), blurRadius: 28)],
        ),
        child: Stack(children: [
          Positioned.fill(
            child: ClipRRect(borderRadius: BorderRadius.circular(6), child: CustomPaint(painter: _SunburstPainter(c))),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 20, 18, 16),
            child: Column(children: [
              GangCrest(color: gang.color, emblem: gang.emblem, tag: gang.tag, size: 92, glow: true),
              const SizedBox(height: 12),
              GoldText(gang.name.toUpperCase(), align: TextAlign.center, style: UW.display(22, weight: FontWeight.w900)),
              if (gang.motto.isNotEmpty)
                Text('“${gang.motto}”',
                    textAlign: TextAlign.center,
                    style: UW.serif(14, color: UW.cream.withValues(alpha: 0.8), weight: FontWeight.w400)
                        .copyWith(fontStyle: FontStyle.italic)),
              const SizedBox(height: 6),
              Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                Icon(rankIcons[my.rank], size: 16, color: UW.goldLight),
                const SizedBox(width: 6),
                Text('Rütben: ${rankNames[my.rank]}', style: UW.body(13, color: UW.goldLight, weight: FontWeight.w700)),
              ]),
              const SizedBox(height: 14),
              Row(children: [
                _Stat('ÜYE', '${gang.members.length}/${gang.maxMembers}'),
                _Stat('SEMT', '${gang.territories.length}'),
                _Stat('KASA', formatMoney(gang.bank), gold: true),
              ]),
            ]),
          ),
        ]),
      ),
      const SizedBox(height: 12),
      // Bölgeler
      DecoPanel(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text('BÖLGELERİMİZ', style: UW.display(11, color: UW.muted)),
          const SizedBox(height: 8),
          if (gang.territories.isEmpty)
            Text('Henüz bir semt yok. Haritada bir semte dokun, nöbet tut ya da rüşvet dağıt. '
                'Tur bittiğinde en çok nüfuzu olan aile semti alır.',
                style: UW.serif(13, color: UW.cream.withValues(alpha: 0.75), weight: FontWeight.w400))
          else
            Wrap(spacing: 6, runSpacing: 6, children: [
              for (final id in gang.territories)
                Chip2(game.district(id)?.name ?? id, icon: Icons.flag, color: hexColor(game.district(id)?.color ?? '#D4AF37')),
            ]),
          const SizedBox(height: 10),
          Text('Bölge avantajları: yarı vergi · satış vergisinin yarısı kasaya · yarı polis riski · soygun yok',
              style: UW.body(11, color: UW.muted)),
        ]),
      ),
      const SizedBox(height: 12),
      // Kasa
      Row(children: [
        Expanded(child: DecoButton('Kasaya Yatır', icon: Icons.savings, onTap: () => _bank(context, true))),
        const SizedBox(width: 8),
        Expanded(
          child: DecoButton('Kasadan Çek',
              icon: Icons.payments, primary: false, onTap: my.canManage ? () => _bank(context, false) : null),
        ),
      ]),
      const SizedBox(height: 12),
      // Üyeler
      DecoPanel(
        padding: const EdgeInsets.fromLTRB(12, 14, 12, 8),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const DecoHeading('Aile Üyeleri', size: 13),
          const SizedBox(height: 10),
          for (final m in gang.members) _MemberRow(game: game, member: m, my: my, toast: toast),
        ]),
      ),
      const SizedBox(height: 12),
      TextButton.icon(
        onPressed: () async {
          final ok = await showDialog<bool>(
            context: context,
            builder: (_) => AlertDialog(
              backgroundColor: UW.panel,
              title: Text('Aileden ayrıl?', style: UW.serif(18)),
              content: Text(
                gang.members.length == 1
                    ? 'Son üyesin. Ayrılırsan aile dağılır, kasa ve bölgeler kaybolur.'
                    : 'Aileden ayrılırsan bölge avantajlarını kaybedersin.',
                style: UW.body(14),
              ),
              actions: [
                TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Vazgeç')),
                TextButton(
                    onPressed: () => Navigator.pop(context, true),
                    child: Text('Ayrıl', style: UW.body(14, color: UW.crimson, weight: FontWeight.w700))),
              ],
            ),
          );
          if (ok != true) return;
          try {
            await game.leaveGang();
            toast('Aileden ayrıldın');
          } catch (e) {
            toast(e.toString(), error: true);
          }
        },
        icon: const Icon(Icons.logout, color: UW.crimson, size: 18),
        label: Text('Aileden ayrıl', style: UW.body(13, color: UW.crimson)),
      ),
    ]);
  }
}

class _Stat extends StatelessWidget {
  final String label, value;
  final bool gold;
  const _Stat(this.label, this.value, {this.gold = false});

  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          margin: const EdgeInsets.symmetric(horizontal: 3),
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            color: Colors.black.withValues(alpha: 0.35),
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: UW.gold.withValues(alpha: 0.25)),
          ),
          child: Column(children: [
            Text(label, style: UW.display(9, color: UW.muted)),
            const SizedBox(height: 2),
            gold ? GoldText(value, style: UW.number(15)) : Text(value, style: UW.number(15)),
          ]),
        ),
      );
}

class _MemberRow extends StatelessWidget {
  final GameState game;
  final GangMember member;
  final MyGang my;
  final Toast toast;
  const _MemberRow({required this.game, required this.member, required this.my, required this.toast});

  @override
  Widget build(BuildContext context) {
    final isMe = member.username == game.me?.username;
    final rankOrder = ['soldier', 'capo', 'underboss', 'boss'];
    final canKick = !isMe && my.canManage && rankOrder.indexOf(member.rank) < rankOrder.indexOf(my.rank);
    final canPromote = !isMe && my.isBoss;
    final loc = game.district(member.districtId);
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: isMe ? UW.gold.withValues(alpha: 0.1) : Colors.black.withValues(alpha: 0.25),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: UW.gold.withValues(alpha: isMe ? 0.5 : 0.12)),
      ),
      child: Row(children: [
        Container(
          width: 34,
          height: 34,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: UW.ink,
            border: Border.all(color: member.rank == 'boss' ? UW.goldLight : UW.gold.withValues(alpha: 0.5)),
          ),
          child: Icon(rankIcons[member.rank], size: 18, color: member.rank == 'boss' ? UW.goldLight : UW.gold),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(member.username, style: UW.serif(14)),
            Text('${member.rankName} · Sv ${member.level}${loc != null ? ' · ${loc.name}' : ''}',
                style: UW.body(11, color: UW.muted)),
          ]),
        ),
        Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
          Text('${member.contribution}', style: UW.number(14, color: UW.goldLight)),
          Text('katkı', style: UW.body(10, color: UW.muted)),
        ]),
        if (canKick || canPromote)
          PopupMenuButton<String>(
            color: UW.panelHi,
            icon: const Icon(Icons.more_vert, color: UW.muted, size: 20),
            onSelected: (v) async {
              try {
                if (v == 'kick') {
                  await game.kickMember(member.userId);
                  toast('${member.username} aileden atıldı');
                } else {
                  await game.setRank(member.userId, v);
                  toast('${member.username} artık ${rankNames[v]}');
                }
              } catch (e) {
                toast(e.toString(), error: true);
              }
            },
            itemBuilder: (_) => [
              if (canPromote)
                for (final r in ['underboss', 'capo', 'soldier'])
                  if (r != member.rank) PopupMenuItem(value: r, child: Text('${rankNames[r]} yap')),
              if (canPromote) const PopupMenuItem(value: 'boss', child: Text('Babalığı devret')),
              if (canKick)
                PopupMenuItem(value: 'kick', child: Text('Aileden at', style: UW.body(14, color: UW.crimson))),
            ],
          ),
      ]),
    );
  }
}

class _AmountDialog extends StatefulWidget {
  final bool deposit;
  const _AmountDialog({required this.deposit});

  @override
  State<_AmountDialog> createState() => _AmountDialogState();
}

class _AmountDialogState extends State<_AmountDialog> {
  final _c = TextEditingController();

  @override
  Widget build(BuildContext context) => Dialog(
        backgroundColor: Colors.transparent,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 360),
          child: DecoPanel(
            padding: const EdgeInsets.all(20),
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              DecoHeading(widget.deposit ? 'Kasaya Yatır' : 'Kasadan Çek', size: 13),
              const SizedBox(height: 16),
              TextField(
                controller: _c,
                autofocus: true,
                keyboardType: TextInputType.number,
                inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                style: UW.number(20, color: UW.goldLight),
                decoration: const InputDecoration(labelText: 'Miktar (₺)'),
                onSubmitted: (_) => Navigator.pop(context, int.tryParse(_c.text)),
              ),
              const SizedBox(height: 16),
              DecoButton('Onayla', onTap: () => Navigator.pop(context, int.tryParse(_c.text))),
            ]),
          ),
        ),
      );
}

class _SunburstPainter extends CustomPainter {
  final Color c;
  _SunburstPainter(this.c);

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, 70);
    final p = Paint()..color = c.withValues(alpha: 0.12);
    for (var i = 0; i < 24; i++) {
      final a0 = i * math.pi / 12;
      if (i.isOdd) continue;
      final path = Path()
        ..moveTo(center.dx, center.dy)
        ..lineTo(center.dx + math.cos(a0) * 600, center.dy + math.sin(a0) * 600)
        ..lineTo(center.dx + math.cos(a0 + math.pi / 12) * 600, center.dy + math.sin(a0 + math.pi / 12) * 600)
        ..close();
      canvas.drawPath(path, p);
    }
  }

  @override
  bool shouldRepaint(covariant _SunburstPainter old) => old.c != c;
}

// ====================== ÇETE KURMA ======================
class CreateGangSheet extends StatefulWidget {
  final GameState game;
  final Toast toast;
  const CreateGangSheet({super.key, required this.game, required this.toast});

  @override
  State<CreateGangSheet> createState() => _CreateGangSheetState();
}

class _CreateGangSheetState extends State<CreateGangSheet> {
  final _name = TextEditingController();
  final _tag = TextEditingController();
  final _motto = TextEditingController();
  String color = gangColors[0];
  String emblem = 'rose';
  bool busy = false;

  Future<void> _create() async {
    setState(() => busy = true);
    try {
      await widget.game.createGang(_name.text, _tag.text, color, emblem, _motto.text);
      if (!mounted) return;
      Navigator.pop(context);
      widget.toast('Ailen kuruldu. Şehir artık seni tanıyor.');
    } catch (e) {
      widget.toast(e.toString(), error: true);
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final tag = _tag.text.isEmpty ? '??' : _tag.text.toUpperCase();
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: Center(
        heightFactor: 1,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: DecoPanel(
              glow: true,
              accent: hexColor(color),
              padding: const EdgeInsets.fromLTRB(20, 18, 20, 16),
              child: SingleChildScrollView(
                child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  const DecoHeading('Yeni Aile'),
                  const SizedBox(height: 14),
                  Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    GangCrest(color: color, emblem: emblem, tag: tag, size: 84, glow: true),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(children: [
                        TextField(
                          controller: _name,
                          maxLength: 24,
                          style: UW.body(15),
                          decoration: const InputDecoration(labelText: 'Aile adı', counterText: '', isDense: true),
                          onChanged: (_) => setState(() {}),
                        ),
                        const SizedBox(height: 10),
                        TextField(
                          controller: _tag,
                          maxLength: 4,
                          textCapitalization: TextCapitalization.characters,
                          style: UW.display(15),
                          decoration: const InputDecoration(labelText: 'Kısaltma (2-4)', counterText: '', isDense: true),
                          onChanged: (_) => setState(() {}),
                        ),
                      ]),
                    ),
                  ]),
                  const SizedBox(height: 10),
                  TextField(
                    controller: _motto,
                    maxLength: 80,
                    style: UW.serif(14, weight: FontWeight.w400),
                    decoration: const InputDecoration(labelText: 'Slogan (isteğe bağlı)', counterText: '', isDense: true),
                  ),
                  const SizedBox(height: 14),
                  Text('RENK', style: UW.display(10, color: UW.muted)),
                  const SizedBox(height: 6),
                  Wrap(spacing: 8, runSpacing: 8, children: [
                    for (final c in gangColors)
                      GestureDetector(
                        onTap: () => setState(() => color = c),
                        child: AnimatedContainer(
                          duration: const Duration(milliseconds: 150),
                          width: 34,
                          height: 34,
                          decoration: BoxDecoration(
                            color: hexColor(c),
                            shape: BoxShape.circle,
                            border: Border.all(color: c == color ? UW.goldLight : Colors.black, width: c == color ? 3 : 1),
                            boxShadow: c == color ? [BoxShadow(color: hexColor(c), blurRadius: 12)] : null,
                          ),
                        ),
                      ),
                  ]),
                  const SizedBox(height: 14),
                  Text('AMBLEM', style: UW.display(10, color: UW.muted)),
                  const SizedBox(height: 6),
                  Wrap(spacing: 8, runSpacing: 8, children: [
                    for (final e in emblemNames.keys)
                      Tooltip(
                        message: emblemNames[e]!,
                        child: GestureDetector(
                          onTap: () => setState(() => emblem = e),
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: BoxDecoration(
                              color: e == emblem ? hexColor(color).withValues(alpha: 0.35) : UW.ink,
                              borderRadius: BorderRadius.circular(4),
                              border: Border.all(color: e == emblem ? UW.goldLight : UW.gold.withValues(alpha: 0.3)),
                            ),
                            child: Icon(emblemIcon(e), color: e == emblem ? UW.goldLight : UW.muted),
                          ),
                        ),
                      ),
                  ]),
                  const SizedBox(height: 18),
                  DecoButton('Kur  ·  ${formatMoney(widget.game.gangCreateCost)}',
                      icon: Icons.add_moderator,
                      loading: busy,
                      onTap: (widget.game.me?.money ?? 0) >= widget.game.gangCreateCost ? _create : null),
                  if ((widget.game.me?.money ?? 0) < widget.game.gangCreateCost)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text('Yeterli paran yok. Biraz daha ticaret yap.',
                          textAlign: TextAlign.center, style: UW.body(12, color: UW.crimson)),
                    ),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ====================== BÖLGE SAVAŞI (semt kartında) ======================
class WarSection extends StatelessWidget {
  final GameState game;
  final District district;
  final Toast toast;
  const WarSection({super.key, required this.game, required this.district, required this.toast});

  String _resultText(Map<String, dynamic> r) => switch (r['type']) {
        'patrol' => 'Adamların sokakları tuttu: +${r['points']} nüfuz',
        'bribe' => 'Zarflar dağıtıldı: +${r['points']} nüfuz',
        'raid' => '${r['rival']} dağıtıldı: -${r['damage']} nüfuz',
        'raid_caught' => 'Baskında polise yakalandın! ${formatMoney(r['fine'] ?? 0)} ceza',
        _ => 'Tamam',
      };

  @override
  Widget build(BuildContext context) {
    final ter = game.territory[district.id];
    final me = game.me!;
    final myGang = me.gang;
    final ctrl = ter?.controller;
    final inf = ter?.influence ?? const <Influence>[];
    final maxPts = math.max(game.controlMin.toDouble(), inf.isEmpty ? 0.0 : inf.first.points.toDouble());
    final here = me.districtId == district.id && me.travel == null;

    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Text('BÖLGE SAVAŞI', style: UW.display(11, color: UW.muted)),
        const Spacer(),
        if (ter?.warEndsAt != null) ...[
          const Icon(Icons.timer_outlined, size: 14, color: UW.goldLight),
          const SizedBox(width: 4),
          Countdown(to: ter!.warEndsAt!, style: UW.number(13, color: UW.goldLight)),
        ],
      ]),
      const SizedBox(height: 8),
      Row(children: [
        if (ctrl != null)
          GangCrest(color: ctrl.color, emblem: ctrl.emblem, tag: ctrl.tag, size: 34)
        else
          Container(
            width: 34,
            height: 40,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              border: Border.all(color: UW.muted.withValues(alpha: 0.5)),
              borderRadius: BorderRadius.circular(4),
            ),
            child: const Icon(Icons.flag_outlined, color: UW.muted, size: 18),
          ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(ctrl == null ? 'Sahipsiz semt' : '[${ctrl.tag}] ${ctrl.name}', style: UW.serif(15)),
            Text(
              ctrl == null
                  ? 'Tur sonunda en az ${game.controlMin} nüfuzu olan en güçlü aile alır'
                  : (ctrl.id == myGang?.id ? 'Senin ailenin bölgesi' : 'Bu semti yöneten aile'),
              style: UW.body(11, color: ctrl?.id == myGang?.id ? UW.emerald : UW.muted),
            ),
          ]),
        ),
        if (ter?.contested == true) const Chip2('ÇATIŞMA', icon: Icons.local_fire_department, color: UW.crimson),
      ]),
      const SizedBox(height: 10),
      if (inf.isEmpty)
        Text('Bu turda kimse nüfuz kazanmadı.', style: UW.body(12, color: UW.muted))
      else
        for (final i in inf.take(3))
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: _InfluenceBar(influence: i, max: maxPts, threshold: game.controlMin, mine: i.id == myGang?.id),
          ),
      const SizedBox(height: 8),
      if (myGang == null)
        Text('Bölge savaşına katılmak için bir aileye katıl (Aile sekmesi).', style: UW.body(12, color: UW.goldLight))
      else if (!here)
        Text('Bu semtte eylem yapmak için önce buraya gitmelisin.', style: UW.body(12, color: UW.muted))
      else
        Row(children: [
          for (final a in game.territoryActions)
            Expanded(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 3),
                child: _ActionButton(
                  action: a,
                  enabled: me.energy >= a.energy && me.money >= a.money,
                  onTap: () async {
                    try {
                      final r = await game.territoryAction(a.id);
                      toast(_resultText(r), error: r['type'] == 'raid_caught');
                    } catch (e) {
                      toast(e.toString(), error: true);
                    }
                  },
                ),
              ),
            ),
        ]),
    ]);
  }
}

class _InfluenceBar extends StatelessWidget {
  final Influence influence;
  final double max;
  final int threshold;
  final bool mine;
  const _InfluenceBar({required this.influence, required this.max, required this.threshold, required this.mine});

  @override
  Widget build(BuildContext context) {
    final c = hexColor(influence.color);
    return Row(children: [
      SizedBox(
        width: 44,
        child: Text(influence.tag, style: UW.display(11, color: mine ? UW.goldLight : UW.cream, weight: FontWeight.w900)),
      ),
      Expanded(
        child: LayoutBuilder(builder: (context, box) {
          final w = box.maxWidth;
          return SizedBox(
            height: 14,
            child: Stack(children: [
              Container(
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(3),
                  border: Border.all(color: c.withValues(alpha: 0.3)),
                ),
              ),
              AnimatedContainer(
                duration: const Duration(milliseconds: 500),
                curve: Curves.easeOutCubic,
                width: w * (influence.points / max).clamp(0.0, 1.0),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(3),
                  gradient: LinearGradient(colors: [Color.lerp(c, Colors.black, 0.3)!, c]),
                  boxShadow: [BoxShadow(color: c.withValues(alpha: 0.6), blurRadius: 8)],
                ),
              ),
              // Kontrol eşiği işareti
              Positioned(
                left: w * (threshold / max).clamp(0.0, 1.0) - 1,
                top: -2,
                bottom: -2,
                child: Container(width: 2, color: UW.goldLight),
              ),
            ]),
          );
        }),
      ),
      SizedBox(
        width: 44,
        child: Text('${influence.points}', textAlign: TextAlign.right, style: UW.number(12, color: UW.goldLight)),
      ),
    ]);
  }
}

class _ActionButton extends StatelessWidget {
  final TerritoryAction action;
  final bool enabled;
  final VoidCallback onTap;
  const _ActionButton({required this.action, required this.enabled, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final icon = switch (action.id) {
      'patrol' => Icons.directions_walk,
      'bribe' => Icons.mail,
      _ => Icons.sports_mma,
    };
    final c = action.id == 'raid' ? UW.crimson : UW.gold;
    return Tooltip(
      message: action.desc,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: enabled ? onTap : null,
          borderRadius: BorderRadius.circular(4),
          child: Opacity(
            opacity: enabled ? 1 : 0.4,
            child: Container(
              padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 4),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                color: c.withValues(alpha: 0.1),
                border: Border.all(color: c.withValues(alpha: 0.7)),
              ),
              child: Column(children: [
                Icon(icon, color: c, size: 22),
                const SizedBox(height: 4),
                Text(action.name.toUpperCase(),
                    textAlign: TextAlign.center, style: UW.display(9.5, color: UW.cream, weight: FontWeight.w800)),
                const SizedBox(height: 2),
                Text(
                  [if (action.energy > 0) '⚡${action.energy}', if (action.money > 0) formatMoney(action.money)].join(' · '),
                  style: UW.number(10, color: UW.muted),
                ),
              ]),
            ),
          ),
        ),
      ),
    );
  }
}

/// Saniyede bir güncellenen geri sayım.
class Countdown extends StatefulWidget {
  final DateTime to;
  final TextStyle style;
  const Countdown({super.key, required this.to, required this.style});

  @override
  State<Countdown> createState() => _CountdownState();
}

class _CountdownState extends State<Countdown> {
  late final Timer _t = Timer.periodic(const Duration(seconds: 1), (_) => setState(() {}));

  @override
  void dispose() {
    _t.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    var d = widget.to.difference(DateTime.now());
    if (d.isNegative) d = Duration.zero;
    final h = d.inHours, m = (d.inMinutes % 60).toString().padLeft(2, '0'), s = (d.inSeconds % 60).toString().padLeft(2, '0');
    return Text(h > 0 ? '$h:$m:$s' : '$m:$s', style: widget.style);
  }
}

// ====================== HABER BANDI ======================
class NewsTicker extends StatefulWidget {
  final List<NewsItem> news;
  const NewsTicker({super.key, required this.news});

  @override
  State<NewsTicker> createState() => _NewsTickerState();
}

class _NewsTickerState extends State<NewsTicker> {
  int _i = 0;
  late final Timer _t = Timer.periodic(const Duration(seconds: 5), (_) {
    if (widget.news.length > 1) setState(() => _i = (_i + 1) % math.min(5, widget.news.length));
  });

  @override
  void dispose() {
    _t.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.news.isEmpty) return const SizedBox();
    final n = widget.news[_i.clamp(0, widget.news.length - 1)];
    final c = switch (n.kind) {
      'war' => UW.crimson,
      'gang' => UW.neon,
      _ => UW.gold,
    };
    return Container(
      constraints: const BoxConstraints(maxWidth: 520),
      decoration: BoxDecoration(
        color: const Color(0xFFEDE3C8),
        borderRadius: BorderRadius.circular(2),
        boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 10, offset: Offset(0, 4))],
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 7),
          color: c,
          child: Text('SON DAKİKA', style: UW.display(9.5, color: Colors.white, weight: FontWeight.w900)),
        ),
        Flexible(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10),
            child: AnimatedSwitcher(
              duration: const Duration(milliseconds: 400),
              transitionBuilder: (child, a) => FadeTransition(
                opacity: a,
                child: SlideTransition(position: Tween(begin: const Offset(0, 0.4), end: Offset.zero).animate(a), child: child),
              ),
              child: Text(
                n.text,
                key: ValueKey(n.id),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: UW.serif(12.5, color: const Color(0xFF1E1A14), weight: FontWeight.w700),
              ),
            ),
          ),
        ),
      ]),
    );
  }
}
