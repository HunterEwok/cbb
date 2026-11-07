<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# التثبيت

يعمل Copy Beyond Borders كخدمة صغيرة في الخلفية على كل حاسوب. وأمره هو `cbb`. كل طريقة أدناه تثبّت البرنامج نفسه؛ فاختر ما يعجبك.

## Linux

أي نظام Linux يعمل بـ systemd (x86-64 وARM64 وARMv7 وARMv6): حاسوب محمول أو مكتبي أو Raspberry Pi أو خادم أو Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

ثم سجّل الخروج والدخول مرة واحدة، ليتمكن مستخدمك من استعمال `cbb` بلا `sudo`. أما الجهاز بلا سطح مكتب فيحصل على النسخ واللصق داخل tmux بالخيار `--console` (`... | sudo sh -s -- --console`).

على سطح مكتب فيه GTK 4 وWebKitGTK 6.0 (x86-64 وARM64) يثبّت أيضًا تطبيق شريط النظام، الذي يبدأ مع جلستك ويظهر في قائمة التطبيقات. وبدونهما يذكر الحزم التي يجب إضافتها؛ ثم شغّله مرة أخرى لتثبيت تطبيق شريط النظام.

يسأل اللصق عن بُعد على GNOME وKDE مرة واحدة، في مربع حوار على الحاسوب، قبل أن يسمح لأول لصق من مشرف بالضغط على المفاتيح. لتخطي مربع الحوار أضف `--uinput` (`... | sudo sh -s -- --uinput`): عندها يضغط مساعد صغير مفاتيح اللصق (Shift+Insert وEnter) نيابةً عمّن يستخدم الشاشة، ولا يفعل ذلك أبدًا في شاشة تسجيل الدخول أو القفل.

الأجهزة الصغيرة التي يكفيها أن تزامن، كالراوتر أو Raspberry Pi Zero، يمكنها استخدام [العضو الخفيف](../../member/README.md) الأخف بدلًا من ذلك: `... | sudo sh -s -- --lite`.

### من دون sudo (بلا root)

على حاسوب Linux لا تستطيع أو لا تريد فيه استعمال `sudo`، ثبّته لمستخدمك أنت من دون `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

يعمل كخدمة خلفية خاصة بك ما دمت مسجّلًا الدخول، ويزامن كأي عضو. استخدمه فقط حين يتعذر التثبيت العادي: فأي برنامج تشغّله يستطيع نسخ مفاتيحه، لذلك لا يمكن أن يكون أبدًا جذر المجموعة أو مشرفًا أو المحور ([كيف يعمل](how-it-works.md#rootless-members))، وليست له قواعد جدار حماية ولا TPM ولا `--console` ولا `--uinput`. ولإبقائه يعمل بعد تسجيل الخروج، ينفّذ مسؤول النظام مرة واحدة `sudo loginctl enable-linger YOUR-USER`. وللإزالة: `sh ~/.local/share/cbb/uninstall.sh`. ويُثبَّت العضو الخفيف بهذه الطريقة أيضًا، بالخيارين `--lite --rootless` ([العضو الخفيف](../../member/README.md#without-sudo-rootless)).

### SteamOS (Steam Deck)

انتقل إلى وضع سطح المكتب، وافتح Konsole، وأعطِ المستخدم `deck` كلمة مرور مرة واحدة إن لم تكن له (`passwd`)، ثم شغّل الأمر نفسه. يستبدل SteamOS ملفات نظامه مع كل تحديث، لذلك يضع المثبّت Copy Beyond Borders في `/opt/cbb` بدلًا من `/usr/local`، ويخبر SteamOS بأي من ملفاته في `/etc` يجب الإبقاء عليها (`/etc/atomic-update.conf.d/cbb.conf`). يبقى مثبّتًا وفي مجموعته عبر تحديثات SteamOS.

- يصبح `cbb` في مسار Konsole جديدة بعد أن تسجّل الخروج وتدخل من جديد. لا يبحث `sudo` هناك، لذلك تأخذ الأوامر التي تحتاج إليه المسار الكامل: `sudo /opt/cbb/bin/cbb pair`.
- في وضع سطح المكتب تتزامن الحافظة كما على أي سطح مكتب KDE Plasma.
- في وضع الألعاب لا توجد حافظة لسطح المكتب، فلا يتزامن شيء هناك؛ تواصل الخدمة عملها وتلحق بالمزامنة في وضع سطح المكتب.
- للإزالة: `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Apple silicon أو Intel، macOS 14 أو أحدث: نزّل `cbb-X.Y.Z.pkg` من
[أحدث إصدار](https://github.com/HunterEwok/cbb/releases/latest) وافتحه. يثبّت تطبيق CBB في شريط
القوائم والخدمة، وكلاهما موقّع من المشروع وفحصته Apple.

أو في Terminal، بلا التطبيق، والأمر نفسه كما في Linux:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

أو عبر Homebrew الذي يحدّثه أيضًا. شغّل السطر الثاني من جديد بعد كل `brew upgrade`:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

Windows 10 (الإصدار 1809 أو أحدث) أو 11، بمعمارية x86-64 أو ARM64، في PowerShell مفتوح بخيار «Run as administrator»:

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

يتيح للمستخدم المسجَّل دخوله عند الشاشة استعمال `cbb` (في طرفية جديدة)، ويشغّل له وكيل الحافظة. تُنفَّذ الأوامر التي تغيّر المجموعة في طرفية مفتوحة بصلاحية المسؤول، حيث يستعمل Linux وmacOS الأمر `sudo`.

ويثبّت أيضًا تطبيق شريط النظام، الذي يبدأ عند تسجيل الدخول ويظهر في قائمة ابدأ باسم CBB.

مع winget، حين تصبح الحزمة في مستودع winget:

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

راوتر يعمل بـ OpenWrt 25.12 أو أحدث وفيه متسع لبرنامج بحجم 25 ميغابايت (128 ميغابايت من الفلاش أو أكثر، أو eMMC؛ و256 ميغابايت من الذاكرة)، بصلاحية root عبر SSH:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

يثبّت `cbb` كخدمة تعمل في منطقة `lan` فقط ولا ترد أبدًا على `wan`. تقيم المفاتيح في `/etc/cbb` الذي يحتفظ به sysupgrade؛ وبعد sysupgrade بإشراف (ASU وowut) شغّل الأمر من جديد. المنطقة الأخرى، مثل شبكة إنترنت الأشياء، وجدار الحماية والفحوص كلها في [الراوترات وFreeBSD](../admin/routers.md#openwrt).

أو من مستودع حزمنا الذي يُبقيه `apk upgrade` محدَّثًا. تتبع معمارية المستودع معالج الراوتر (`grep DISTRIB_ARCH /etc/openwrt_release`): `arm64` للمعمارية `aarch64_*`، و`armv7` للمعمارية `arm_cortex-a*` التي يرد في اسمها `neon` أو `vfp`، و`mipsle` للمعمارية `mipsel_*`، و`mips` للمعمارية `mips_*`، و`amd64` للمعمارية `x86_64`. ضع معماريتك مكان `arm64` في السطر الثاني:

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

يزيله `apk del cbb` ويُبقي المفاتيح في `/etc/cbb`.

## FreeBSD

FreeBSD 15، بمعمارية amd64 أو arm64، بصلاحية root (مع `sudo` أو `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

يثبّت `cbb` وسكربت rc.d يشغّل الخدمة عبر daemon(8)، ويضيف السطر `cbb_enable="YES"` إلى rc.conf. تقيم المفاتيح في `/var/db/cbb`.

على OPNsense يضيف المثبّت نفسه أيضًا خطّاف إضافة: تظهر الخدمة تحت System > Diagnostics > Services، وتتبع قواعد جدار حمايتها (في مرساة pf المسماة `cbb`) كل إعادة تحميل للمرشّح. عطّل مكرّر mDNS (Services > mDNS Repeater) ما دامت الخدمة تعمل: فكلاهما يحتاج إلى المنفذ UDP 5353، والخدمة تجيب عن mDNS بنفسها على كل واجهة منزلية. pfSense غير مدعوم: يعمل المثبّت هناك أيضًا، لكنه يطبع قواعد جدار الحماية لتضعها في Firewall > Rules بدلًا من أن يضيفها، وقد يزيل تحديث pfSense برنامج Copy Beyond Borders.

على سطح مكتب FreeBSD (X11، أو Wayland مع بروتوكول data control كما في KDE وsway وHyprland) تشغّل الجلسة `cbb agent` من البدء التلقائي في XDG وتنضم الحافظة إلى المجموعة؛ سجّل الدخول من جديد بعد التثبيت. ويكتب اللصق عن بُعد عبر XTEST على X11 وعبر لوحة المفاتيح الافتراضية على أسطح مكتب wlroots؛ ولا يقبل GNOME اللصق عن بُعد على FreeBSD، إذ لا يوجد من دون logind ما يدل على أن شاشته مقفلة.

## Docker

لجهاز NAS أو خادم منزلي يعمل دائمًا ([README الخاص بالصورة](../../packaging/docker/README.md)؛ تُنشر مع كل إصدار منذ 0.5). ينضم كعضو عادي: أنشئ المجموعة على الهاتف أو على حاسوب تحمله أنت.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## جدار الحماية

يحتاج Copy Beyond Borders إلى منفذ TCP واحد هو 8764، وإلى mDNS (UDP 5353)، وكلاهما من الشبكة المنزلية فقط. يجد المثبّت جدار الحماية (ufw أو firewalld أو nftables أو iptables على Linux، وpf أو ipfw على FreeBSD، وجدار حماية التطبيقات في Mac، وجدار حماية Windows)، ويعرض كل قاعدة، ويسأل `Add these rules now? [y/N]`:

- **نعم**: يضيفها، ويُبقيها محدَّثة مع كل تحديث، ويزيلها حين تلغي التثبيت. ولا يمس القواعد الأخرى أبدًا.
- **لا** (وهو الافتراضي، وهو ما يحدث حين لا توجد طرفية للسؤال): لا يضيف شيئًا ويطبع الأوامر بدقة لتشغّلها أنت.
- `--express` (`-Express` على Windows) يضيفها من دون سؤال؛ و`--no-firewall` يجيب بـ«لا».

يحصل nftables وiptables دائمًا على الأوامر فقط، لأن القواعد المضافة أثناء التشغيل لا تبقى بعد إعادة التشغيل. وعلى FreeBSD تحصل pf على القواعد في مرساة خاصة بها، تقرؤها pf عبر ثلاثة أسطر معلَّمة يضيفها المثبّت في نهاية `/etc/pf.conf` ثم يزيلها؛ وتحصل ipfw عليها في مجموعة القواعد 17، وتُضاف من جديد عند كل بدء تشغيل. وإذا فعّلت جدار حماية لاحقًا فشغّل المثبّت من جديد.

**منفذ آخر**، إن كان 8764 مشغولًا: `... | sudo sh -s -- --port 9000` (على Windows `$env:CBB_PORT = "9000"` قبل المثبّت). يعرف تطبيق الهاتف المنفذ من رمز QR.

جميع خيارات المثبّت في [مرجع الأوامر](../reference/cli.md#installers).

## التحديث

الإصدارات موقَّعة منذ 0.6. للانتقال إلى 0.6 من إصدار أقدم، شغّل أمر التثبيت من جديد؛ ومن ثم يتولى `cbb update` ذلك.

يثبّت `sudo cbb update` (على Windows الأمر `cbb update` في طرفية مفتوحة بصلاحية المسؤول) أحدث إصدار على حاسوب أو عضو خفيف مثبَّت بـ `get.sh` أو `get.ps1` أو أرشيف إصدار؛ ويكتفي `cbb update -check` بإخبارك إن كان هناك إصدار جديد. وتبقى إعداداتك. لا يثبّت إلا إصدارًا وقّعه المشروع، ولا يثبّت أبدًا إصدارًا أقدم. وإذا لم يبدأ الإصدار الجديد خلال دقيقة، يعود السابق من تلقاء نفسه. وطريقة فحصه للتواقيع موصوفة في [البروتوكول](../protocol.md)، القسم 16.

تسأل المثبّتات مرة واحدة عما إذا كان التحديث تلقائيًا (`--auto-update on|off`، أو `-AutoUpdate on|off` و`$env:CBB_AUTO_UPDATE` على Windows، لتجيب مسبقًا)؛ ويغيّره لاحقًا `sudo cbb update -auto on|off`. وعند تفعيله يفحص مؤقّت مرة في اليوم في وقت خاص به: مؤقّت systemd على Linux، ومهمة launchd على Mac، ومهمة مجدولة بصلاحية SYSTEM على Windows، وcron على OpenWrt وFreeBSD. ينزّل كل فحص الملفات الصغيرة نفسها من GitHub (أو من `dl.cbb.tools` حين لا يرد GitHub)، فيعرف GitHub عنوان هذا الجهاز وأنه يستخدم Copy Beyond Borders، كما في أي تنزيل؛ ولا يرسل شيئًا عن المجموعة. ويأخذ `sudo cbb update -mirror https://...` التحديثات من مرآة أخرى بدلًا من ذلك، ولا يتطلب ذلك أي ثقة لأن التواقيع تُفحص. وسجل المؤقّت هو `update.log` في `/var/lib/cbb-update` (Linux) أو `/etc/cbb-update` (OpenWrt) أو `/var/db/cbb-update` (FreeBSD) أو `/Library/Application Support/cbb-update` (Mac) أو `C:\Program Files\cbb-update` (Windows).

تخبر أجهزة المجموعة بعضها بأحدث إصدار موقَّع رآه أيٌّ منها، فيكفي فحص جهاز واحد ليقول `cbb status` وتطبيق شريط المهام على الأجهزة الأخرى إن إصدارًا أحدث قد صدر (يشغّل «Update to X» في تطبيق شريط المهام الأمر `cbb update` بصلاحية المسؤول). ويفحص كل جهاز التواقيع بنفسه وينزّل أرشيفه الخاص.

وتشغيل أمر التثبيت نفسه من جديد يحدّث كذلك. ومع Homebrew أو winget، حدّث هناك ثم شغّل السطر الثاني من جديد؛ ويقول لك `cbb update` ذلك. ويُحدَّث Docker وحزمة OpenWrt عبر `docker compose pull` و`apk upgrade`.

## التحقق من تنزيل

تتحقق المثبّتات ذات السطر الواحد من التنزيل بمقارنته بملف `SHA256SUMS` الخاص بالإصدار. ولكل ملف في الإصدار أيضًا شهادة منشأ للبناء تربطه بهذا المستودع وبالبناء الذي أنتجه؛ وذلك باستخدام [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

يفحصها `get.sh` بنفسه حين يكون `gh` مثبّتًا ومسجَّلًا الدخول لحساب root (`sudo gh auth login`)؛ ويرفض `CBB_ATTESTATION=require` التثبيت من دونها.

وتُوقَّع الإصدارات أيضًا بمفاتيح المشروع نفسه التي لا تمس CI أبدًا (مفاتيح الجذر على مفاتيح عتادية غير متصلة، ومفتاح الإصدار في Secure Enclave لدى المشرف على المشروع): يسمّي `keys.json` مفاتيح الإصدار تحت مفاتيح جذر المشروع، ويسرد `release.json` كل ملف في الإصدار مع بصمته، ويبيّن `stable.json` أي إصدار هو الحالي. وحين تُضمَّن مفاتيح الجذر في المثبّتات سيفحص `get.sh` (مع `openssl`) و`get.ps1` هذه الملفات قبل التثبيت ويرفضان إصدارًا غير موقَّع؛ وإلى ذلك الحين يفحصان `SHA256SUMS` وشهادة المنشأ فقط. ويثبّت `CBB_VERIFY=skip` من دون الفحص.

## إزالته

على Linux وMac:

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

وعلى SteamOS هو `sudo sh /opt/cbb/share/uninstall.sh`. ومع Homebrew شغّل `brew uninstall cbb` بعده.

على Windows: الإعدادات، التطبيقات، «CBB»، إلغاء التثبيت.

يزيل هذا البرنامج والخدمة وقواعد جدار الحماية التي أضافها المثبّت، وعلى Mac التطبيق الذي ثبّته `.pkg`. وتبقى مفاتيح الجهاز، فيعيده التثبيت من جديد إلى مجموعته. ولحذفها أيضًا أضف `--purge` (`-Purge` على Windows، مع `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge`)، ثم أزل الجهاز من المجموعة من جهاز آخر (`sudo cbb remove NAME`، أو على الهاتف). ولمغادرة المجموعة مع الإبقاء على CBB، شغّل بدلًا من ذلك `sudo cbb leave`: فهو يحذف المفاتيح وملفات المجموعة، ويستطيع الجهاز الانضمام إلى مجموعة من جديد.
