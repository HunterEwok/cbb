<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# التثبيت

لمن يثبّت Connect Beyond Borders أو يحدّثه أو يتحقق منه أو يزيله على حاسوب أو موجّه أو خادم منزلي. لتطبيقات الهواتف والأجهزة اللوحية والساعات والتلفاز، انظر [التطبيقات](apps.md).

يعمل Connect Beyond Borders كخدمة صغيرة في الخلفية على كل حاسوب. وأداة سطر الأوامر الخاصة به هي `cbb`. تثبّت كل طريقة أدناه الخدمة نفسها؛ اختر الطريقة التي تناسب نظامك.

## Linux

مدعوم على أنظمة Linux المزوّدة بـ `systemd` على معماريات x86-64 وARM64 وARMv7 وARMv6 (الحواسيب المحمولة والمكتبية ولوحات Raspberry Pi والخوادم وSteam Deck).

1. شغّل المثبّت في الطرفية:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. أجب عن الأسئلة المتعلقة بقواعد جدار الحماية (عند العثور على جدار حماية نشط) والتحديثات التلقائية اليومية.
3. سجّل الخروج ثم سجّل الدخول مرة واحدة حتى يتمكن حسابك (بعد إضافته إلى المجموعة `cbb`) من تشغيل `cbb` من دون `sudo`.

على أسطح المكتب بمعمارية x86-64 وARM64 التي تتوفر عليها GTK 4 وWebKitGTK 6.0 (الحزمتان `libgtk-4-1 libwebkitgtk-6.0-4` على Debian وUbuntu؛ والحزمتان `gtk4 webkitgtk6.0` على Fedora)، يثبّت المثبّت أيضًا تطبيق شريط النظام (`cbb-desktop`)، الذي يبدأ مع جلسة سطح المكتب ويظهر في قائمة التطبيقات. وإذا كانت تلك المكتبات غير متوفرة، يسمّي المثبّت الحزم المطلوب تثبيتها؛ أعد تشغيل المثبّت بعد إضافتها لتثبيت تطبيق شريط النظام.

يمكنك تمرير خيارات إضافية إلى `get.sh` بعد `sh -s --`:

- **الطرفية النصية (`--console`):** لجهاز بلا سطح مكتب، يضيف النسخ واللصق داخل `tmux` ويثبّت `cbb-console.service` للصق عن بُعد في الطرفية النصية:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **تخطي مربعات حوار اللصق على سطح المكتب (`--uinput`):** على GNOME وKDE، يسأل اللصق عن بُعد مرة واحدة في مربع حوار للنظام قبل ضغط المفاتيح. تؤدي إضافة `--uinput` إلى تثبيت `cbb-uinput.service` وتحميل وحدة النواة `uinput` ليضغط Connect Beyond Borders مفاتيح اللصق مباشرةً (ولا يفعل ذلك أبدًا في شاشة تسجيل الدخول أو شاشة القفل). يتطلب هذا الخيار `cbb-helper`.
- **الأجهزة الصغيرة من دون المساعد (`--no-helper`):** يستبعد `cbb-helper` (البرنامج المساعد الذي يتولى مفاتيح TPM وحافظات سطح المكتب وإدخال مفاتيح اللصق عن بُعد ولوحات مفاتيح البلوتوث وأجهزة التحكم بالتلفاز) على الأجهزة الصغيرة التي تقتصر على المزامنة:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  انظر [الأجهزة الصغيرة](../../member/README.md). وتستبعد أرشيفات موجّهات MIPS برنامج `cbb-helper` افتراضيًا. وبمجرد تثبيت جهاز من دون `cbb-helper`، تحافظ التحديثات اللاحقة على ذلك.

كما أن Homebrew على Linux (بمعماريتي x86-64 وARM64) مدعوم أيضًا:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

أعد تشغيل الأمر الثاني بعد كل `brew upgrade`.

### من دون sudo (بلا صلاحيات root)

على حاسوب Linux لا تملك فيه صلاحيات المسؤول (`sudo`)، ثبّت Connect Beyond Borders لحساب المستخدم الخاص بك من دون `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

يثبّت هذا `cbb` في `~/.local/bin` ويشغّله كخدمة مستخدم لـ `systemd` ما دمت مسجّلًا الدخول. ولا يمكن تثبيته بالتوازي مع تثبيت على مستوى النظام.

لا تستخدم التثبيت بلا صلاحيات root إلا عندما يتعذر التثبيت العادي. ونظرًا لأن أي برنامج يعمل تحت حساب المستخدم الخاص بك يمكنه قراءة ملفات مفاتيحه، فلا يمكن لجهاز مثبَّت بلا صلاحيات root أن يكون أبدًا **الجهاز الرئيسي** أو **مشرفًا** أو **محورًا** ([الأعضاء بلا صلاحيات root](how-it-works.md#rootless-members)). كما لا يملك التثبيت بلا صلاحيات root قواعد جدار حماية ولا دعم TPM ولا مساعدَي `--console` أو `--uinput`.

- **الاستمرار في العمل بعد تسجيل الخروج:** إذا لم يتمكن المثبّت من تفعيل الاستمرار (lingering) تلقائيًا، فاطلب من المسؤول تشغيل `sudo loginctl enable-linger YOUR-USER` مرة واحدة.
- **من دون المساعد:** مرّر `--no-helper --rootless` لاستبعاد `cbb-helper` أيضًا (انظر [من دون sudo على الأجهزة الصغيرة](../../member/README.md#without-sudo-rootless)).
- **الإزالة:** شغّل `sh ~/.local/share/cbb/uninstall.sh`.

### SteamOS (Steam Deck)

1. انتقل إلى **وضع سطح المكتب** وافتح **Konsole**.
2. إذا لم تعيّن كلمة مرور للمستخدم `deck` بعد، فشغّل `passwd` لتعيين واحدة.
3. شغّل أمر التثبيت الخاص بـ Linux:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

يستبدل SteamOS نظام ملفاته الجذري مع كل تحديث للنظام، لذا يضع المثبّت Connect Beyond Borders في `/opt/cbb` بدلًا من `/usr/local` ويسجّل ملفات إعداده في `/etc` ضمن `/etc/atomic-update.conf.d/cbb.conf`. ويبقى تثبيتك وعضويتك في المجموعة محفوظَين عبر تحديثات SteamOS.

- بعد تسجيل الخروج ثم تسجيل الدخول مجددًا، يصبح `cbb` ضمن `PATH` في Konsole. ولأن `sudo` لا يبحث في `/opt/cbb/bin`، يجب أن تستخدم الأوامر التي تتطلب `sudo` المسار الكامل، مثل `sudo /opt/cbb/bin/cbb pair -code`.
- في وضع سطح المكتب، تتزامن الحافظة كما على أي سطح مكتب KDE Plasma.
- في وضع الألعاب، لا توجد حافظة لسطح المكتب، لذا لا يتزامن شيء هناك؛ وتستمر الخدمة في العمل وتلحق بالمزامنة عند عودتك إلى وضع سطح المكتب.
- لإزالته، شغّل `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

مدعوم على أجهزة Mac ذات شريحة Apple أو معالج Intel العاملة بنظام macOS 14 أو أحدث.

- **حزمة التثبيت (موصى بها، وتشمل تطبيق شريط القوائم):** نزّل `cbb-X.Y.Z.pkg` من [أحدث إصدار على GitHub](https://github.com/HunterEwok/cbb/releases/latest) وافتحه. تثبّت الحزمة تطبيق شريط القوائم **CBB** (`/Applications/CBB.app`) وخدمة الخلفية، وكلاهما موقَّع وموثَّق.
- **الطرفية (الخدمة و`cbb` فقط، من دون تطبيق شريط القوائم):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (الخدمة و`cbb` فقط، من دون تطبيق شريط القوائم):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  أعد تشغيل الأمر الثاني بعد كل `brew upgrade` لإعادة تشغيل الخدمة ووكيل الحافظة على الإصدار المحدَّث.

## Windows

مدعوم على Windows 10 (الإصدار 1809 أو أحدث) وWindows 11، بمعماريتي x86-64 وARM64.

1. افتح PowerShell بخيار **تشغيل كمسؤول**.
2. شغّل المثبّت:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. أجب عن الأسئلة المتعلقة بقواعد جدار حماية Windows والتحديثات التلقائية اليومية.
4. افتح نافذة طرفية جديدة لاستخدام `cbb`.

يضيف المثبّت المستخدم المسجَّل دخوله إلى المجموعة `cbb`، ويشغّل خدمة الخلفية ووكيل الحافظة، ويثبّت تطبيق شريط النظام (يبدأ عند تسجيل الدخول ويظهر في قائمة ابدأ باسم **CBB**). وتُشغَّل الأوامر التي تغيّر عضوية المجموعة أو إعداداتها في طرفية مسؤول، حيث يستخدم Linux وmacOS الأمر `sudo`.

للتثبيت باستخدام **winget** (باستخدام الحزمة `HunterEwok.cbb`):

```powershell
winget install HunterEwok.cbb
cbb install
```

شغّل `cbb install` في طرفية مسؤول لتثبيت الخدمة ووكيل الحافظة وتطبيق شريط النظام وقواعد جدار الحماية من الحزمة المفكوكة، وأعد تشغيله بعد كل `winget upgrade`.

## OpenWrt

مدعوم على الموجّهات التي تعمل بنظام OpenWrt 25.12 أو أحدث (باستخدام `apk`) وفيها مساحة لبرنامج بحجم 25 ميغابايت (128 ميغابايت على الأقل من الفلاش أو eMMC، و256 ميغابايت من ذاكرة RAM).

اتصل عبر SSH بصلاحية `root` وشغّل:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

يُعدّ المثبّت `cbb` (من دون `cbb-helper`) كخدمة `procd` تستمع على منطقة `lan` فقط ولا ترد أبدًا على `wan`. وتبقى المفاتيح في `/etc/cbb/state` الذي يحتفظ به `sysupgrade`؛ وبعد إجراء ترقية نظام بإشراف (ASU أو `owut`)، شغّل أمر التثبيت مرة أخرى. وعند تشغيله في طرفية تفاعلية، يبدأ المثبّت الاقتران فورًا (`--no-pair` يتخطى ذلك). للمناطق الإضافية (مثل شبكة إنترنت الأشياء) وتفاصيل جدار الحماية والفحوص، انظر [الموجّهات وFreeBSD](../admin/routers.md#openwrt).

يمكنك أيضًا التثبيت من موجز حزم `apk` الخاص بالمشروع لكي يبقيه `apk upgrade` محدَّثًا:

1. تحقق من معمارية موجّهك باستخدام `grep DISTRIB_ARCH /etc/openwrt_release` وطابقها بدليل الموجز:
   - `aarch64_*` ← `arm64`
   - `arm_cortex-a*` (التي تحتوي في اسمها على `neon` أو `vfp`) ← `armv7`
   - `mipsel_*` ← `mipsle`
   - `mips_*` ← `mips`
   - `x86_64` ← `amd64`
2. أضف مفتاح الموجز والمستودع (استبدل `arm64` بمعماريتك) ثم ثبّت:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

يزيل `apk del cbb` الحزمة ويُبقي المفاتيح في `/etc/cbb`. لاحظ أن إصدارات الموجّهات لمعماريتي `mips` و`mipsle` تزامن على الشبكة المنزلية فقط (بلا مزامنة خارج المنزل).

## FreeBSD

مدعوم على FreeBSD 15 (`amd64` و`arm64`). شغّله بصلاحية `root` (مع `sudo` أو `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

يثبّت المثبّت `cbb`، ويضيف سكربت `rc.d` يشغّل الخدمة عبر `daemon(8)`، ويضيف `cbb_enable="YES"` إلى `rc.conf`. وتُحفظ المفاتيح في `/var/db/cbb` والإعدادات في `/usr/local/etc/cbb`.

- **OPNsense:** يضيف المثبّت نفسه خطّاف إضافة لتظهر الخدمة ضمن **System > Diagnostics > Services** وتستمر قواعد جدار حمايتها (في مرساة `pf` المسماة `cbb`) عبر عمليات إعادة تحميل المرشّح. أوقف **Services > mDNS Repeater** ما دام Connect Beyond Borders يعمل، لأن كليهما يحتاج إلى منفذ UDP 5353 وتجيب الخدمة عن mDNS على كل واجهة منزلية بنفسها.
- **pfSense (غير مدعوم):** يعمل المثبّت على pfSense، ويطبع القواعد لإضافتها يدويًا ضمن **Firewall > Rules**، وقد يزيله تحديث نظام pfSense.
- **أسطح مكتب FreeBSD:** على X11، أو على مديري نوافذ Wayland الذين يدعمون بروتوكول data-control (مثل KDE وsway وHyprland)، يشغّل البدء التلقائي في XDG الأمر `cbb agent` عند تسجيل دخولك مجددًا. ويستخدم اللصق عن بُعد XTEST على X11 ولوحة المفاتيح الافتراضية على أسطح مكتب wlroots؛ ولا يقبل GNOME على FreeBSD اللصق عن بُعد لأن حالة قفل الشاشة غير متوفرة من دون `logind`.

## Docker

لجهاز NAS أو خادم منزلي يعمل دائمًا بلا سطح مكتب (انظر [ملف README لصورة Docker](../../packaging/docker/README.md)). تنضم الحاوية بصفتها عضوًا عاديًا؛ أنشئ المجموعة على هاتفك أو على حاسوب معك.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

افتح نافذة اقتران على هاتفك أو على حاسوب مشرف أولًا، ثم اكتب الأرقام الستة عندما يطلبها `cbb pair -code`.

## جدار الحماية

يحتاج Connect Beyond Borders إلى **منفذ TCP 8764** الوارد (أو منفذ العضو المخصّص لديك) و**منفذ UDP 5353** (mDNS)، من شبكتك المنزلية فقط.

يكتشف المثبّت جدار الحماية لديك (`ufw` أو `firewalld` أو `nftables` أو `iptables` على Linux؛ و`pf` أو `ipfw` أو OPNsense على FreeBSD؛ وجدار حماية التطبيقات في macOS؛ وجدار حماية Windows)، ويعرض كل قاعدة يحتاجها، ويسأل `Add these rules now? [y/N]` (`Add this rule now? [y/N]` على macOS):

- **نعم:** يضيف المثبّت القواعد، ويبقيها محدَّثة عند الترقيات، ويزيلها عند إلغاء التثبيت من دون تغيير أي قواعد أخرى.
- **لا** (الخيار الافتراضي، وعندما لا تكون هناك طرفية تفاعلية متصلة): لا يضيف المثبّت أي قواعد ويطبع الأوامر الدقيقة لتشغّلها بنفسك.
- **خيارات التشغيل غير التفاعلي:**
  - على Linux وmacOS وFreeBSD: مرّر `--express` لإضافة القواعد من دون سؤال، أو `--no-firewall` للرفض وطباعة الأوامر.
  - على Windows: عيّن `$env:CBB_FIREWALL = "express"` أو `$env:CBB_FIREWALL = "no"` قبل تشغيل `get.ps1` (أو مرّر `-Express` أو `-NoFirewall` إلى `install.ps1`).

السلوك الخاص بكل جدار حماية:

- يطبع `nftables` و`iptables` دائمًا الأوامر اليدوية فقط، لأن القواعد المضافة أثناء التشغيل لا تستمر بعد إعادة التشغيل.
- يضع `pf` على FreeBSD القواعد في مرساة `cbb` الخاصة به، وتُحمَّل عبر ثلاثة أسطر معلَّمة تُضاف إلى نهاية `/etc/pf.conf` (وتُزال عند إلغاء التثبيت). ويضيف `ipfw` على FreeBSD القواعد في مجموعة القواعد 17 ويعيد تحميلها عند كل بدء تشغيل.
- إذا فعّلت جدار حماية بعد تثبيت Connect Beyond Borders، فأعد تشغيل المثبّت.

لاستخدام منفذ عضو مختلف عندما يكون TCP 8764 قيد الاستخدام بالفعل:

- على Linux وmacOS وFreeBSD وOpenWrt: مرّر `--port 9000` (مثلًا، `... | sudo sh -s -- --port 9000`).
- على Windows: عيّن `$env:CBB_PORT = "9000"` قبل تشغيل `get.ps1` (أو مرّر `-Port 9000` إلى `install.ps1`).

جميع خيارات المثبّت مدرجة في [مرجع الأوامر](../reference/cli.md#installers).

## التحديث

أبقِ كل جهاز في المجموعة على الإصدار نفسه. انظر [الإصدارات والتوافق](../reference/compatibility.md) لتفاصيل التوافق.

### التحديثات اليدوية

- **التثبيت باستخدام `get.sh` أو `get.ps1` أو أرشيف إصدار:**
  - للتحقق من وجود إصدار أحدث: `cbb update -check`
  - لتثبيت أحدث إصدار موقَّع: `sudo cbb update` (على Windows، شغّل `cbb update` في طرفية مسؤول؛ وعلى Linux بلا صلاحيات root، شغّل `cbb update` من دون `sudo`؛ وعلى SteamOS، شغّل `sudo /opt/cbb/bin/cbb update`).

  يحافظ `cbb update` على إعداداتك ومفاتيحك، ولا يثبّت إلا الإصدارات الموقَّعة من المشروع، ويرفض الإصدارات الأقدم، ويعيد الإصدار السابق تلقائيًا إذا فشل تشغيل الخدمة المحدَّثة خلال دقيقة واحدة. كما أن إعادة تشغيل أمر `get.sh` أو `get.ps1` الأصلي تقوم بالتحديث أيضًا.
- **Homebrew:** شغّل `brew upgrade cbb`، ثم أعد تشغيل أمر `install.sh` من قسم [Mac](#mac) أو [Linux](#linux).
- **winget:** شغّل `winget upgrade HunterEwok.cbb`، ثم شغّل `cbb install` في طرفية مسؤول.
- **Docker:** شغّل `docker compose -f compose.home.yaml pull` وأعد إنشاء الحاوية.
- **موجز حزم OpenWrt:** شغّل `apk update && apk upgrade`.

### التحديثات التلقائية

في التثبيتات التي تستخدم `get.sh` و`get.ps1`، يسأل المثبّت مرة واحدة هل تريد تشغيل التحديثات التلقائية اليومية. يمكنك تعيين الإجابة مسبقًا أو تغييرها لاحقًا:

- **أثناء التثبيت:** مرّر `--auto-update on` أو `--auto-update off` إلى `get.sh`؛ وعلى Windows، عيّن `$env:CBB_AUTO_UPDATE = "on"` أو `"off"` قبل تشغيل `get.ps1` (أو مرّر `-AutoUpdate on|off` إلى `install.ps1`).
- **بعد التثبيت:** شغّل `sudo cbb update -auto on` أو `sudo cbb update -auto off` (من دون `sudo` على Linux بلا صلاحيات root؛ وفي طرفية مسؤول على Windows).

عندما تكون التحديثات التلقائية مفعّلة، يتحقق جدول يومي من وجود إصدارات موقَّعة: مؤقّت `systemd` على Linux (مؤقّت مستخدم في الوضع بلا صلاحيات root)، أو مهمة `launchd` على macOS، أو مهمة مجدولة بصلاحية `SYSTEM` على Windows، أو `cron` على OpenWrt وFreeBSD.

ينزّل كل فحص ملفات بيانات وصفية صغيرة موقَّعة من GitHub (مع الرجوع إلى `dl.cbb.tools` إذا لم يستجب GitHub). يرى GitHub عنوان IP الخاص بالجهاز وأنه يطلب البيانات الوصفية لـ Connect Beyond Borders، لكن لا يرى شيئًا عن مجموعتك. ولاستخدام مرآة مخصّصة بدلًا من ذلك، شغّل `sudo cbb update -mirror https://...`؛ ولا تحتاج المرآة إلى أن تكون موثوقة لأن التواقيع تظل تُفحص.

تُكتب سجلات التحديث التلقائي في `update.log` داخل:

| النظام | دليل سجل التحديث |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (بلا صلاحيات root) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

تتشارك أجهزة المجموعة إشعارات بأحدث إصدار موقَّع رآه أي منها، بحيث ينبّهك `cbb status` وتطبيقات سطح المكتب عند توفر تحديث. ويظل كل جهاز يتحقق من التواقيع بنفسه وينزّل أرشيفه الخاص.

## التحقق من التنزيل

يُفحص كل أرشيف إصدار بثلاث طرق:

1. **مجاميع التحقق (`SHA256SUMS`):** يتحقق كل من `get.sh` و`get.ps1` من الأرشيف المُنزَّل مقابل ملف `SHA256SUMS` الخاص بالإصدار.
2. **تواقيع إصدار المشروع:** تُوقَّع الإصدارات بمفاتيح الجذر غير المتصلة بالإنترنت ومفتاح الإصدار الخاص بالمشروع (والتي لا تمس CI أبدًا): يشهد `keys.json` لمفاتيح الإصدار تحت مفاتيح جذر المشروع، ويسرد `release.json` حجم كل ملف وتجزئة SHA-256 الخاصة به، ويسمّي `stable.json` الإصدار المستقر الحالي ([البروتوكول](../protocol.md)، القسم 16). يحمل كل من `get.sh` (باستخدام `openssl`) و`get.ps1` مفاتيح الجذر المدمجة للمشروع ويرفضان تثبيت أي إصدار لا تثبت صحة تواقيعه. يفحص `get.sh` كلًا من ES256 وSLH-DSA-SHA2-128s عندما يكون OpenSSL 3.5 أو أحدث مثبّتًا (وES256 على إصدارات OpenSSL الأقدم)؛ ويفحص `get.ps1` توقيع ES256. للتثبيت من دون فحص تواقيع المشروع، عيّن `CBB_VERIFY=skip`.
3. **شهادة منشأ البناء:** يملك كل ملف إصدار شهادة منشأ بناء من GitHub تربطه بسير عمل الإصدار في هذا المستودع. وباستخدام [GitHub CLI](https://cli.github.com/) (`gh`)، يمكنك التحقق من أي ملف يدويًا:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   يشغّل كل من `get.sh` و`get.ps1` هذا الفحص تلقائيًا عندما يكون `gh` مثبّتًا ومسجَّلًا الدخول (`gh auth login`؛ وبالنسبة إلى `get.sh` تحت `sudo`، شغّل `sudo gh auth login`). عيّن `CBB_ATTESTATION=require` لرفض التثبيت من دون شهادة منشأ موثَّقة، أو `CBB_ATTESTATION=skip` لتخطي فحص الشهادة.

## إزالته

شغّل أمر إلغاء التثبيت الخاص بنظامك:

| النظام | الأمر أو الخطوات |
|---|---|
| Linux وmacOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (بلا صلاحيات root) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (أو باستخدام `doas`) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (أو `apk del cbb` إذا ثُبّت من الموجز) |
| Windows | افتح **الإعدادات > التطبيقات > CBB > إلغاء التثبيت**، أو شغّل `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` كمسؤول |

إذا ثبّتَّه باستخدام Homebrew، فشغّل سكربت إلغاء التثبيت أولًا ثم شغّل `brew uninstall cbb`.

يزيل إلغاء التثبيت البرنامج، وخدمة الخلفية، ووكيل الحافظة، ومؤقّت التحديث، وقواعد جدار الحماية التي أضافها المثبّت، و(على macOS) `/Applications/CBB.app` إذا ثُبّت من `.pkg`. وتبقى مفاتيح جهازك وحالة المجموعة على القرص بحيث يعيد التثبيت الانضمام إلى المجموعة نفسها.

- **حذف المفاتيح وحالة المجموعة أيضًا:** أضف `--purge` على أنظمة Unix، أو شغّل `uninstall.ps1 -Purge` في PowerShell كمسؤول على Windows. بعد ذلك، أزل الجهاز من المجموعة من على جهاز مشرف (`sudo cbb remove NAME` أو في تطبيق الهاتف).
- **مغادرة المجموعة من دون إلغاء التثبيت:** شغّل `sudo cbb leave` (من دون `sudo` على Linux بلا صلاحيات root، أو `cbb leave` في طرفية مسؤول على Windows). يحذف هذا مفاتيح الجهاز وملفات المجموعة مع إبقاء Connect Beyond Borders مثبّتًا حتى يتمكن الجهاز من الانضمام إلى مجموعة مجددًا.
