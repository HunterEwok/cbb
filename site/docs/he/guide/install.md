<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# התקנה

למי שמתקין, מעדכן, מאמת או מסיר את Connect Beyond Borders במחשב, בנתב או בשרת ביתי. לאפליקציות לטלפון, לטאבלט, לשעון ולטלוויזיה, ראו [האפליקציות](apps.md).

‏Connect Beyond Borders פועל כשירות רקע קטן בכל מחשב. כלי שורת הפקודה שלו הוא `cbb`. כל אחת מהדרכים שלהלן מתקינה את אותו שירות; בחרו את זו שמתאימה למערכת שלכם.

## Linux

נתמך במערכות Linux עם `systemd` בארכיטקטורות x86-64,‏ ARM64,‏ ARMv7 ו-ARMv6 (מחשבים ניידים, מחשבים שולחניים, לוחות Raspberry Pi, שרתים ו-Steam Deck).

1. הריצו את תוכנית ההתקנה במסוף:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. ענו לשאלות על כללי חומת האש (כשנמצאת חומת אש פעילה) ועל עדכונים אוטומטיים יומיים.
3. התנתקו והתחברו מחדש פעם אחת כדי שהחשבון שלכם (שנוסף לקבוצה `cbb`) יוכל להריץ את `cbb` בלי `sudo`.

בשולחנות עבודה של x86-64 ו-ARM64 שבהם מותקנים GTK 4 ו-WebKitGTK 6.0 (‏`libgtk-4-1 libwebkitgtk-6.0-4` ב-Debian וב-Ubuntu; ‏`gtk4 webkitgtk6.0` ב-Fedora), תוכנית ההתקנה מתקינה גם את אפליקציית המגש (`cbb-desktop`), שמופעלת עם ההתחברות לשולחן העבודה ומופיעה בתפריט האפליקציות שלכם. אם הספריות האלה חסרות, תוכנית ההתקנה מציינת אילו חבילות להתקין; הריצו שוב את תוכנית ההתקנה אחרי שתוסיפו אותן כדי להתקין את אפליקציית המגש.

אפשר להעביר ל-`get.sh` אפשרויות נוספות אחרי `sh -s --`:

- **מסוף טקסט (`--console`):** למכונה בלי שולחן עבודה, מוסיף העתקה והדבקה בתוך `tmux` ומתקין את `cbb-console.service` להדבקה מרחוק במסוף הטקסט:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **דילוג על חלונות אישור הדבקה בשולחן העבודה (`--uinput`):** ב-GNOME וב-KDE, הדבקה מרחוק שואלת פעם אחת בתיבת דו-שיח של המערכת לפני לחיצה על מקשים. הוספת `--uinput` מתקינה את `cbb-uinput.service` וטוענת את מודול הליבה `uinput` כך ש-Connect Beyond Borders לוחץ ישירות על מקשי ההדבקה (לעולם לא במסך התחברות או נעילה). אפשרות זו דורשת את `cbb-helper`.
- **מכשירים קטנים בלי העוזר (`--no-helper`):** משמיט את `cbb-helper` (תוכנית העזר שמטפלת במפתחות TPM, בלוחות העתקה של שולחן העבודה, בהזרקת מקשים בהדבקה מרחוק, במקלדות Bluetooth ובשלטים לטלוויזיה) במכשירים קטנים שרק מסנכרנים:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  ראו [מכשירים קטנים](../../member/README.md). ארכיונים לנתבי MIPS משמיטים את `cbb-helper` כברירת מחדל. ברגע שמכשיר הותקן בלי `cbb-helper`, עדכונים עתידיים משאירים אותו כך.

גם Homebrew ב-Linux ‏(x86-64 ו-ARM64) נתמך:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

הריצו שוב את הפקודה השנייה אחרי כל `brew upgrade`.

### בלי sudo (ללא root)

במחשב Linux שבו אין לכם הרשאות מנהל (`sudo`), התקינו את Connect Beyond Borders לחשבון המשתמש שלכם בלי `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

פעולה זו מתקינה את `cbb` ב-`~/.local/bin` ומריצה אותו כשירות משתמש של `systemd` בזמן שאתם מחוברים. אי אפשר להתקין אותו לצד התקנה כלל-מערכתית.

השתמשו בהתקנה ללא root רק כשאי אפשר לבצע התקנה רגילה. מכיוון שכל תוכנית שרצה תחת חשבון המשתמש שלכם יכולה לקרוא את קובצי המפתחות שלו, מכשיר ללא root לעולם לא יכול להיות **המכשיר הראשי**, **מנהל** או **רכזת** ([חברים ללא root](how-it-works.md#rootless-members)). להתקנה ללא root אין גם כללי חומת אש, אין תמיכה ב-TPM ואין את העוזרים `--console` או `--uinput`.

- **המשך פעולה אחרי התנתקות:** אם תוכנית ההתקנה אינה יכולה להפעיל השארת שירותים פעילים (lingering) אוטומטית, בקשו ממנהל מערכת להריץ פעם אחת `sudo loginctl enable-linger YOUR-USER`.
- **בלי העוזר:** העבירו `--no-helper --rootless` כדי להשמיט גם את `cbb-helper` (ראו [בלי sudo במכשירים קטנים](../../member/README.md#without-sudo-rootless)).
- **הסרה:** הריצו `sh ~/.local/share/cbb/uninstall.sh`.

### SteamOS ‏(Steam Deck)

1. עברו אל **Desktop Mode** ופתחו את **Konsole**.
2. אם לא הגדרתם סיסמה למשתמש `deck`, הריצו `passwd` כדי להגדיר אחת.
3. הריצו את פקודת ההתקנה של Linux:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

‏SteamOS מחליפה את מערכת הקבצים הראשית שלה בכל עדכון מערכת, ולכן תוכנית ההתקנה ממקמת את Connect Beyond Borders ב-`/opt/cbb` במקום ב-`/usr/local` ורושמת את קובצי ההגדרות שלו ב-`/etc` בתוך `/etc/atomic-update.conf.d/cbb.conf`. ההתקנה והחברות שלכם בקבוצה נשמרות לאורך עדכוני SteamOS.

- אחרי שתתנתקו ותתחברו מחדש, `cbb` נמצא ב-`PATH` שלכם ב-Konsole. מכיוון ש-`sudo` אינו מחפש ב-`/opt/cbb/bin`, פקודות שדורשות `sudo` חייבות להשתמש בנתיב המלא, כמו `sudo /opt/cbb/bin/cbb pair -code`.
- ב-Desktop Mode, לוח ההעתקה מסתנכרן כמו בכל שולחן עבודה של KDE Plasma.
- ב-Game Mode, אין לוח העתקה של שולחן עבודה, ולכן שום דבר לא מסתנכרן שם; השירות ממשיך לרוץ ומשלים את הפער כשאתם חוזרים ל-Desktop Mode.
- כדי להסיר אותו, הריצו `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

נתמך במחשבי Mac עם שבב Apple או Intel שמריצים macOS 14 ומעלה.

- **חבילת התקנה (מומלץ, כוללת את אפליקציית שורת התפריטים):** הורידו את `cbb-X.Y.Z.pkg` מתוך [הגרסה האחרונה ב-GitHub](https://github.com/HunterEwok/cbb/releases/latest) ופתחו אותו. החבילה מתקינה את אפליקציית שורת התפריטים **CBB** (‏`/Applications/CBB.app`) ואת שירות הרקע, שניהם חתומים ומאושרים בנוטריזציה.
- **מסוף (השירות ו-`cbb` בלבד, בלי אפליקציית שורת התפריטים):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (השירות ו-`cbb` בלבד, בלי אפליקציית שורת התפריטים):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  הריצו שוב את הפקודה השנייה אחרי כל `brew upgrade` כדי להפעיל מחדש את השירות ואת סוכן הלוח על הגרסה המעודכנת.

## Windows

נתמך ב-Windows 10 (גרסה 1809 ומעלה) וב-Windows 11, בארכיטקטורות x86-64 ו-ARM64.

1. פתחו PowerShell עם **הפעל כמנהל**.
2. הריצו את תוכנית ההתקנה:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. ענו לשאלות על כללי Windows Firewall ועל עדכונים אוטומטיים יומיים.
4. פתחו חלון מסוף חדש כדי להשתמש ב-`cbb`.

תוכנית ההתקנה מוסיפה את המשתמש המחובר לקבוצה `cbb`, מפעילה את שירות הרקע ואת סוכן הלוח, ומתקינה את אפליקציית המגש (שנפתחת בהתחברות ומופיעה בתפריט התחל בשם **CBB**). פקודות שמשנות חברות בקבוצה או הגדרות רצות במסוף מנהל, במקום שבו Linux ו-macOS משתמשות ב-`sudo`.

להתקנה עם **winget** (באמצעות החבילה `HunterEwok.cbb`):

```powershell
winget install HunterEwok.cbb
cbb install
```

הריצו `cbb install` במסוף מנהל כדי להתקין את השירות, את סוכן הלוח, את אפליקציית המגש ואת כללי חומת האש מתוך החבילה שנפרסה, והריצו אותו שוב אחרי כל `winget upgrade`.

## OpenWrt

נתמך בנתבים המריצים OpenWrt 25.12 ומעלה (המשתמשים ב-`apk`) עם מקום לתוכנה של 25 MB (לפחות 128 MB של אחסון פלאש או eMMC, ו-256 MB של RAM).

התחברו דרך SSH כ-`root` והריצו:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

תוכנית ההתקנה מגדירה את `cbb` (בלי `cbb-helper`) כשירות `procd` שמאזין באזור `lan` בלבד ולעולם אינו עונה ב-`wan`. המפתחות נמצאים ב-`/etc/cbb/state`, ש-`sysupgrade` שומר; אחרי sysupgrade מבוקר (ASU או `owut`), הריצו שוב את פקודת ההתקנה. כשמריצים אותה במסוף אינטראקטיבי, תוכנית ההתקנה מתחילה צימוד מיד (`--no-pair` מדלג על כך). לאזורים נוספים (כמו רשת IoT), לפרטי חומת האש ולבדיקות, ראו [נתבים ו-FreeBSD](../admin/routers.md#openwrt).

אפשר גם להתקין ממאגר החבילות `apk` של הפרויקט כך ש-`apk upgrade` ישמור אותו מעודכן:

1. בדקו את הארכיטקטורה של הנתב שלכם באמצעות `grep DISTRIB_ARCH /etc/openwrt_release` ומפו אותה לתיקיית המאגר:
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*` (עם `neon` או `vfp` בשם) → `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. הוסיפו את מפתח המאגר ואת המאגר עצמו (החליפו את `arm64` בארכיטקטורה שלכם) והתקינו:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

‏`apk del cbb` מסיר את החבילה ושומר את המפתחות ב-`/etc/cbb`. שימו לב שגרסאות נתבים של `mips` ו-`mipsle` מסנכרנות ברשת הביתית בלבד (בלי סנכרון מחוץ לבית).

## FreeBSD

נתמך ב-FreeBSD 15 ‏(`amd64` ו-`arm64`). הריצו כ-`root` (עם `sudo` או `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

תוכנית ההתקנה מתקינה את `cbb`, מוסיפה סקריפט `rc.d` שמריץ את השירות דרך `daemon(8)`, ומוסיפה את `cbb_enable="YES"` אל `rc.conf`. המפתחות נמצאים ב-`/var/db/cbb` וההגדרות ב-`/usr/local/etc/cbb`.

- **OPNsense:** אותה תוכנית התקנה מוסיפה וו לתוסף כך שהשירות מופיע תחת **System > Diagnostics > Services** וכללי חומת האש שלו (בעוגן `cbb` של `pf`) נשמרים בין טעינות מחדש של המסנן. כבו את **Services > mDNS Repeater** בזמן ש-Connect Beyond Borders פועל, משום ששניהם זקוקים ליציאת UDP 5353 והשירות עונה ל-mDNS בעצמו בכל ממשק ביתי.
- **pfSense (לא נתמך):** תוכנית ההתקנה רצה ב-pfSense, מדפיסה את הכללים שיש להוסיף ידנית תחת **Firewall > Rules**, ועלולה להימחק בעדכון מערכת של pfSense.
- **שולחנות עבודה של FreeBSD:** ב-X11, או במנהלי תצוגה של Wayland עם פרוטוקול data-control (כמו KDE,‏ sway ו-Hyprland), ההפעלה האוטומטית של XDG מפעילה את `cbb agent` כשאתם מתחברים מחדש. הדבקה מרחוק משתמשת ב-XTEST ב-X11 ובמקלדת וירטואלית בשולחנות עבודה של wlroots; ‏GNOME ב-FreeBSD אינו מקבל הדבקה מרחוק משום שמצב נעילת המסך אינו זמין בלי `logind`.

## Docker

עבור NAS או שרת ביתי שדולק תמיד בלי שולחן עבודה (ראו את [ה-README של אימג׳ ה-Docker](../../packaging/docker/README.md)). מכולה מצטרפת כחבר רגיל; צרו את הקבוצה בטלפון שלכם או במחשב שנמצא אצלכם.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

פתחו קודם חלון צימוד בטלפון שלכם או במחשב מנהל, ואז הקלידו את שש הספרות כש-`cbb pair -code` מבקש אותן.

## חומת האש

‏Connect Beyond Borders צריך יציאה נכנסת **TCP 8764** (או יציאת החבר המותאמת שלכם) ואת **UDP 5353** (‏mDNS), מהרשת הביתית שלכם בלבד.

תוכנית ההתקנה מזהה את חומת האש שלכם (`ufw`,‏ `firewalld`,‏ `nftables` או `iptables` ב-Linux; ‏`pf`,‏ `ipfw` או OPNsense ב-FreeBSD; חומת האש של האפליקציות ב-macOS; ‏Windows Firewall), מפרטת כל כלל שהיא צריכה, ושואלת `Add these rules now? [y/N]` (‏`Add this rule now? [y/N]` ב-macOS):

- **כן:** תוכנית ההתקנה מוסיפה את הכללים, שומרת עליהם מעודכנים בשדרוגים, ומסירה אותם בהסרת ההתקנה בלי לשנות אף כלל אחר.
- **לא** (ברירת המחדל, וגם כשאין מסוף אינטראקטיבי מחובר): תוכנית ההתקנה אינה מוסיפה כללים ומדפיסה את הפקודות המדויקות כדי שתריצו אותן בעצמכם.
- **אפשרויות ללא התערבות:**
  - ב-Linux, ב-macOS וב-FreeBSD: העבירו `--express` כדי להוסיף כללים בלי לשאול, או `--no-firewall` כדי לסרב ולהדפיס את הפקודות.
  - ב-Windows: הגדירו `$env:CBB_FIREWALL = "express"` או `$env:CBB_FIREWALL = "no"` לפני הרצת `get.ps1` (או העבירו `-Express` או `-NoFirewall` אל `install.ps1`).

התנהגות ספציפית לפי חומת אש:

- `nftables` ו-`iptables` תמיד מדפיסות פקודות ידניות בלבד, משום שכללי זמן ריצה אינם שורדים הפעלה מחדש.
- `pf` ב-FreeBSD שם את הכללים בעוגן `cbb` משלו, שנטען דרך שלוש שורות מסומנות שמתווספות לסוף `/etc/pf.conf` (ומוסרות בהסרה). `ipfw` ב-FreeBSD מוסיף אותם בערכת הכללים 17 וטוען אותם מחדש בכל הפעלה.
- אם תפעילו חומת אש אחרי שהתקנתם את Connect Beyond Borders, הריצו שוב את תוכנית ההתקנה.

כדי להשתמש ביציאת חבר אחרת כש-TCP 8764 כבר בשימוש:

- ב-Linux, ב-macOS, ב-FreeBSD וב-OpenWrt: העבירו `--port 9000` (לדוגמה, `... | sudo sh -s -- --port 9000`).
- ב-Windows: הגדירו `$env:CBB_PORT = "9000"` לפני הרצת `get.ps1` (או העבירו `-Port 9000` אל `install.ps1`).

כל אפשרויות תוכנית ההתקנה מפורטות ב[מדריך הפקודות](../reference/cli.md#installers).

## עדכון

שמרו את כל המכשירים בקבוצה על אותה גרסה. ראו [גרסאות ותאימות](../reference/compatibility.md) לפרטי התאימות.

### עדכון ידני

- **הותקן עם `get.sh`,‏ `get.ps1` או ארכיון גרסה:**
  - בדיקה אם יש גרסה חדשה יותר: `cbb update -check`
  - התקנת הגרסה החתומה החדשה ביותר: `sudo cbb update` (ב-Windows, הריצו `cbb update` במסוף מנהל; ב-Linux ללא root, הריצו `cbb update` בלי `sudo`; ב-SteamOS, הריצו `sudo /opt/cbb/bin/cbb update`).

  `cbb update` שומר על ההגדרות והמפתחות שלכם, מתקין רק גרסאות שהפרויקט חתם עליהן, מסרב לגרסאות ישנות יותר, ומשחזר אוטומטית את הגרסה הקודמת אם השירות המעודכן לא מצליח לעלות תוך דקה. גם הרצה חוזרת של פקודת `get.sh` או `get.ps1` המקורית מעדכנת.
- **Homebrew:** הריצו `brew upgrade cbb`, ואז הריצו שוב את פקודת `install.sh` מהסעיף [Mac](#mac) או [Linux](#linux).
- **winget:** הריצו `winget upgrade HunterEwok.cbb`, ואז הריצו `cbb install` במסוף מנהל.
- **Docker:** הריצו `docker compose -f compose.home.yaml pull` וצרו מחדש את המכולה.
- **מאגר החבילות של OpenWrt:** הריצו `apk update && apk upgrade`.

### עדכונים אוטומטיים

בהתקנות של `get.sh` ו-`get.ps1`, תוכנית ההתקנה שואלת פעם אחת אם להפעיל עדכונים אוטומטיים יומיים. אפשר לקבוע את התשובה מראש או לשנות אותה מאוחר יותר:

- **בזמן ההתקנה:** העבירו `--auto-update on` או `--auto-update off` אל `get.sh`; ב-Windows, הגדירו `$env:CBB_AUTO_UPDATE = "on"` או `"off"` לפני הרצת `get.ps1` (או העבירו `-AutoUpdate on|off` אל `install.ps1`).
- **אחרי ההתקנה:** הריצו `sudo cbb update -auto on` או `sudo cbb update -auto off` (בלי `sudo` ב-Linux ללא root; במסוף מנהל ב-Windows).

כשעדכונים אוטומטיים מופעלים, מתזמן יומי בודק אם יש גרסאות חתומות: טיימר של `systemd` ב-Linux (טיימר משתמש ללא root), משימת `launchd` ב-macOS, משימה מתוזמנת כ-`SYSTEM` ב-Windows, או `cron` ב-OpenWrt וב-FreeBSD.

כל בדיקה מורידה קובצי מטא-דאטה חתומים קטנים מ-GitHub (ועוברת אל `dl.cbb.tools` אם GitHub לא עונה). GitHub רואה את כתובת ה-IP של המכשיר ושהוא מבקש מטא-דאטה של Connect Beyond Borders, אבל שום דבר על הקבוצה שלכם. כדי להשתמש במראה מותאמת אישית במקום זאת, הריצו `sudo cbb update -mirror https://...`; אין צורך לסמוך על המראה משום שהחתימות עדיין מאומתות.

יומני העדכונים האוטומטיים נכתבים לקובץ `update.log` בתיקייה:

| מערכת | תיקיית יומן העדכונים |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (ללא root) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

מכשירים בקבוצה משתפים הודעות על הגרסה החתומה החדשה ביותר שאחד מהם ראה, כך ש-`cbb status` ואפליקציות שולחן העבודה מודיעים לכם כשזמין עדכון. כל מכשיר עדיין מאמת את החתימות בעצמו ומוריד את הארכיון שלו.

## בדיקת הורדה

כל ארכיון גרסה נבדק בשלוש דרכים:

1. **סכומי ביקורת (`SHA256SUMS`):** גם `get.sh` וגם `get.ps1` מאמתים את הארכיון שהורד מול קובץ ה-`SHA256SUMS` של הגרסה.
2. **חתימות הגרסה של הפרויקט:** הגרסאות חתומות במפתחות השורש הלא מקוונים של הפרויקט ובמפתח הגרסה (שלעולם אינם נוגעים ב-CI): ‏`keys.json` מאשר את מפתחות הגרסה תחת מפתחות השורש של הפרויקט, `release.json` מפרט את הגודל ואת גיבוב ה-SHA-256 של כל קובץ, ו-`stable.json` מציין את הגרסה היציבה הנוכחית ([הפרוטוקול](../protocol.md), סעיף 16). גם `get.sh` (באמצעות `openssl`) וגם `get.ps1` נושאים את מפתחות השורש המובנים של הפרויקט ומסרבים להתקין כל גרסה שחתימותיה אינן מאומתות. `get.sh` בודק גם ES256 וגם SLH-DSA-SHA2-128s כשמותקן OpenSSL 3.5 ומעלה (ES256 ב-OpenSSL ישן יותר); `get.ps1` בודק ES256. כדי להתקין בלי לבדוק את חתימות הפרויקט, הגדירו `CBB_VERIFY=skip`.
3. **אישור מקור בנייה (Build provenance attestation):** לכל קובץ בגרסה יש אישור מקור בנייה של GitHub הקושר אותו לתהליך הוצאת הגרסאות של המאגר הזה. באמצעות [GitHub CLI](https://cli.github.com/) (‏`gh`), אפשר לאמת כל קובץ ידנית:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   גם `get.sh` וגם `get.ps1` מריצים את הבדיקה הזו אוטומטית כש-`gh` מותקן ומחובר (`gh auth login`; עבור `get.sh` תחת `sudo`, הריצו `sudo gh auth login`). הגדירו `CBB_ATTESTATION=require` כדי לסרב להתקנה בלי אישור מאומת, או `CBB_ATTESTATION=skip` כדי לדלג על בדיקת האישור.

## הסרה

הריצו את פקודת ההסרה עבור המערכת שלכם:

| מערכת | פקודה או שלבים |
|---|---|
| Linux ו-macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (ללא root) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (או עם `doas`) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (או `apk del cbb` אם הותקן מהמאגר) |
| Windows | פתחו **הגדרות > אפליקציות > CBB > הסרת התקנה**, או הריצו `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` כמנהל |

אם התקנתם עם Homebrew, הריצו קודם את סקריפט ההסרה ואז הריצו `brew uninstall cbb`.

הסרת ההתקנה מוחקת את התוכנה, את שירות הרקע, את סוכן הלוח, את מתזמן העדכונים, את כללי חומת האש שתוכנית ההתקנה הוסיפה, וב-macOS גם את `/Applications/CBB.app` אם הותקן מה-`.pkg`. המפתחות ומצב הקבוצה של המכשיר שלכם נשארים בדיסק כך שהתקנה מחדש מחזירה אותו לאותה קבוצה.

- **מחיקת המפתחות ומצב הקבוצה גם כן:** הוסיפו `--purge` במערכות Unix, או הריצו `uninstall.ps1 -Purge` ב-PowerShell מנהל ב-Windows. אחר כך הסירו את המכשיר מהקבוצה במכשיר מנהל (`sudo cbb remove NAME` או באפליקציית הטלפון).
- **עזיבת הקבוצה בלי הסרת ההתקנה:** הריצו `sudo cbb leave` (בלי `sudo` ב-Linux ללא root, או `cbb leave` במסוף מנהל ב-Windows). פעולה זו מוחקת את המפתחות ואת קובצי הקבוצה של המכשיר תוך השארת Connect Beyond Borders מותקן, כך שהמכשיר יכול להצטרף שוב לקבוצה.
