<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# התקנה

Copy Beyond Borders רץ כשירות קטן ברקע בכל מחשב. הפקודה שלו היא `cbb`. כל אחת מהדרכים שלהלן מתקינה את אותה תוכנה; בחרו את זו שנוחה לכם.

## Linux

כל Linux עם systemd (‏x86-64, ARM64, ARMv7, ARMv6): מחשב נייד, מחשב שולחני, Raspberry Pi, שרת, Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

לאחר מכן התנתקו והתחברו מחדש פעם אחת, כדי שהמשתמש שלכם יוכל להשתמש ב-`cbb` בלי `sudo`. מכונה בלי שולחן עבודה מקבלת העתקה והדבקה בתוך tmux באמצעות `--console` (‏`... | sudo sh -s -- --console`).

בשולחן עבודה עם GTK 4 ו-WebKitGTK 6.0 (x86-64 ו-ARM64) הוא מתקין גם את אפליקציית המגש, שנפתחת עם ההפעלה שלכם ונמצאת בתפריט היישומים. בלעדיהם הוא מציין אילו חבילות להוסיף; לאחר מכן הריצו אותו שוב כדי לקבל את אפליקציית המגש.

הדבקה מרחוק ב-GNOME וב-KDE שואלת פעם אחת, בחלון במחשב, לפני שההדבקה הראשונה של מנהל רשאית ללחוץ על המקשים. כדי לדלג על החלון, הוסיפו `--uinput` (‏`... | sudo sh -s -- --uinput`): אז עוזר קטן לוחץ על מקשי ההדבקה (Shift+Insert ו-Enter) עבור מי שמשתמש במסך, ואף פעם לא במסך כניסה או נעילה.

מכשירים קטנים שצריכים רק לסנכרן, כמו נתב או Raspberry Pi Zero, יכולים להשתמש במקום זאת ב[חבר הקל](../../member/README.md) הקל יותר: ‏`... | sudo sh -s -- --lite`.

### בלי sudo (ללא root)

במחשב Linux שבו אי אפשר או לא רוצים להשתמש ב-`sudo`, התקינו אותו עבור המשתמש שלכם בלבד, בלי `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

הוא רץ כשירות הרקע שלכם בזמן שאתם מחוברים, ומסתנכרן כמו כל חבר. השתמשו בו רק כשההתקנה הרגילה אינה אפשרית: כל תוכנית שאתם מריצים יכולה להעתיק את המפתחות שלו, ולכן הוא לעולם אינו יכול להיות שורש הקבוצה, מנהל או הרכזת ([איך זה עובד](how-it-works.md#rootless-members)), ואין לו כללי חומת אש, אין לו TPM ואין לו `--console` או `--uinput`. כדי שימשיך לרוץ גם אחרי שתתנתקו, מנהל המערכת מריץ פעם אחת `sudo loginctl enable-linger YOUR-USER`. להסרה: ‏`sh ~/.local/share/cbb/uninstall.sh`. גם החבר הקל מותקן כך, עם `--lite --rootless` ([חבר קל](../../member/README.md#without-sudo-rootless)).

### SteamOS ‏(Steam Deck)

עברו למצב שולחן עבודה, פתחו את Konsole, תנו למשתמש `deck` סיסמה פעם אחת אם אין לו (`passwd`), והריצו את אותה פקודה. SteamOS מחליפה את קבצי המערכת שלה בכל עדכון, ולכן תוכנית ההתקנה מציבה את Copy Beyond Borders ב-`/opt/cbb` במקום ב-`/usr/local`, ואומרת ל-SteamOS אילו מהקבצים שלה ב-`/etc` לשמור (`/etc/atomic-update.conf.d/cbb.conf`). הוא נשאר מותקן ובקבוצה שלו לאורך עדכוני SteamOS.

- `cbb` נמצא בנתיב של Konsole חדש אחרי שמתנתקים ומתחברים מחדש. `sudo` לא מחפש שם, ולכן פקודות שזקוקות לו מקבלות את הנתיב המלא: ‏`sudo /opt/cbb/bin/cbb pair`.
- במצב שולחן עבודה לוח ההעתקה מסתנכרן כמו בכל שולחן עבודה של KDE Plasma.
- במצב משחק אין לוח העתקה של שולחן עבודה, ולכן שם שום דבר לא מסתנכרן; השירות ממשיך לרוץ ומדביק את הפער במצב שולחן עבודה.
- להסרה: ‏`sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Apple silicon או Intel, macOS 14 ומעלה: הורידו את `cbb-X.Y.Z.pkg` מ
[הגרסה האחרונה](https://github.com/HunterEwok/cbb/releases/latest) ופתחו אותו. הוא מתקין את אפליקציית CBB
בשורת התפריטים ואת השירות, שניהם חתומים על ידי הפרויקט ונבדקו על ידי Apple.

או ב-Terminal, בלי האפליקציה, אותה פקודה כמו ב-Linux:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

או באמצעות Homebrew, שגם מעדכן אותו. הריצו שוב את השורה השנייה אחרי כל `brew upgrade`:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

‏Windows 10 (גרסה 1809 ומעלה) או 11, ‏x86-64 או ARM64, ב-PowerShell שנפתח באמצעות "Run as administrator":

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

הוא מאפשר למשתמש שמחובר במסך להשתמש ב-`cbb` (בטרמינל חדש) ומפעיל עבורו את סוכן לוח ההעתקה. פקודות ששינו את הקבוצה רצות בטרמינל שנפתח כמנהל, במקום שבו Linux ו-macOS משתמשים ב-`sudo`.

הוא מתקין גם את אפליקציית המגש, שנפתחת בכניסה למערכת ונמצאת בתפריט התחל בשם CBB.

עם winget, אחרי שהחבילה תהיה במאגר של winget:

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

נתב עם OpenWrt 25.12 ומעלה ומקום לתוכנה של 25 MB (‏128 MB של פלאש או יותר, או eMMC; ‏256 MB של זיכרון), כ-root דרך SSH:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

הוא מתקין את `cbb` כשירות שפועל רק באזור `lan` ולעולם לא עונה ב-`wan`. המפתחות נמצאים ב-`/etc/cbb`, ש-sysupgrade שומר; אחרי sysupgrade מבוקר (ASU, ‏owut) הריצו את הפקודה שוב. אזור אחר, כמו רשת IoT, חומת האש והבדיקות מפורטים ב[נתבים ו-FreeBSD](../admin/routers.md#openwrt).

או ממאגר החבילות שלנו, ש-`apk upgrade` שומר אז מעודכן. הארכיטקטורה של המאגר נקבעת לפי המעבד של הנתב (‏`grep DISTRIB_ARCH /etc/openwrt_release`): ‏`arm64` עבור `aarch64_*`, ‏`armv7` עבור `arm_cortex-a*` שיש בשמו `neon` או `vfp`, ‏`mipsle` עבור `mipsel_*`, ‏`mips` עבור `mips_*`, ‏`amd64` עבור `x86_64`. הציבו את שלכם במקום `arm64` בשורה השנייה:

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

‏`apk del cbb` מסיר אותו ומשאיר את המפתחות ב-`/etc/cbb`.

## FreeBSD

‏FreeBSD 15, ‏amd64 או arm64, כ-root (עם `sudo` או `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

הוא מתקין את `cbb`, סקריפט rc.d שמריץ את השירות דרך daemon(8), ומוסיף את השורה `cbb_enable="YES"` ל-rc.conf. המפתחות נמצאים ב-`/var/db/cbb`.

ב-OPNsense תוכנית ההתקנה הזאת מוסיפה גם וו לתוסף: השירות מופיע תחת System > Diagnostics > Services, וכללי חומת האש שלו (בעוגן `cbb` של pf) עוקבים אחרי כל טעינה מחדש של המסנן. כבו את מהדר ה-mDNS (‏Services > mDNS Repeater) בזמן שהשירות רץ: שניהם זקוקים ליציאת UDP 5353, והשירות עונה ל-mDNS בעצמו בכל ממשק ביתי. pfSense אינו נתמך: תוכנית ההתקנה רצה גם שם, אבל היא מדפיסה את כללי חומת האש עבור Firewall > Rules במקום להוסיף אותם, ועדכון של pfSense עלול להסיר את Copy Beyond Borders.

בשולחן עבודה של FreeBSD (‏X11, או Wayland עם פרוטוקול data control, כמו ב-KDE, ב-sway וב-Hyprland) ההפעלה מתחילה את `cbb agent` מהפעלה האוטומטית של XDG ולוח ההעתקה מצטרף לקבוצה; התחברו מחדש אחרי ההתקנה. הדבקה מרחוק מקלידה דרך XTEST ב-X11 ודרך המקלדת הווירטואלית בשולחנות עבודה של wlroots; ‏GNOME אינו מקבל הדבקה מרחוק ב-FreeBSD, כי בלי logind שום דבר לא אומר אם המסך שלו נעול.

## Docker

עבור NAS או שרת ביתי שתמיד דלוק ([ה-README של התמונה](../../packaging/docker/README.md); מתפרסם עם כל גרסה מ-0.5). הוא מצטרף כחבר רגיל: צרו את הקבוצה בטלפון או במחשב שאתם מחזיקים.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## חומת האש

Copy Beyond Borders צריך יציאת TCP אחת, ‏8764, ואת mDNS (‏UDP 5353), שתיהן מהרשת הביתית בלבד. תוכנית ההתקנה מזהה את חומת האש (‏ufw, ‏firewalld, ‏nftables או iptables ב-Linux, ‏pf או ipfw ב-FreeBSD, חומת האש של האפליקציות ב-Mac, ‏Windows Firewall), מפרטת כל כלל, ושואלת `Add these rules now? [y/N]`:

- **כן**: היא מוסיפה אותם, שומרת עליהם עדכניים בכל עדכון ומסירה אותם כשמסירים את ההתקנה. היא לעולם לא נוגעת בכללים אחרים.
- **לא** (ברירת המחדל, וגם כשאין טרמינל לשאול בו): היא לא מוסיפה דבר ומדפיסה את הפקודות המדויקות, כדי שתריצו אותן בעצמכם.
- ‏`--express` (‏`-Express` ב-Windows) מוסיף אותם בלי לשאול; ‏`--no-firewall` עונה לא.

ב-nftables וב-iptables מקבלים תמיד רק את הפקודות, כי כללים שנוספו בזמן ריצה לא שורדים הפעלה מחדש. ב-FreeBSD, pf מקבל את הכללים בעוגן משלו, ש-pf קורא באמצעות שלוש שורות מסומנות שתוכנית ההתקנה מוסיפה בסוף `/etc/pf.conf` ומסירה שוב; ipfw מקבל אותם בקבוצת הכללים 17, שנוספת מחדש בכל הפעלה. אם תפעילו חומת אש מאוחר יותר, הריצו שוב את תוכנית ההתקנה.

**יציאה אחרת**, אם 8764 תפוסה: ‏`... | sudo sh -s -- --port 9000` (ב-Windows, ‏`$env:CBB_PORT = "9000"` לפני תוכנית ההתקנה). אפליקציית הטלפון לומדת את היציאה מקוד ה-QR.

כל אפשרויות תוכנית ההתקנה נמצאות ב[מדריך הפקודות](../reference/cli.md#installers).

## עדכון

הגרסאות חתומות מ-0.6 ואילך. כדי לעבור ל-0.6 מגרסה קודמת, הריצו שוב את פקודת ההתקנה; מכאן ואילך `cbb update` עושה זאת.

‏`sudo cbb update` (ב-Windows ‏`cbb update` בטרמינל שנפתח כמנהל) מתקין את הגרסה החדשה ביותר במחשב או בחבר קל שהותקנו באמצעות `get.sh`, ‏`get.ps1` או ארכיון גרסה; ‏`cbb update -check` רק אומר אם יש אחת. ההגדרות שלכם נשמרות. הוא מתקין רק גרסה שהפרויקט חתם עליה, ולעולם לא גרסה ישנה יותר. אם הגרסה החדשה לא עולה תוך דקה, הקודמת חוזרת מעצמה. איך הוא בודק את החתימות מתואר ב[פרוטוקול](../protocol.md), סעיף 16.

תוכניות ההתקנה שואלות פעם אחת אם להתעדכן אוטומטית (‏`--auto-update on|off`, או `-AutoUpdate on|off` ו-`$env:CBB_AUTO_UPDATE` ב-Windows, כדי לענות מראש); ‏`sudo cbb update -auto on|off` משנה זאת מאוחר יותר. כשהאפשרות פועלת, טיימר בודק פעם ביום בשעה משלו: טיימר של systemd ב-Linux, משימת launchd ב-Mac, משימה מתוזמנת כ-SYSTEM ב-Windows, ו-cron ב-OpenWrt וב-FreeBSD. כל בדיקה מורידה את אותם קבצים קטנים מ-GitHub (או מ-`dl.cbb.tools` כש-GitHub לא עונה), ולכן GitHub לומד את כתובת המכשיר הזה ושהוא משתמש ב-Copy Beyond Borders, כמו בכל הורדה; הוא לא שולח דבר על הקבוצה. ‏`sudo cbb update -mirror https://...` לוקח עדכונים ממראה אחרת במקום זאת, מה שאינו דורש אמון, כי החתימות נבדקות. יומן הטיימר הוא `update.log` ב-`/var/lib/cbb-update` (Linux), ב-`/etc/cbb-update` (OpenWrt), ב-`/var/db/cbb-update` (FreeBSD), ב-`/Library/Application Support/cbb-update` (Mac) או ב-`C:\Program Files\cbb-update` (Windows).

מכשירי הקבוצה מספרים זה לזה על הגרסה החתומה החדשה ביותר שמישהו מהם ראה, ולכן בדיקה של מכשיר אחד מספיקה כדי ש-`cbb status` ואפליקציית המגש במכשירים האחרים יגידו שיצאה גרסה חדשה יותר (‏"Update to X" באפליקציית המגש מריץ את `cbb update` כמנהל). כל מכשיר עדיין בודק את החתימות בעצמו ומוריד את הארכיון שלו.

הרצה חוזרת של אותה פקודת התקנה גם מעדכנת. עם Homebrew או winget, שדרגו שם והריצו שוב את השורה השנייה; ‏`cbb update` אומר זאת. ‏Docker וחבילת OpenWrt מתעדכנים באמצעות `docker compose pull` ו-`apk upgrade`.

## בדיקת הורדה

תוכניות ההתקנה בשורה אחת בודקות את ההורדה מול `SHA256SUMS` של הגרסה. לכל קובץ בגרסה יש גם אישור מקור בנייה שקושר אותו למאגר הזה ולבנייה שיצרה אותו; באמצעות [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

‏`get.sh` בודק זאת בעצמו כש-`gh` מותקן ומחובר עבור root (‏`sudo gh auth login`); ‏`CBB_ATTESTATION=require` מסרב להתקין בלעדיו.

הגרסאות חתומות גם במפתחות של הפרויקט עצמו, שלעולם לא נוגעים ב-CI (מפתחות השורש נמצאים במפתחות חומרה לא מקוונים, מפתח הגרסה ב-Secure Enclave של המתחזק): ‏`keys.json` מציין את מפתחות הגרסה תחת מפתחות השורש של הפרויקט, ‏`release.json` מפרט כל קובץ בגרסה עם הגיבוב שלו, ו-`stable.json` אומר איזו גרסה היא הנוכחית. אחרי שמפתחות השורש ייבנו לתוך תוכניות ההתקנה, ‏`get.sh` (עם `openssl`) ו-`get.ps1` יבדקו אותם לפני ההתקנה וידחו גרסה שאינה חתומה; עד אז הם בודקים רק את `SHA256SUMS` ואת אישור המקור. ‏`CBB_VERIFY=skip` מתקין בלי הבדיקה.

## הסרה

ב-Linux וב-Mac:

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

ב-SteamOS זה `sudo sh /opt/cbb/share/uninstall.sh`. עם Homebrew, הריצו אחריו `brew uninstall cbb`.

ב-Windows: הגדרות, אפליקציות, "CBB", הסרת התקנה.

פעולה זו מסירה את התוכנה, את השירות, את כללי חומת האש שתוכנית ההתקנה הוסיפה, וב-Mac גם את האפליקציה שה-`.pkg` התקין. מפתחות המכשיר נשארים, ולכן התקנה מחדש מחזירה אותו לקבוצה שלו. כדי למחוק גם אותם, הוסיפו `--purge` (‏`-Purge` ב-Windows, עם `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge`), ואז הסירו את המכשיר מהקבוצה ממכשיר אחר (‏`sudo cbb remove NAME`, או בטלפון). כדי לצאת מהקבוצה ולהשאיר את CBB, הריצו במקום זאת ‏`sudo cbb leave`: הוא מוחק את המפתחות ואת קובצי הקבוצה, והמכשיר יכול להצטרף שוב לקבוצה.
