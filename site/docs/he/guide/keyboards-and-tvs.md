<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: c2d39475bc20 -->
# מקלדות וטלוויזיות

למי שרוצה להקליד סיסמה ארוכה, קישור או חיפוש בטלוויזיה, בטאבלט, בקונסולה או במחשב שאין בהם שום דבר של Copy Beyond Borders. מכשיר אחד בקבוצה שלך מקליד שם את הטקסט כמקלדת או כשלט של הטלוויזיה, כשאתה מקיש או כשמנהל שולח הדבקה מרחוק.

## בחר דרך

| דרך | מקליד אל | דורש |
|---|---|---|
| [טלפון Android כמקלדת Bluetooth](#an-android-phone-as-a-bluetooth-keyboard) | כל דבר שמקבל מקלדת Bluetooth: טלוויזיות, טאבלטים, טלפונים, מחשבים, ה-Steam Deck, ה-PlayStation 5 | Android 10 ומעלה עם פרופיל מקלדת Bluetooth |
| [מחשב Linux כמקלדת Bluetooth](#a-linux-computer-as-a-bluetooth-keyboard) | כל דבר שמקבל מקלדת Bluetooth LE | BlueZ 5.50 ומעלה ומתאם עם Bluetooth 4.0 ומעלה |
| [ה-Nano ESP32 כמקלדת USB או Bluetooth](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | ב-USB גם BIOS, בקשת הצפנת דיסק, ה-Xbox וה-Nintendo Switch | Arduino Nano ESP32 בקבוצה שלך |
| [מחשב כשלט של הטלוויזיה](#a-computer-as-the-tvs-remote) | Android TV, Google TV או Roku ברשת הביתית שלך | מחשב Linux, macOS, Windows או FreeBSD בבית |

ה-Xbox וה-Nintendo Switch מקבלים רק מקלדות USB, ולכן עבורם השתמש ב-Nano ESP32. macOS, Windows ו-iPhone לא מאפשרים לאף אפליקציה לפעול כמקלדת Bluetooth.

## הפריסה חייבת להתאים

מקלדת שולחת מקשים, לא תווים: המכשיר שמקלידים בו הופך כל מקש לתו לפי הפריסה שלו עצמו. לכן יש לומר למקלדת איזו פריסה פעילה שם, אנגלית (ארה"ב) או רוסית. טקסט שיש בו תו שאין לו מקש בפריסה הזו לא מוקלד בכלל, ומוצג לך אילו תווים אלה; שום דבר אחר לא מוקלד במקומם. ירידת שורה מקישה Enter וטאב מקיש Tab.

ההקלדה איטית בכוונה, 20 תווים בשנייה כברירת מחדל: יש טלוויזיות שמפספסות מקשים שמגיעים מהר יותר. הנמך את הקצב אם חסרות אותיות.

## טלפון Android כמקלדת Bluetooth

1. באפליקציה, פתח הגדרות, מקלדת Bluetooth, והפעל **Act as a Bluetooth keyboard**. אשר Bluetooth ("מכשירים בקרבת מקום") אם מתבקש. אם האפליקציה אומרת שהטלפון לא יכול לפעול כמקלדת, היצרן שלו השמיט את הפרופיל (למשל ה-Fairphone 6 וכמה טלפונים של Huawei, Honor ו-Xiaomi ישנים); השתמש בדרך אחרת. אם היא אומרת שאפליקציה אחרת עשויה להיות המקלדת של הטלפון, כבה את המקלדת של אותה אפליקציה: רק אפליקציה אחת בכל פעם יכולה להיות כזו.
2. הקש **Make this phone visible**. בתוך שתי דקות, הוסף את הטלפון במכשיר, בהגדרות ה-Bluetooth שלו, כפי שמוסיפים מקלדת.
3. תחת **Type into**, בחר את המכשיר. האפליקציה אומרת "Connected to …".
4. הגדר את **The device's keyboard layout** ואם צריך את **Speed** (‏10, 20 או 40 תווים בשנייה).
5. הקש **Type the clipboard**. הטקסט מופיע במקום שבו יש למכשיר מיקוד, לכן פתח קודם שם שדה טקסט.

כדי שהדבקות מרחוק של מנהל יוקלדו שם ולא בטלפון, הפעל הדבקה מרחוק באפליקציה ואז **Type remote pastes there**. טקסט עם ירידת שורה דורש שהמקש Enter יותר להדבקה מרחוק.

## מחשב Linux כמקלדת Bluetooth

```sh
sudo cbb keyboard on -layout us    # registers the keyboard with BlueZ
sudo cbb keyboard pair             # discoverable for two minutes
# add "CBB <this computer's name>" on the device, in its Bluetooth settings
cbb keyboard                       # shows whether it is connected
echo 'the text' | sudo cbb keyboard type
```

`on` מקבל גם `-rate N`, הקצב, ‏5 עד 60 תווים בשנייה, ו-`-pastes`, ששולח את ההדבקות מרחוק של הקבוצה אל המכשיר במקום אל מסך המחשב הזה: `sudo cbb keyboard on -layout us -rate 10 -pastes`. הפקודה `sudo cbb keyboard off` עוצרת אותו. מקלדות ועכברי ה-Bluetooth של המחשב עצמו ממשיכים לעבוד.

## ה-Nano ESP32 כמקלדת USB או Bluetooth

הלוח הוא חבר קל בקבוצה שלך. בקונסולה שלו:

- `usb keyboard` הופך את יציאת ה-USB שלו למקלדת, כשהקונסולה היא יציאה טורית שנייה לצידה; חבר אותו למכשיר. זה עובד לפני שמערכת כלשהי עולה: ב-BIOS, בהגדרות UEFI או בבקשת הצפנת דיסק.
- `ble on`, ואחר כך `ble pair`, הופך אותו למקלדת Bluetooth LE; הוסף את "CBB Nano ESP32" במכשיר בתוך שתי דקות. הוא זוכר עד ארבעה מכשירים; `ble forget` שוכח אותם.
- `layout ru` או `layout us` ו-`rate N` קובעים את הפריסה ואת הקצב.
- `type TEXT` מקליד במכשיר ה-Bluetooth המחובר, ואם אין כזה, במכשיר ה-USB.

הדבקות מרחוק של הקבוצה אל הלוח מוקלדות באותו אופן. המדריך של הלוח עצמו נמצא ב-[lite/esp32](../../lite/esp32/README.md).

## מחשב כשלט של הטלוויזיה

מחשב בבית יכול להקליד בטלוויזיה דרך הרשת, כמו שהשלט שלה עושה. שום דבר לא מותקן בטלוויזיה, והטלוויזיה אף פעם לא מצטרפת לקבוצה.

Android TV או Google TV מותאמים פעם אחת:

```sh
sudo cbb remote add -name living-room-tv living-room-tv.lan   # the TV shows a six-digit code
sudo cbb remote code 123456              # within two minutes
```

Apple TV מותאם באותה דרך, עם קוד PIN בן ארבע ספרות שהוא מציג. קודם, ב-Apple TV, הגדירו הגדרות, AirPlay ו-HomeKit, אפשר גישה ל"כל מי שנמצא באותה רשת": עם "רק אנשים שמשתפים את הבית הזה" הוא מסרב לכל התאמה.

```sh
sudo cbb remote add -appletv -name lounge 192.168.1.30   # the Apple TV shows a four-digit PIN
sudo cbb remote code 1234                # within two minutes
```

ב-Roku אין התאמה ואין הצפנה: הטקסט עובר ברשת הביתית שלך כ-HTTP גלוי, ולכן הוא מתווסף רק כשאתה אומר זאת במפורש עם `-consent`. ב-Roku, הגדר קודם הגדרות, מערכת, הגדרות מערכת מתקדמות, שליטה על ידי אפליקציות לנייד ל"מופעל" או ל"מתירני".

```sh
sudo cbb remote add -roku -consent 192.168.1.40
```

אחר כך פתח בטלוויזיה שדה חיפוש או שדה טקסט בעזרת השלט שלה, והקלד:

```sh
echo 'the film' | sudo cbb remote type
sudo cbb remote pastes living-room-tv on   # an admin's remote pastes go to that TV
```

`cbb remote` מציג את רשימת הטלוויזיות, `-tv NAME` בוחר אחת כשיש כמה, ו-`sudo cbb remote remove NAME` שוכח אחת. Android TV או Apple TV שאופסו, או ששכחו את המחשב הזה, חייבים להיות מותאמים מחדש.

## בטיחות

- מקלדת Bluetooth מקלידה בכל מקום שבו יש למכשיר מיקוד, כאילו ישבת מול המקלדת שלו. התאם אותה רק למכשירים שאתה מתכוון להקליד בהם, ושכח אותה בשני הצדדים כשאתה מפסיק.
- כשהדבקות מרחוק נשלחות למקלדת או לטלוויזיה, כל מנהל של הקבוצה שלך יכול להקליד שם. הפעל זאת רק היכן שצריך; זה נכבה עם ההדבקה מרחוק.
- אל טלוויזיה מגיעים רק ברשת הביתית: כתובת מחוצה לה נדחית, לא משנה למה השם יתורגם אחר כך.
- הטקסט ב-Roku לא מוצפן ברשת הביתית. אל תשלח סיסמאות ל-Roku.

## מגבלות

- עדיין לא נוסה על טלוויזיות, טאבלטים או מתאמי Bluetooth אמיתיים: הבדיקות רצות מול BlueZ מדומה, Android TV מדומה ו-Roku מדומה.
- האפליקציות בטלפונים עדיין לא יכולות להיות שלט של טלוויזיה; טלוויזיות Samsung ו-LG וה-Apple TV יבואו בהמשך ([מפת הדרכים](../roadmap.md), סעיף 25).
- מקלדת מקלידה לכל היותר 4,096 תווים בכל פעם.

כל הדגלים נמצאים ב[פקודות](../reference/cli.md); היציאות של הטלוויזיות נמצאות ב[מכשירים, יציאות וקבצים](../reference/devices.md#ports); איך זה עובד מבפנים מופיע ב[מפרט האפליקציות](../apps.md#android-the-bluetooth-keyboard).
