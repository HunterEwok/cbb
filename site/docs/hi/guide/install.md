<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# इंस्टॉल करना

उन लोगों के लिए जो किसी कंप्यूटर, राउटर या होम सर्वर पर Connect Beyond Borders इंस्टॉल, अपडेट, सत्यापित या हटा रहे हैं। फ़ोन, टैबलेट, घड़ी और टीवी ऐप्स के लिए [ऐप](apps.md) देखें।

Connect Beyond Borders हर कंप्यूटर पर एक छोटी बैकग्राउंड सेवा के रूप में चलता है। इसका कमांड-लाइन टूल `cbb` है। नीचे दिया गया हर तरीका वही सेवा इंस्टॉल करता है; वह चुनें जो आपके सिस्टम के अनुकूल हो।

## Linux

`systemd` वाले x86-64, ARM64, ARMv7 और ARMv6 Linux सिस्टम (लैपटॉप, डेस्कटॉप, Raspberry Pi बोर्ड, सर्वर और Steam Deck) पर समर्थित।

1. टर्मिनल में इंस्टॉलर चलाएँ:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. फ़ायरवॉल नियमों (जब कोई सक्रिय फ़ायरवॉल मिले) और दैनिक अपने-आप अपडेट के संकेतों के उत्तर दें।
3. एक बार लॉग आउट करके दोबारा लॉग इन करें ताकि आपका खाता (`cbb` समूह में जोड़ा गया) `sudo` के बिना `cbb` चला सके।

जिन x86-64 और ARM64 डेस्कटॉप पर GTK 4 और WebKitGTK 6.0 इंस्टॉल हैं (Debian और Ubuntu पर `libgtk-4-1 libwebkitgtk-6.0-4`; Fedora पर `gtk4 webkitgtk6.0`), उन पर इंस्टॉलर ट्रे ऐप (`cbb-desktop`) भी इंस्टॉल करता है, जो आपके डेस्कटॉप सत्र के साथ शुरू होता है और आपके ऐप्लिकेशन मेनू में दिखाई देता है। यदि ये लाइब्रेरी नहीं हैं, तो इंस्टॉलर इंस्टॉल करने के लिए पैकेजों के नाम बताता है; उन्हें जोड़ने के बाद ट्रे ऐप इंस्टॉल करने के लिए इंस्टॉलर फिर से चलाएँ।

आप `sh -s --` के बाद `get.sh` को अतिरिक्त विकल्प दे सकते हैं:

- **टेक्स्ट कंसोल (`--console`):** बिना डेस्कटॉप वाली मशीन के लिए, `tmux` के भीतर कॉपी और पेस्ट जोड़ता है और टेक्स्ट कंसोल पर रिमोट पेस्ट के लिए `cbb-console.service` इंस्टॉल करता है:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **डेस्कटॉप पेस्ट संवाद छोड़ें (`--uinput`):** GNOME और KDE पर, रिमोट पेस्ट कुंजियाँ दबाने से पहले एक बार सिस्टम संवाद में पूछता है। `--uinput` जोड़ने से `cbb-uinput.service` इंस्टॉल होता है और `uinput` कर्नेल मॉड्यूल लोड होता है ताकि Connect Beyond Borders सीधे पेस्ट की कुंजियाँ दबा सके (लॉगिन या लॉक स्क्रीन पर कभी नहीं)। इस विकल्प के लिए `cbb-helper` आवश्यक है।
- **हेल्पर के बिना छोटे डिवाइस (`--no-helper`):** उन छोटे डिवाइसों पर `cbb-helper` (वह सहायक प्रोग्राम जो TPM कुंजियाँ, डेस्कटॉप क्लिपबोर्ड, रिमोट पेस्ट की कुंजी प्रविष्टि, ब्लूटूथ कीबोर्ड और टीवी रिमोट संभालता है) को छोड़ देता है जो केवल सिंक करते हैं:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  देखें [छोटे डिवाइस](../../member/README.md)। MIPS राउटर आर्काइव डिफ़ॉल्ट रूप से `cbb-helper` को छोड़ देते हैं। एक बार कोई डिवाइस `cbb-helper` के बिना इंस्टॉल हो जाए, तो बाद के अपडेट इसे वैसा ही रखते हैं।

Linux (x86-64 और ARM64) पर Homebrew भी समर्थित है:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

हर `brew upgrade` के बाद दूसरा कमांड फिर से चलाएँ।

### बिना sudo (बिना root)

जिस Linux कंप्यूटर पर आपके पास एडमिनिस्ट्रेटर अधिकार (`sudo`) नहीं हैं, वहाँ बिना `sudo` के अपने उपयोगकर्ता खाते के लिए Connect Beyond Borders इंस्टॉल करें:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

यह `cbb` को `~/.local/bin` में इंस्टॉल करता है और आपके लॉग इन रहने तक इसे `systemd` उपयोगकर्ता सेवा के रूप में चलाता है। इसे सिस्टम-व्यापी इंस्टॉलेशन के साथ इंस्टॉल नहीं किया जा सकता।

बिना root वाला इंस्टॉल केवल तभी इस्तेमाल करें जब सामान्य इंस्टॉल संभव न हो। चूँकि आपके उपयोगकर्ता खाते के तहत चलने वाला कोई भी प्रोग्राम इसकी कुंजी फ़ाइलें पढ़ सकता है, इसलिए बिना root वाला डिवाइस कभी **मुख्य डिवाइस**, **एडमिन** या **हब** नहीं बन सकता ([बिना root वाले सदस्य](how-it-works.md#rootless-members))। बिना root वाले इंस्टॉल में कोई फ़ायरवॉल नियम, कोई TPM समर्थन, और कोई `--console` या `--uinput` हेल्पर भी नहीं होता।

- **लॉग आउट के बाद चालू रखें:** यदि इंस्टॉलर अपने-आप लिंगरिंग सक्षम नहीं कर पाता, तो किसी एडमिनिस्ट्रेटर से एक बार `sudo loginctl enable-linger YOUR-USER` चलाने को कहें।
- **हेल्पर के बिना:** `cbb-helper` को भी छोड़ने के लिए `--no-helper --rootless` दें (देखें [छोटे डिवाइसों पर बिना sudo](../../member/README.md#without-sudo-rootless))।
- **हटाना:** `sh ~/.local/share/cbb/uninstall.sh` चलाएँ।

### SteamOS (Steam Deck)

1. **डेस्कटॉप मोड** पर स्विच करें और **Konsole** खोलें।
2. यदि आपने `deck` उपयोगकर्ता के लिए पासवर्ड सेट नहीं किया है, तो सेट करने के लिए `passwd` चलाएँ।
3. Linux इंस्टॉलर कमांड चलाएँ:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

SteamOS हर OS अपडेट पर अपना रूट फ़ाइल सिस्टम बदल देता है, इसलिए इंस्टॉलर Connect Beyond Borders को `/usr/local` के बजाय `/opt/cbb` में रखता है और इसकी `/etc` कॉन्फ़िगरेशन फ़ाइलों को `/etc/atomic-update.conf.d/cbb.conf` में पंजीकृत करता है। आपका इंस्टॉलेशन और समूह सदस्यता SteamOS अपडेट के बाद भी बने रहते हैं।

- लॉग आउट करके दोबारा लॉग इन करने के बाद `cbb` Konsole में आपके `PATH` पर होता है। चूँकि `sudo` `/opt/cbb/bin` में नहीं खोजता, इसलिए `sudo` की ज़रूरत वाले कमांड को पूरा पाथ इस्तेमाल करना होता है, जैसे `sudo /opt/cbb/bin/cbb pair -code`।
- डेस्कटॉप मोड में क्लिपबोर्ड किसी भी KDE Plasma डेस्कटॉप की तरह सिंक होता है।
- गेम मोड में कोई डेस्कटॉप क्लिपबोर्ड नहीं होता, इसलिए वहाँ कुछ सिंक नहीं होता; सेवा चलती रहती है और डेस्कटॉप मोड में लौटने पर बकाया सिंक पूरा कर लेती है।
- इसे हटाने के लिए `sudo sh /opt/cbb/share/uninstall.sh` चलाएँ।

## Mac

macOS 14 या नए पर चलने वाले Apple सिलिकॉन और Intel Mac पर समर्थित।

- **इंस्टॉलर पैकेज (अनुशंसित, मेनू बार ऐप शामिल है):** [नवीनतम GitHub रिलीज़](https://github.com/HunterEwok/cbb/releases/latest) से `cbb-X.Y.Z.pkg` डाउनलोड करें और खोलें। यह पैकेज **CBB** मेनू बार ऐप (`/Applications/CBB.app`) और बैकग्राउंड सेवा दोनों इंस्टॉल करता है, जो हस्ताक्षरित और नोटराइज़ किए गए हैं।
- **टर्मिनल (केवल सेवा और `cbb`, मेनू बार ऐप के बिना):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (केवल सेवा और `cbb`, मेनू बार ऐप के बिना):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  अपडेट किए गए संस्करण पर सेवा और पेस्टबोर्ड एजेंट को फिर से शुरू करने के लिए हर `brew upgrade` के बाद दूसरा कमांड फिर से चलाएँ।

## Windows

Windows 10 (संस्करण 1809 या नया) और Windows 11 पर, x86-64 और ARM64 पर समर्थित।

1. **Run as administrator** के साथ PowerShell खोलें।
2. इंस्टॉलर चलाएँ:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. Windows Firewall नियमों और दैनिक अपने-आप अपडेट के संकेतों के उत्तर दें।
4. `cbb` का उपयोग करने के लिए एक नई टर्मिनल विंडो खोलें।

इंस्टॉलर साइन-इन किए गए उपयोगकर्ता को `cbb` समूह में जोड़ता है, बैकग्राउंड सेवा और क्लिपबोर्ड एजेंट शुरू करता है, और ट्रे ऐप इंस्टॉल करता है (जो साइन-इन पर शुरू होता है और Start मेनू में **CBB** नाम से सूचीबद्ध होता है)। समूह सदस्यता या सेटिंग्स बदलने वाले कमांड एडमिनिस्ट्रेटर टर्मिनल में चलते हैं, जहाँ Linux और macOS `sudo` का उपयोग करते हैं।

**winget** से इंस्टॉल करने के लिए (`HunterEwok.cbb` पैकेज का उपयोग करके):

```powershell
winget install HunterEwok.cbb
cbb install
```

अनपैक किए गए पैकेज से सेवा, क्लिपबोर्ड एजेंट, ट्रे ऐप और फ़ायरवॉल नियम इंस्टॉल करने के लिए एडमिनिस्ट्रेटर टर्मिनल में `cbb install` चलाएँ, और हर `winget upgrade` के बाद इसे फिर से चलाएँ।

## OpenWrt

OpenWrt 25.12 या नए (`apk` का उपयोग करने वाले) ऐसे राउटरों पर समर्थित जिनमें 25 MB के प्रोग्राम के लिए जगह हो (कम से कम 128 MB फ़्लैश या eMMC, और 256 MB RAM)।

SSH के ज़रिए `root` के रूप में कनेक्ट करें और चलाएँ:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

इंस्टॉलर `cbb` (`cbb-helper` के बिना) को एक `procd` सेवा के रूप में सेट करता है जो केवल `lan` ज़ोन में सुनती है और `wan` पर कभी जवाब नहीं देती। कुंजियाँ `/etc/cbb/state` में रहती हैं, जिसे `sysupgrade` सुरक्षित रखता है; अटेंडेड sysupgrade (ASU या `owut`) के बाद इंस्टॉल कमांड फिर से चलाएँ। जब इसे इंटरैक्टिव टर्मिनल में चलाया जाता है, तो इंस्टॉलर तुरंत पेयरिंग शुरू करता है (`--no-pair` इसे छोड़ देता है)। अतिरिक्त ज़ोन (जैसे IoT नेटवर्क), फ़ायरवॉल विवरण और जाँचों के लिए [राउटर और FreeBSD](../admin/routers.md#openwrt) देखें।

आप प्रोजेक्ट के `apk` पैकेज फ़ीड से भी इंस्टॉल कर सकते हैं ताकि `apk upgrade` इसे अपडेट रखे:

1. `grep DISTRIB_ARCH /etc/openwrt_release` से अपने राउटर का आर्किटेक्चर जाँचें और उसे फ़ीड डायरेक्टरी से मिलाएँ:
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*` (जिसके नाम में `neon` या `vfp` हो) → `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. फ़ीड कुंजी और रिपॉज़िटरी जोड़ें (`arm64` को अपने आर्किटेक्चर से बदलें) और इंस्टॉल करें:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

`apk del cbb` पैकेज को हटा देता है और कुंजियों को `/etc/cbb` में सुरक्षित रखता है। ध्यान दें कि `mips` और `mipsle` राउटर बिल्ड केवल घर के नेटवर्क पर सिंक करते हैं (घर से बाहर सिंक नहीं होता)।

## FreeBSD

FreeBSD 15 (`amd64` और `arm64`) पर समर्थित। `root` के रूप में चलाएँ (`sudo` या `doas` के साथ):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

इंस्टॉलर `cbb` इंस्टॉल करता है, एक `rc.d` स्क्रिप्ट जोड़ता है जो `daemon(8)` के ज़रिए सेवा चलाती है, और `rc.conf` में `cbb_enable="YES"` जोड़ता है। कुंजियाँ `/var/db/cbb` में और सेटिंग्स `/usr/local/etc/cbb` में रहती हैं।

- **OPNsense:** वही इंस्टॉलर एक प्लगइन हुक जोड़ता है जिससे सेवा **System > Diagnostics > Services** के अंतर्गत दिखाई देती है और इसके फ़ायरवॉल नियम (`pf` एंकर `cbb` में) फ़िल्टर रीलोड होने पर भी बने रहते हैं। Connect Beyond Borders चलते समय **Services > mDNS Repeater** बंद रखें, क्योंकि दोनों को UDP पोर्ट 5353 चाहिए और सेवा हर घरेलू इंटरफ़ेस पर mDNS का जवाब खुद देती है।
- **pfSense (असमर्थित):** इंस्टॉलर pfSense पर चलता है, **Firewall > Rules** के तहत मैन्युअल रूप से जोड़ने के लिए नियम छापता है, और pfSense सिस्टम अपडेट से यह हट सकता है।
- **FreeBSD डेस्कटॉप:** X11 पर, या data-control प्रोटोकॉल वाले Wayland कंपोज़िटरों पर (जैसे KDE, sway और Hyprland), जब आप फिर से लॉग इन करते हैं तो XDG ऑटोस्टार्ट `cbb agent` शुरू करता है। रिमोट पेस्ट X11 पर XTEST और wlroots डेस्कटॉप पर वर्चुअल कीबोर्ड इस्तेमाल करता है; FreeBSD पर GNOME रिमोट पेस्ट स्वीकार नहीं करता क्योंकि `logind` के बिना लॉक-स्क्रीन की स्थिति उपलब्ध नहीं होती।

## Docker

बिना डेस्कटॉप वाले NAS या हमेशा चालू रहने वाले होम सर्वर के लिए ([Docker इमेज README](../../packaging/docker/README.md) देखें)। कंटेनर एक सामान्य सदस्य के रूप में जुड़ता है; समूह अपने फ़ोन या अपने पास मौजूद कंप्यूटर पर बनाएँ।

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

पहले अपने फ़ोन या किसी एडमिन कंप्यूटर पर पेयरिंग विंडो खोलें, फिर जब `cbb pair -code` पूछे तब छह अंक टाइप करें।

## फ़ायरवॉल

Connect Beyond Borders को केवल आपके घर के नेटवर्क से आने वाले **TCP पोर्ट 8764** (या आपके कस्टम सदस्य पोर्ट) और **UDP पोर्ट 5353** (mDNS) की आवश्यकता होती है।

इंस्टॉलर आपके फ़ायरवॉल का पता लगाता है (Linux पर `ufw`, `firewalld`, `nftables` या `iptables`; FreeBSD पर `pf`, `ipfw` या OPNsense; macOS एप्लिकेशन फ़ायरवॉल; Windows Firewall), हर आवश्यक नियम की सूची दिखाता है, और पूछता है `Add these rules now? [y/N]` (macOS पर `Add this rule now? [y/N]`):

- **हाँ:** इंस्टॉलर नियम जोड़ देता है, अपग्रेड पर उन्हें अपडेट रखता है, और किसी अन्य नियम को बदले बिना अनइंस्टॉल करने पर उन्हें हटा देता है।
- **नहीं** (डिफ़ॉल्ट, और जब कोई इंटरैक्टिव टर्मिनल जुड़ा न हो): इंस्टॉलर कोई नियम नहीं जोड़ता और आपके स्वयं चलाने के लिए सटीक कमांड छाप देता है।
- **बिना पूछे विकल्प:**
  - Linux, macOS और FreeBSD पर: बिना पूछे नियम जोड़ने के लिए `--express` दें, या मना करने और कमांड छापने के लिए `--no-firewall` दें।
  - Windows पर: `get.ps1` चलाने से पहले `$env:CBB_FIREWALL = "express"` या `$env:CBB_FIREWALL = "no"` सेट करें (या `install.ps1` को `-Express` या `-NoFirewall` दें)।

फ़ायरवॉल-विशिष्ट व्यवहार:

- `nftables` और `iptables` हमेशा केवल मैन्युअल कमांड छापते हैं, क्योंकि रनटाइम नियम रीबूट के बाद नहीं बचते।
- FreeBSD `pf` नियमों को अपने स्वयं के `cbb` एंकर में रखता है, जो `/etc/pf.conf` के अंत में जोड़ी गई तीन चिह्नित पंक्तियों के ज़रिए लोड होते हैं (अनइंस्टॉल करने पर हटा दिए जाते हैं)। FreeBSD `ipfw` उन्हें नियम सेट 17 में जोड़ता है और हर स्टार्ट पर फिर से लोड करता है।
- यदि आप Connect Beyond Borders इंस्टॉल करने के बाद फ़ायरवॉल चालू करते हैं, तो इंस्टॉलर फिर से चलाएँ।

जब TCP 8764 पहले से उपयोग में हो, तो अलग सदस्य पोर्ट इस्तेमाल करने के लिए:

- Linux, macOS, FreeBSD और OpenWrt पर: `--port 9000` दें (उदाहरण के लिए, `... | sudo sh -s -- --port 9000`)।
- Windows पर: `get.ps1` चलाने से पहले `$env:CBB_PORT = "9000"` सेट करें (या `install.ps1` को `-Port 9000` दें)।

इंस्टॉलर के सभी विकल्प [कमांड संदर्भ](../reference/cli.md#installers) में सूचीबद्ध हैं।

## अपडेट करना

समूह के हर डिवाइस को एक ही रिलीज़ पर रखें। संगतता विवरण के लिए [संस्करण और संगतता](../reference/compatibility.md) देखें।

### मैन्युअल अपडेट

- **`get.sh`, `get.ps1` या रिलीज़ आर्काइव से इंस्टॉल किया गया:**
  - नए रिलीज़ की जाँच करें: `cbb update -check`
  - नवीनतम हस्ताक्षरित रिलीज़ इंस्टॉल करें: `sudo cbb update` (Windows पर, एडमिनिस्ट्रेटर टर्मिनल में `cbb update` चलाएँ; बिना root वाले Linux पर, `sudo` के बिना `cbb update` चलाएँ; SteamOS पर, `sudo /opt/cbb/bin/cbb update` चलाएँ)।

  `cbb update` आपकी सेटिंग्स और कुंजियाँ सुरक्षित रखता है, केवल प्रोजेक्ट द्वारा हस्ताक्षरित रिलीज़ इंस्टॉल करता है, पुराने संस्करणों को अस्वीकार करता है, और यदि अपडेट की गई सेवा एक मिनट के भीतर शुरू नहीं होती है तो अपने-आप पिछला संस्करण बहाल कर देता है। मूल `get.sh` या `get.ps1` कमांड को फिर से चलाने से भी अपडेट हो जाता है।
- **Homebrew:** `brew upgrade cbb` चलाएँ, फिर [Mac](#mac) या [Linux](#linux) अनुभाग का `install.sh` कमांड फिर से चलाएँ।
- **winget:** `winget upgrade HunterEwok.cbb` चलाएँ, फिर एडमिनिस्ट्रेटर टर्मिनल में `cbb install` चलाएँ।
- **Docker:** `docker compose -f compose.home.yaml pull` चलाएँ और कंटेनर को फिर से बनाएँ।
- **OpenWrt पैकेज फ़ीड:** `apk update && apk upgrade` चलाएँ।

### अपने-आप अपडेट

`get.sh` और `get.ps1` इंस्टॉलेशन के लिए, इंस्टॉलर एक बार पूछता है कि क्या दैनिक अपने-आप अपडेट चालू करना है। आप पहले से उत्तर तय कर सकते हैं या बाद में बदल सकते हैं:

- **इंस्टॉल के दौरान:** `get.sh` को `--auto-update on` या `--auto-update off` दें; Windows पर, `get.ps1` चलाने से पहले `$env:CBB_AUTO_UPDATE = "on"` या `"off"` सेट करें (या `install.ps1` को `-AutoUpdate on|off` दें)।
- **इंस्टॉल के बाद:** `sudo cbb update -auto on` या `sudo cbb update -auto off` चलाएँ (बिना root वाले Linux पर `sudo` के बिना; Windows पर एडमिनिस्ट्रेटर टर्मिनल में)।

जब अपने-आप अपडेट चालू होते हैं, तो एक दैनिक शेड्यूल हस्ताक्षरित रिलीज़ की जाँच करता है: Linux पर `systemd` टाइमर (बिना root पर उपयोगकर्ता टाइमर), macOS पर `launchd` जॉब, Windows पर `SYSTEM` के रूप में शेड्यूल्ड टास्क, या OpenWrt और FreeBSD पर `cron`।

हर जाँच GitHub से छोटी हस्ताक्षरित मेटाडेटा फ़ाइलें डाउनलोड करती है (यदि GitHub जवाब न दे, तो `dl.cbb.tools` से)। GitHub डिवाइस का IP पता देखता है और यह देखता है कि वह Connect Beyond Borders मेटाडेटा माँग रहा है, पर आपके समूह के बारे में कुछ नहीं। इसके बजाय कस्टम मिरर का उपयोग करने के लिए `sudo cbb update -mirror https://...` चलाएँ; मिरर पर भरोसा करने की आवश्यकता नहीं है क्योंकि हस्ताक्षर फिर भी सत्यापित होते हैं।

अपने-आप अपडेट के लॉग `update.log` में यहाँ लिखे जाते हैं:

| सिस्टम | अपडेट लॉग डायरेक्टरी |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (बिना root) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

समूह के डिवाइस किसी भी डिवाइस द्वारा देखी गई नवीनतम हस्ताक्षरित रिलीज़ की सूचना आपस में साझा करते हैं, इसलिए जब कोई अपडेट उपलब्ध होता है तो `cbb status` और डेस्कटॉप ऐप आपको सूचित करते हैं। हर डिवाइस फिर भी हस्ताक्षर स्वयं सत्यापित करता है और अपना आर्काइव स्वयं डाउनलोड करता है।

## डाउनलोड की जाँच

हर रिलीज़ आर्काइव की तीन तरीकों से जाँच की जाती है:

1. **चेकसम (`SHA256SUMS`):** `get.sh` और `get.ps1` दोनों डाउनलोड किए गए आर्काइव को रिलीज़ की `SHA256SUMS` फ़ाइल से सत्यापित करते हैं।
2. **प्रोजेक्ट रिलीज़ हस्ताक्षर:** रिलीज़ प्रोजेक्ट की ऑफ़लाइन रूट कुंजियों और रिलीज़ कुंजी से हस्ताक्षरित होती हैं (जो CI को कभी नहीं छूतीं): `keys.json` प्रोजेक्ट की रूट कुंजियों के तहत रिलीज़ कुंजियों को प्रमाणित करता है, `release.json` हर फ़ाइल का आकार और SHA-256 हैश सूचीबद्ध करता है, और `stable.json` मौजूदा स्थिर रिलीज़ का नाम बताता है ([प्रोटोकॉल](../protocol.md), खंड 16)। `get.sh` (`openssl` का उपयोग करके) और `get.ps1` दोनों में प्रोजेक्ट की अंतर्निहित रूट कुंजियाँ होती हैं और वे किसी भी ऐसी रिलीज़ को इंस्टॉल करने से मना करते हैं जिसके हस्ताक्षर सत्यापित न हों। जब OpenSSL 3.5 या नया इंस्टॉल हो तो `get.sh` ES256 और SLH-DSA-SHA2-128s दोनों की जाँच करता है (पुराने OpenSSL पर ES256); `get.ps1` ES256 की जाँच करता है। प्रोजेक्ट हस्ताक्षरों की जाँच किए बिना इंस्टॉल करने के लिए `CBB_VERIFY=skip` सेट करें।
3. **बिल्ड प्रोवेनेंस प्रमाणन:** हर रिलीज़ फ़ाइल के पास एक GitHub बिल्ड प्रोवेनेंस प्रमाणन होता है जो उसे इस रिपॉज़िटरी के रिलीज़ वर्कफ़्लो से जोड़ता है। [GitHub CLI](https://cli.github.com/) (`gh`) के साथ, आप किसी भी फ़ाइल को मैन्युअल रूप से सत्यापित कर सकते हैं:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   जब `gh` इंस्टॉल और साइन इन हो (`gh auth login`; `sudo` के तहत `get.sh` के लिए `sudo gh auth login` चलाएँ), तो `get.sh` और `get.ps1` दोनों यह जाँच अपने-आप चलाते हैं। सत्यापित प्रमाणन के बिना इंस्टॉलेशन अस्वीकार करने के लिए `CBB_ATTESTATION=require` सेट करें, या प्रमाणन जाँच छोड़ने के लिए `CBB_ATTESTATION=skip` सेट करें।

## हटाना

अपने सिस्टम के लिए अनइंस्टॉल कमांड चलाएँ:

| सिस्टम | कमांड या चरण |
|---|---|
| Linux और macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (बिना root) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (या `doas` के साथ) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (या यदि फ़ीड से इंस्टॉल किया गया हो तो `apk del cbb`) |
| Windows | **Settings > Apps > CBB > Uninstall** खोलें, या एडमिनिस्ट्रेटर के रूप में `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` चलाएँ |

यदि आपने Homebrew से इंस्टॉल किया था, तो पहले अनइंस्टॉल स्क्रिप्ट चलाएँ और फिर `brew uninstall cbb` चलाएँ।

अनइंस्टॉल करने से प्रोग्राम, बैकग्राउंड सेवा, क्लिपबोर्ड एजेंट, अपडेट टाइमर, इंस्टॉलर द्वारा जोड़े गए फ़ायरवॉल नियम, और (macOS पर, यदि `.pkg` से इंस्टॉल किया गया हो) `/Applications/CBB.app` हट जाते हैं। आपके डिवाइस की कुंजियाँ और समूह की स्थिति डिस्क पर बनी रहती हैं ताकि दोबारा इंस्टॉल करने पर वह उसी समूह से फिर जुड़ जाए।

- **कुंजियाँ और समूह की स्थिति भी मिटाएँ:** Unix सिस्टम पर `--purge` जोड़ें, या Windows पर एडमिनिस्ट्रेटर PowerShell में `uninstall.ps1 -Purge` चलाएँ। इसके बाद, किसी एडमिन डिवाइस पर डिवाइस को समूह से हटा दें (`sudo cbb remove NAME` या फ़ोन ऐप में)।
- **अनइंस्टॉल किए बिना समूह छोड़ें:** `sudo cbb leave` चलाएँ (बिना root वाले Linux पर `sudo` के बिना, या Windows पर एडमिनिस्ट्रेटर टर्मिनल में `cbb leave`)। यह Connect Beyond Borders को इंस्टॉल रखते हुए डिवाइस की कुंजियाँ और समूह की फ़ाइलें मिटा देता है ताकि डिवाइस फिर से किसी समूह से जुड़ सके।
