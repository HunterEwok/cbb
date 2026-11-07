<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# इंस्टॉल करना

Copy Beyond Borders हर कंप्यूटर पर एक छोटी बैकग्राउंड सेवा की तरह चलता है। इसका कमांड `cbb` है। नीचे के सभी तरीके एक ही प्रोग्राम इंस्टॉल करते हैं; जो पसंद आए, चुन लें।

## Linux

systemd वाला कोई भी Linux (x86-64, ARM64, ARMv7, ARMv6): लैपटॉप, डेस्कटॉप, Raspberry Pi, सर्वर, Steam Deck।

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

फिर एक बार लॉग आउट करके दोबारा लॉग इन करें, ताकि आपका उपयोगकर्ता `sudo` के बिना `cbb` चला सके। बिना डेस्कटॉप वाली मशीन को `--console` से tmux के भीतर कॉपी और पेस्ट मिलता है (`... | sudo sh -s -- --console`)।

GTK 4 और WebKitGTK 6.0 वाले डेस्कटॉप पर (x86-64 और ARM64) यह ट्रे ऐप भी इंस्टॉल करता है, जो आपके सत्र के साथ शुरू होता है और ऐप्लिकेशन मेनू में रहता है। इनके बिना यह बताता है कि कौन-से पैकेज जोड़ने हैं; उसके बाद ट्रे ऐप के लिए इसे फिर से चलाएँ।

GNOME और KDE पर रिमोट पेस्ट एक बार कंप्यूटर पर एक संवाद में पूछता है, इससे पहले कि किसी एडमिन का पहला पेस्ट कुंजियाँ दबा सके। संवाद छोड़ने के लिए `--uinput` जोड़ें (`... | sudo sh -s -- --uinput`): तब एक छोटा सहायक स्क्रीन इस्तेमाल करने वाले के लिए पेस्ट की कुंजियाँ (Shift+Insert और Enter) दबाता है, लॉगिन या लॉक स्क्रीन पर कभी नहीं।

जिन छोटे डिवाइस को केवल सिंक करना है, जैसे राउटर या Raspberry Pi Zero, वे इसके बजाय हल्का [लाइट सदस्य](../../member/README.md) ले सकते हैं: `... | sudo sh -s -- --lite`।

### बिना sudo (बिना root)

जिस Linux कंप्यूटर पर आप `sudo` इस्तेमाल नहीं कर सकते या नहीं करना चाहते, वहाँ इसे `sudo` के बिना केवल अपने उपयोगकर्ता के लिए इंस्टॉल करें:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

यह आपके लॉग इन रहने तक आपकी अपनी बैकग्राउंड सेवा की तरह चलता है, और किसी भी सदस्य की तरह सिंक करता है। इसे तभी इस्तेमाल करें जब सामान्य इंस्टॉल संभव न हो: आपका चलाया हर प्रोग्राम इसकी कुंजियाँ नकल कर सकता है, इसलिए यह कभी समूह का रूट, एडमिन या हब नहीं बन सकता ([यह कैसे काम करता है](how-it-works.md#rootless-members)), और इसमें न फ़ायरवॉल नियम हैं, न TPM, न `--console` या `--uinput`। लॉग आउट के बाद भी इसे चालू रखने के लिए कोई एडमिनिस्ट्रेटर एक बार `sudo loginctl enable-linger YOUR-USER` चलाता है। इसे हटाने के लिए: `sh ~/.local/share/cbb/uninstall.sh`। लाइट सदस्य भी इसी तरह `--lite --rootless` से इंस्टॉल होता है ([लाइट सदस्य](../../member/README.md#without-sudo-rootless))।

### SteamOS (Steam Deck)

डेस्कटॉप मोड में जाएँ, Konsole खोलें, अगर `deck` उपयोगकर्ता का पासवर्ड नहीं है तो एक बार उसे दें (`passwd`), और वही कमांड चलाएँ। SteamOS हर अपडेट में अपनी सिस्टम फ़ाइलें बदल देता है, इसलिए इंस्टॉलर Copy Beyond Borders को `/usr/local` की जगह `/opt/cbb` में रखता है, और SteamOS को बताता है कि `/etc` की उसकी कौन-सी फ़ाइलें रखनी हैं (`/etc/atomic-update.conf.d/cbb.conf`)। SteamOS के अपडेट के बाद भी यह इंस्टॉल रहता है और अपने समूह में बना रहता है।

- लॉग आउट और दोबारा लॉग इन के बाद `cbb` नए Konsole के पाथ में होता है। `sudo` वहाँ नहीं देखता, इसलिए जिन कमांड को उसकी ज़रूरत है उन्हें पूरा पाथ देना पड़ता है: `sudo /opt/cbb/bin/cbb pair`।
- डेस्कटॉप मोड में क्लिपबोर्ड वैसे ही सिंक होता है जैसे किसी भी KDE Plasma डेस्कटॉप पर।
- गेम मोड में डेस्कटॉप क्लिपबोर्ड नहीं होता, इसलिए वहाँ कुछ सिंक नहीं होता; सेवा चलती रहती है और डेस्कटॉप मोड में पीछे का सब पकड़ लेती है।
- इसे हटाने के लिए: `sudo sh /opt/cbb/share/uninstall.sh`।

## Mac

Apple silicon या Intel, macOS 14 या नया: `cbb-X.Y.Z.pkg`
[नवीनतम रिलीज़](https://github.com/HunterEwok/cbb/releases/latest) से डाउनलोड करें और खोलें। यह मेन्यू बार में
CBB ऐप और सेवा इंस्टॉल करता है; दोनों प्रोजेक्ट द्वारा हस्ताक्षरित और Apple द्वारा जाँचे गए हैं।

या Terminal में, ऐप के बिना, वही कमांड जो Linux पर है:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

या Homebrew से, जो इसे अपडेट भी करता है। हर `brew upgrade` के बाद दूसरी पंक्ति दोबारा चलाएँ:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

Windows 10 (1809 या बाद का) या 11, x86-64 या ARM64, "Run as administrator" से खोली गई PowerShell में:

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

यह स्क्रीन पर साइन इन उपयोगकर्ता को `cbb` इस्तेमाल करने देता है (नए टर्मिनल में) और उसके लिए क्लिपबोर्ड एजेंट शुरू करता है। समूह बदलने वाले कमांड एडमिनिस्ट्रेटर के रूप में खोले गए टर्मिनल में चलते हैं, जहाँ Linux और macOS `sudo` इस्तेमाल करते हैं।

यह ट्रे ऐप भी इंस्टॉल करता है, जो साइन-इन पर शुरू होता है और Start मेनू में CBB नाम से रहता है।

winget के साथ, पैकेज के winget के रिपॉज़िटरी में आ जाने के बाद:

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

OpenWrt 25.12 या बाद का राउटर, जिसमें 25 MB के प्रोग्राम की जगह हो (128 MB या ज़्यादा फ़्लैश, या eMMC; 256 MB RAM), SSH के ज़रिए root के रूप में:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

यह `cbb` को ऐसी सेवा के रूप में इंस्टॉल करता है जो केवल `lan` ज़ोन में काम करती है और `wan` पर कभी जवाब नहीं देती। कुंजियाँ `/etc/cbb` में रहती हैं, जिसे sysupgrade रखता है; निगरानी वाले sysupgrade (ASU, owut) के बाद कमांड दोबारा चलाएँ। कोई और ज़ोन, जैसे IoT नेटवर्क, फ़ायरवॉल और जाँचें [राउटर और FreeBSD](../admin/routers.md#openwrt) में हैं।

या हमारे पैकेज फ़ीड से, जिसे `apk upgrade` फिर ताज़ा रखता है। फ़ीड का आर्किटेक्चर राउटर के CPU के अनुसार होता है (`grep DISTRIB_ARCH /etc/openwrt_release`): `aarch64_*` के लिए `arm64`, `arm_cortex-a*` के लिए `armv7` (जिसके नाम में `neon` या `vfp` हो), `mipsel_*` के लिए `mipsle`, `mips_*` के लिए `mips`, `x86_64` के लिए `amd64`। दूसरी पंक्ति में `arm64` की जगह अपना रखें:

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

`apk del cbb` इसे हटा देता है और कुंजियाँ `/etc/cbb` में रहने देता है।

## FreeBSD

FreeBSD 15, amd64 या arm64, root के रूप में (`sudo` या `doas` से):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

यह `cbb` इंस्टॉल करता है, एक rc.d स्क्रिप्ट जो daemon(8) के ज़रिए सेवा चलाती है, और rc.conf में `cbb_enable="YES"` पंक्ति जोड़ता है। कुंजियाँ `/var/db/cbb` में रहती हैं।

OPNsense पर वही इंस्टॉलर एक प्लगइन हुक भी जोड़ता है: सेवा System > Diagnostics > Services के तहत दिखती है, और उसके फ़ायरवॉल नियम (pf के एंकर `cbb` में) हर फ़िल्टर रीलोड के साथ बने रहते हैं। सेवा चलने तक mDNS रिपीटर (Services > mDNS Repeater) बंद रखें: दोनों को UDP पोर्ट 5353 चाहिए, और सेवा हर घरेलू इंटरफ़ेस पर mDNS का जवाब खुद देती है। pfSense समर्थित नहीं है: इंस्टॉलर वहाँ भी चलता है, पर वह फ़ायरवॉल नियम जोड़ने के बजाय Firewall > Rules के लिए छाप देता है, और pfSense का अपडेट Copy Beyond Borders को हटा सकता है।

FreeBSD डेस्कटॉप पर (X11, या data control प्रोटोकॉल वाला Wayland, जैसे KDE, sway और Hyprland में), सत्र XDG ऑटोस्टार्ट से `cbb agent` शुरू करता है और क्लिपबोर्ड समूह में जुड़ जाता है; इंस्टॉल के बाद दोबारा लॉग इन करें। रिमोट पेस्ट X11 पर XTEST से और wlroots डेस्कटॉप पर वर्चुअल कीबोर्ड से टाइप करता है; GNOME FreeBSD पर रिमोट पेस्ट नहीं लेता, क्योंकि logind के बिना कुछ नहीं बताता कि उसकी स्क्रीन लॉक है या नहीं।

## Docker

हमेशा चालू रहने वाले NAS या घरेलू सर्वर के लिए ([इमेज की README](../../packaging/docker/README.md); 0.5 से हर रिलीज़ के साथ प्रकाशित)। यह सामान्य सदस्य के रूप में जुड़ता है: समूह उस फ़ोन या कंप्यूटर पर बनाएँ जो आप संभालते हैं।

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## फ़ायरवॉल

Copy Beyond Borders को एक TCP पोर्ट, 8764, और mDNS (UDP 5353) चाहिए, दोनों केवल घर के नेटवर्क से। इंस्टॉलर फ़ायरवॉल ढूँढता है (Linux पर ufw, firewalld, nftables या iptables, FreeBSD पर pf या ipfw, Mac का एप्लिकेशन फ़ायरवॉल, Windows Firewall), हर नियम सूचीबद्ध करता है, और पूछता है `Add these rules now? [y/N]`:

- **हाँ**: वह उन्हें जोड़ता है, हर अपडेट पर उन्हें ताज़ा रखता है और अनइंस्टॉल करने पर हटा देता है। वह दूसरे नियमों को कभी नहीं छूता।
- **नहीं** (डिफ़ॉल्ट, और तब भी जब पूछने के लिए टर्मिनल न हो): वह कुछ नहीं जोड़ता और सटीक कमांड छाप देता है, ताकि आप खुद चलाएँ।
- `--express` (Windows पर `-Express`) बिना पूछे जोड़ देता है; `--no-firewall` का जवाब "नहीं" है।

nftables और iptables को हमेशा केवल कमांड मिलते हैं, क्योंकि चलते समय जोड़े गए नियम वहाँ रीस्टार्ट के बाद नहीं बचते। FreeBSD पर pf को नियम उसके अपने एंकर में मिलते हैं, जिसे pf तीन चिह्नित पंक्तियों से पढ़ता है जो इंस्टॉलर `/etc/pf.conf` के अंत में जोड़ता और फिर हटा देता है; ipfw को वे नियम सेट 17 में मिलते हैं, जो हर स्टार्ट पर दोबारा जोड़े जाते हैं। अगर आप फ़ायरवॉल बाद में चालू करें, तो इंस्टॉलर दोबारा चलाएँ।

**दूसरा पोर्ट**, अगर 8764 लिया हुआ है: `... | sudo sh -s -- --port 9000` (Windows पर इंस्टॉलर से पहले `$env:CBB_PORT = "9000"`)। फ़ोन ऐप पोर्ट QR कोड से जान लेता है।

इंस्टॉलर के सभी विकल्प [कमांड संदर्भ](../reference/cli.md#installers) में हैं।

## अपडेट करना

0.6 से रिलीज़ पर हस्ताक्षर होते हैं। किसी पुराने संस्करण से 0.6 पर जाने के लिए इंस्टॉल कमांड दोबारा चलाएँ; उसके बाद `cbb update` यह करता है।

`sudo cbb update` (Windows पर एडमिनिस्ट्रेटर के रूप में खोले गए टर्मिनल में `cbb update`) `get.sh`, `get.ps1` या रिलीज़ आर्काइव से इंस्टॉल किए गए कंप्यूटर या लाइट सदस्य पर नवीनतम रिलीज़ इंस्टॉल करता है; `cbb update -check` केवल बताता है कि कोई है या नहीं। आपकी सेटिंग्स बनी रहती हैं। यह केवल वही रिलीज़ इंस्टॉल करता है जिस पर परियोजना ने हस्ताक्षर किए हैं, और कभी पुरानी नहीं। अगर नया संस्करण एक मिनट में शुरू न हो, तो पिछला अपने आप लौट आता है। यह हस्ताक्षर कैसे जाँचता है, यह [प्रोटोकॉल](../protocol.md) के खंड 16 में है।

इंस्टॉलर एक बार पूछते हैं कि अपने आप अपडेट करना है या नहीं (`--auto-update on|off`, या Windows पर `-AutoUpdate on|off` और `$env:CBB_AUTO_UPDATE`, पहले से जवाब देने के लिए); `sudo cbb update -auto on|off` इसे बाद में बदलता है। चालू होने पर एक टाइमर दिन में एक बार अपने ही समय पर जाँच करता है: Linux पर systemd टाइमर, Mac पर launchd जॉब, Windows पर SYSTEM के रूप में शेड्यूल्ड टास्क, OpenWrt और FreeBSD पर cron। हर जाँच GitHub से (या GitHub के जवाब न देने पर `dl.cbb.tools` से) वही छोटी फ़ाइलें डाउनलोड करती है, इसलिए GitHub इस डिवाइस का पता जान लेता है और यह भी कि यह Copy Beyond Borders इस्तेमाल करता है, जैसे किसी भी डाउनलोड में; यह समूह के बारे में कुछ नहीं भेजता। `sudo cbb update -mirror https://...` इसके बजाय किसी दूसरे मिरर से अपडेट लेता है, जिसमें भरोसे की ज़रूरत नहीं, क्योंकि हस्ताक्षर जाँचे जाते हैं। टाइमर का लॉग `update.log` है, जो `/var/lib/cbb-update` (Linux), `/etc/cbb-update` (OpenWrt), `/var/db/cbb-update` (FreeBSD), `/Library/Application Support/cbb-update` (Mac) या `C:\Program Files\cbb-update` (Windows) में रहता है।

समूह के डिवाइस एक-दूसरे को वह नवीनतम हस्ताक्षरित रिलीज़ बताते हैं जो उनमें से किसी ने देखी है, इसलिए एक डिवाइस की जाँच इतनी काफ़ी है कि बाकी पर `cbb status` और ट्रे ऐप बता दें कि नई रिलीज़ आ गई है (ट्रे ऐप में "Update to X" एडमिनिस्ट्रेटर के रूप में `cbb update` चलाता है)। हर डिवाइस फिर भी हस्ताक्षर खुद जाँचता है और अपना आर्काइव खुद डाउनलोड करता है।

वही इंस्टॉल कमांड दोबारा चलाने से भी अपडेट होता है। Homebrew या winget के साथ वहीं से अपग्रेड करें और दूसरी पंक्ति दोबारा चलाएँ; `cbb update` यही बताता है। Docker और OpenWrt पैकेज `docker compose pull` और `apk upgrade` से अपडेट होते हैं।

## डाउनलोड की जाँच

एक-पंक्ति वाले इंस्टॉलर डाउनलोड को रिलीज़ के `SHA256SUMS` से मिलाकर जाँचते हैं। हर रिलीज़ फ़ाइल के साथ एक बिल्ड प्रोवेनेंस प्रमाणन भी होता है जो उसे इस रिपॉज़िटरी और उसे बनाने वाले बिल्ड से जोड़ता है; [GitHub CLI](https://cli.github.com/) से:

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

जब `gh` इंस्टॉल हो और root के लिए साइन इन हो (`sudo gh auth login`), तब `get.sh` इसे खुद जाँचता है; `CBB_ATTESTATION=require` इसके बिना इंस्टॉल करने से मना कर देता है।

रिलीज़ परियोजना की अपनी कुंजियों से भी हस्ताक्षरित होती हैं, जो CI को कभी नहीं छूतीं (रूट कुंजियाँ ऑफ़लाइन हार्डवेयर कुंजियों पर हैं, रिलीज़ कुंजी मेंटेनर के Secure Enclave में): `keys.json` परियोजना की रूट कुंजियों के नीचे रिलीज़ कुंजियों के नाम देता है, `release.json` रिलीज़ की हर फ़ाइल को उसके हैश के साथ सूचीबद्ध करता है, और `stable.json` बताता है कि कौन-सी रिलीज़ मौजूदा है। जब रूट कुंजियाँ इंस्टॉलर में बन जाएँगी, तब `get.sh` (`openssl` के साथ) और `get.ps1` इंस्टॉल से पहले इन्हें जाँचेंगे और बिना हस्ताक्षर वाली रिलीज़ को ठुकरा देंगे; तब तक वे केवल `SHA256SUMS` और प्रमाणन जाँचते हैं। `CBB_VERIFY=skip` बिना जाँच के इंस्टॉल कर देता है।

## हटाना

Linux और Mac पर:

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

SteamOS पर यह `sudo sh /opt/cbb/share/uninstall.sh` है। Homebrew के साथ, उसके बाद `brew uninstall cbb` चलाएँ।

Windows पर: सेटिंग्स, ऐप्स, "CBB", अनइंस्टॉल।

इससे प्रोग्राम, सेवा, इंस्टॉलर के जोड़े फ़ायरवॉल नियम और Mac पर `.pkg` का इंस्टॉल किया ऐप हट जाते हैं। डिवाइस की कुंजियाँ रहती हैं, इसलिए दोबारा इंस्टॉल करने पर वह अपने समूह में लौट आता है। उन्हें भी मिटाने के लिए `--purge` जोड़ें (Windows पर `-Purge`, `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge` के साथ), फिर किसी दूसरे डिवाइस से इस डिवाइस को समूह से हटाएँ (`sudo cbb remove NAME`, या फ़ोन पर)। CBB रखते हुए समूह छोड़ने के लिए इसके बजाय `sudo cbb leave` चलाएँ: यह कुंजियाँ और समूह की फ़ाइलें मिटाता है, और डिवाइस फिर से किसी समूह में शामिल हो सकता है।
