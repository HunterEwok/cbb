<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# Kusakinisha

Kwa yeyote anayesakinisha, kusasisha, kukagua, au kuondoa Connect Beyond Borders kwenye kompyuta, kipanga njia, au seva ya nyumbani. Kwa programu za simu, kompyuta kibao, saa, na TV, tazama [Programu](apps.md).

Connect Beyond Borders huendeshwa kama huduma ndogo ya chinichini kwenye kila kompyuta. Zana yake ya mstari wa amri ni `cbb`. Kila njia iliyo hapa chini husakinisha huduma ileile; chagua inayofaa mfumo wako.

## Linux

Inatumika kwenye mifumo ya Linux yenye `systemd` kwenye x86-64, ARM64, ARMv7, na ARMv6 (kompyuta mpakato, kompyuta za mezani, bodi za Raspberry Pi, seva, na Steam Deck).

1. Endesha kisakinishi kwenye terminal:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. Jibu maswali kuhusu kanuni za ngome (ngome inayofanya kazi inapopatikana) na masasisho ya kiotomatiki ya kila siku.
3. Toka na uingie tena mara moja ili akaunti yako (iliyoongezwa kwenye kikundi `cbb`) iweze kuendesha `cbb` bila `sudo`.

Kwenye kompyuta za mezani za x86-64 na ARM64 ambazo zimesakinisha GTK 4 na WebKitGTK 6.0 (`libgtk-4-1 libwebkitgtk-6.0-4` kwenye Debian na Ubuntu; `gtk4 webkitgtk6.0` kwenye Fedora), kisakinishi pia husakinisha programu ya trei (`cbb-desktop`), ambayo huanza pamoja na kipindi chako cha eneo-kazi na huonekana kwenye menyu yako ya programu. Ikiwa maktaba hizo hazipo, kisakinishi hutaja vifurushi vya kusakinisha; endesha kisakinishi tena baada ya kuviongeza ili kusakinisha programu ya trei.

Unaweza kupitisha chaguo za ziada kwa `get.sh` baada ya `sh -s --`:

- **Konsoli ya maandishi (`--console`):** Kwa mashine isiyo na eneo-kazi, huongeza kunakili na kubandika ndani ya `tmux` na kusakinisha `cbb-console.service` kwa ajili ya kubandika kwa mbali kwenye konsoli ya maandishi:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **Ruka visanduku vya kubandika vya eneo-kazi (`--uinput`):** Kwenye GNOME na KDE, kubandika kwa mbali huuliza mara moja kwenye kisanduku cha mfumo kabla ya kubonyeza vitufe. Kuongeza `--uinput` husakinisha `cbb-uinput.service` na kupakia moduli ya kiini ya `uinput` ili Connect Beyond Borders ibonyeze vitufe vya kubandika moja kwa moja (kamwe si kwenye skrini ya kuingia au ya kufunga). Chaguo hili linahitaji `cbb-helper`.
- **Vifaa vidogo bila msaidizi (`--no-helper`):** Huacha `cbb-helper` (programu msaidizi inayoshughulikia funguo za TPM, mbao za kunakili za eneo-kazi, uingizaji wa vitufe vya kubandika kwa mbali, kibodi za Bluetooth, na rimoti za TV) kwenye vifaa vidogo vinavyosawazisha tu:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  Tazama [Vifaa vidogo](../../member/README.md). Kumbukumbu za vipanga njia vya MIPS huacha `cbb-helper` kwa chaguo-msingi. Kifaa kikishasakinishwa bila `cbb-helper`, masasisho ya baadaye hukiacha hivyo.

Homebrew kwenye Linux (x86-64 na ARM64) pia inaungwa mkono:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

Endesha amri ya pili tena baada ya kila `brew upgrade`.

### Bila sudo (bila root)

Kwenye kompyuta ya Linux ambapo huna haki za msimamizi (`sudo`), sakinisha Connect Beyond Borders kwa akaunti yako mwenyewe ya mtumiaji bila `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

Hii husakinisha `cbb` katika `~/.local/bin` na huiendesha kama huduma ya mtumiaji ya `systemd` wakati umeingia. Haiwezi kusakinishwa pamoja na usakinishaji wa mfumo mzima.

Tumia usakinishaji bila root pale tu usakinishaji wa kawaida hauwezekani. Kwa sababu programu yoyote inayoendeshwa chini ya akaunti yako ya mtumiaji inaweza kusoma faili zake za funguo, kifaa kisicho na root hakiwezi kamwe kuwa **kifaa kikuu**, **msimamizi**, wala **kitovu** ([wanachama bila root](how-it-works.md#rootless-members)). Usakinishaji bila root pia hauna kanuni za ngome, hauna msaada wa TPM, na hauna wasaidizi wa `--console` au `--uinput`.

- **Endelea kufanya kazi baada ya kutoka:** Ikiwa kisakinishi hakiwezi kuwasha lingering kiotomatiki, mwombe msimamizi wa mfumo aendeshe `sudo loginctl enable-linger YOUR-USER` mara moja.
- **Bila msaidizi:** Pitisha `--no-helper --rootless` ili kuacha `cbb-helper` pia (tazama [bila sudo kwenye vifaa vidogo](../../member/README.md#without-sudo-rootless)).
- **Kuondoa:** Endesha `sh ~/.local/share/cbb/uninstall.sh`.

### SteamOS (Steam Deck)

1. Badilisha kwenda **Desktop Mode** na ufungue **Konsole**.
2. Ikiwa bado hujaweka nywila kwa mtumiaji `deck`, endesha `passwd` ili kuweka moja.
3. Endesha amri ya kisakinishi cha Linux:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

SteamOS hubadilisha mfumo wake mkuu wa faili kwenye kila sasisho la OS, kwa hiyo kisakinishi huweka Connect Beyond Borders katika `/opt/cbb` badala ya `/usr/local` na kusajili faili zake za usanidi za `/etc` katika `/etc/atomic-update.conf.d/cbb.conf`. Usakinishaji wako na uanachama wa kikundi hubaki baada ya masasisho ya SteamOS.

- Baada ya kutoka na kuingia tena, `cbb` iko kwenye `PATH` yako katika Konsole. Kwa sababu `sudo` haitafuti `/opt/cbb/bin`, amri zinazohitaji `sudo` lazima zitumie njia kamili, kama `sudo /opt/cbb/bin/cbb pair -code`.
- Katika Desktop Mode, ubao wa kunakili husawazisha kama kwenye eneo-kazi lolote la KDE Plasma.
- Katika Game Mode, hakuna ubao wa kunakili wa eneo-kazi, kwa hiyo hakuna kinachosawazishwa huko; huduma hubaki ikifanya kazi na hukamata nakala unaporudi kwenye Desktop Mode.
- Kuiondoa, endesha `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Inatumika kwenye Mac zenye Apple silicon na Intel zinazoendesha macOS 14 au mpya zaidi.

- **Kifurushi cha kisakinishi (inapendekezwa, kinajumuisha programu ya upau wa menyu):** Pakua `cbb-X.Y.Z.pkg` kutoka [toleo la karibuni la GitHub](https://github.com/HunterEwok/cbb/releases/latest) na ukifungue. Kifurushi husakinisha programu ya upau wa menyu ya **CBB** (`/Applications/CBB.app`) na huduma ya chinichini, zote zikiwa zimetiwa sahihi na kuthibitishwa na Apple.
- **Terminal (huduma na `cbb` pekee, bila programu ya upau wa menyu):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (huduma na `cbb` pekee, bila programu ya upau wa menyu):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  Endesha amri ya pili tena baada ya kila `brew upgrade` ili kuanzisha upya huduma na wakala wa ubao wa kunakili kwenye toleo lililosasishwa.

## Windows

Inatumika kwenye Windows 10 (toleo 1809 au mpya zaidi) na Windows 11, kwenye x86-64 na ARM64.

1. Fungua PowerShell kwa **Run as administrator**.
2. Endesha kisakinishi:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. Jibu maswali kuhusu kanuni za Windows Firewall na masasisho ya kiotomatiki ya kila siku.
4. Fungua dirisha jipya la terminal ili kutumia `cbb`.

Kisakinishi humwongeza mtumiaji aliyeingia kwenye kikundi `cbb`, huanzisha huduma ya chinichini na wakala wa ubao wa kunakili, na kusakinisha programu ya trei (inayoanza wakati wa kuingia na kuorodheshwa kwenye menyu ya Start kama **CBB**). Amri zinazobadilisha uanachama wa kikundi au mipangilio huendeshwa kwenye terminal ya msimamizi wa mfumo, mahali ambapo Linux na macOS hutumia `sudo`.

Ili kusakinisha kwa **winget** (kwa kutumia kifurushi `HunterEwok.cbb`):

```powershell
winget install HunterEwok.cbb
cbb install
```

Endesha `cbb install` kwenye terminal ya msimamizi wa mfumo ili kusakinisha huduma, wakala wa ubao wa kunakili, programu ya trei, na kanuni za ngome kutoka kwenye kifurushi kilichofunguliwa, na uiendeshe tena baada ya kila `winget upgrade`.

## OpenWrt

Inatumika kwenye vipanga njia vinavyoendesha OpenWrt 25.12 au mpya zaidi (vinavyotumia `apk`) vyenye nafasi ya programu ya MB 25 (angalau MB 128 za flash au eMMC, na MB 256 za RAM).

Unganisha kupitia SSH kama `root` na uendeshe:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Kisakinishi huweka `cbb` (bila `cbb-helper`) kama huduma ya `procd` inayosikiliza kwenye eneo la `lan` pekee na kamwe haijibu kwenye `wan`. Funguo hukaa katika `/etc/cbb/state`, ambayo `sysupgrade` huihifadhi; baada ya attended sysupgrade (ASU au `owut`), endesha amri ya usakinishaji tena. Kinapoendeshwa kwenye terminal shirikishi, kisakinishi huanzisha kuoanisha mara moja (`--no-pair` huruka hili). Kwa maeneo ya ziada (kama mtandao wa IoT), maelezo ya ngome, na ukaguzi, tazama [Vipanga njia na FreeBSD](../admin/routers.md#openwrt).

Unaweza pia kusakinisha kutoka kwenye hazina ya vifurushi ya `apk` ya mradi ili `apk upgrade` iendelee kuisasisha:

1. Kagua usanifu wa kipanga njia chako kwa `grep DISTRIB_ARCH /etc/openwrt_release` na uulinganishe na folda ya hazina:
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*` (yenye `neon` au `vfp` kwenye jina) → `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. Ongeza ufunguo wa hazina na hazina yenyewe (badilisha `arm64` na usanifu wako) kisha usakinishe:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

`apk del cbb` huondoa kifurushi na kuhifadhi funguo katika `/etc/cbb`. Kumbuka kwamba matoleo ya vipanga njia vya `mips` na `mipsle` husawazisha kwenye mtandao wa nyumbani pekee (hakuna usawazishaji ukiwa mbali na nyumbani).

## FreeBSD

Inatumika kwenye FreeBSD 15 (`amd64` na `arm64`). Endesha kama `root` (kwa `sudo` au `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Kisakinishi husakinisha `cbb`, huongeza hati ya `rc.d` inayoendesha huduma kupitia `daemon(8)`, na kuongeza `cbb_enable="YES"` kwenye `rc.conf`. Funguo hukaa katika `/var/db/cbb` na mipangilio katika `/usr/local/etc/cbb`.

- **OPNsense:** Kisakinishi hichohicho huongeza ndoano ya programu-jalizi ili huduma ionekane chini ya **System > Diagnostics > Services** na kanuni zake za ngome (katika nanga ya `pf` ya `cbb`) zibaki hata kichujio kikipakiwa upya. Zima **Services > mDNS Repeater** wakati Connect Beyond Borders inaendeshwa, kwa sababu vyote viwili vinahitaji mlango wa UDP 5353 na huduma hujibu mDNS yenyewe kwenye kila kiolesura cha nyumbani.
- **pfSense (haiungwi mkono):** Kisakinishi huendeshwa kwenye pfSense, huchapisha kanuni za kuongeza kwa mkono chini ya **Firewall > Rules**, na kinaweza kuondolewa na sasisho la mfumo wa pfSense.
- **Maeneo-kazi ya FreeBSD:** Kwenye X11, au kwenye compositors za Wayland zenye itifaki ya data-control (kama KDE, sway, na Hyprland), XDG autostart huanzisha `cbb agent` unapoingia tena. Kubandika kwa mbali hutumia XTEST kwenye X11 na kibodi pepe kwenye maeneo-kazi ya wlroots; GNOME kwenye FreeBSD haikubali kubandika kwa mbali kwa sababu hali ya skrini iliyofungwa haipatikani bila `logind`.

## Docker

Kwa NAS au seva ya nyumbani inayowashwa kila wakati bila eneo-kazi (tazama [README ya taswira ya Docker](../../packaging/docker/README.md)). Kontena hujiunga kama mwanachama wa kawaida; unda kikundi kwenye simu yako au kwenye kompyuta unayoishikilia.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

Fungua dirisha la kuoanisha kwenye simu yako au kompyuta ya msimamizi kwanza, kisha andika tarakimu sita pale `cbb pair -code` inapokuuliza.

## Ngome

Connect Beyond Borders inahitaji **mlango wa TCP 8764** unaoingia (au mlango wako maalum wa mwanachama) na **mlango wa UDP 5353** (mDNS), kutoka mtandao wako wa nyumbani pekee.

Kisakinishi hutambua ngome yako (`ufw`, `firewalld`, `nftables`, au `iptables` kwenye Linux; `pf`, `ipfw`, au OPNsense kwenye FreeBSD; ngome ya programu ya macOS; Windows Firewall), huorodhesha kila kanuni inayohitajika, na kuuliza `Add these rules now? [y/N]` (`Add this rule now? [y/N]` kwenye macOS):

- **Ndiyo:** Kisakinishi huongeza kanuni, huzisasisha wakati wa uboreshaji, na kuziondoa unapoondoa usakinishaji bila kubadilisha kanuni nyingine yoyote.
- **Hapana** (chaguo-msingi, na wakati hakuna terminal shirikishi): Kisakinishi hakiongezi kanuni zozote na huchapisha amri kamili ili uziendeshe mwenyewe.
- **Chaguo za bila kuingilia:**
  - Kwenye Linux, macOS, na FreeBSD: pitisha `--express` ili kuongeza kanuni bila kuuliza, au `--no-firewall` ili kukataa na kuchapisha amri.
  - Kwenye Windows: weka `$env:CBB_FIREWALL = "express"` au `$env:CBB_FIREWALL = "no"` kabla ya kuendesha `get.ps1` (au pitisha `-Express` au `-NoFirewall` kwa `install.ps1`).

Tabia maalum za ngome:

- `nftables` na `iptables` huchapisha amri za kuendesha kwa mkono pekee kila mara, kwa sababu kanuni za wakati wa uendeshaji hazibaki baada ya kuwasha upya.
- `pf` ya FreeBSD huweka kanuni katika nanga yake ya `cbb`, inayopakiwa kupitia mistari mitatu iliyowekewa alama inayoongezwa mwishoni mwa `/etc/pf.conf` (inaondolewa wakati wa kuondoa usakinishaji). `ipfw` ya FreeBSD huziongeza katika seti ya kanuni 17 na kuzipakia upya kila inapoanza.
- Ukiwasha ngome baada ya kusakinisha Connect Beyond Borders, endesha kisakinishi tena.

Ili kutumia mlango tofauti wa mwanachama wakati TCP 8764 tayari inatumika:

- Kwenye Linux, macOS, FreeBSD, na OpenWrt: pitisha `--port 9000` (kwa mfano, `... | sudo sh -s -- --port 9000`).
- Kwenye Windows: weka `$env:CBB_PORT = "9000"` kabla ya kuendesha `get.ps1` (au pitisha `-Port 9000` kwa `install.ps1`).

Chaguo zote za kisakinishi zimeorodheshwa katika [marejeleo ya amri](../reference/cli.md#installers).

## Kusasisha

Weka kila kifaa katika kikundi kwenye toleo moja. Tazama [Matoleo na uoanifu](../reference/compatibility.md) kwa maelezo ya uoanifu.

### Masasisho ya mkono

- **Iliyosakinishwa kwa `get.sh`, `get.ps1`, au kumbukumbu ya toleo:**
  - Kagua kama kuna toleo jipya zaidi: `cbb update -check`
  - Sakinisha toleo jipya zaidi lililotiwa sahihi: `sudo cbb update` (kwenye Windows, endesha `cbb update` kwenye terminal ya msimamizi wa mfumo; kwenye Linux bila root, endesha `cbb update` bila `sudo`; kwenye SteamOS, endesha `sudo /opt/cbb/bin/cbb update`).

  `cbb update` huhifadhi mipangilio na funguo zako, husakinisha matoleo yaliyotiwa sahihi na mradi pekee, hukataa matoleo ya zamani zaidi, na hurejesha toleo la awali kiotomatiki ikiwa huduma iliyosasishwa itashindwa kuanza ndani ya dakika moja. Kuendesha tena amri ya awali ya `get.sh` au `get.ps1` pia husasisha.
- **Homebrew:** Endesha `brew upgrade cbb`, kisha uendeshe tena amri ya `install.sh` kutoka sehemu ya [Mac](#mac) au [Linux](#linux).
- **winget:** Endesha `winget upgrade HunterEwok.cbb`, kisha uendeshe `cbb install` kwenye terminal ya msimamizi wa mfumo.
- **Docker:** Endesha `docker compose -f compose.home.yaml pull` na uunde upya kontena.
- **Hazina ya vifurushi ya OpenWrt:** Endesha `apk update && apk upgrade`.

### Masasisho ya kiotomatiki

Kwa usakinishaji wa `get.sh` na `get.ps1`, kisakinishi huuliza mara moja kama kiwashe masasisho ya kiotomatiki ya kila siku. Unaweza kuweka jibu mapema au kulibadilisha baadaye:

- **Wakati wa kusakinisha:** Pitisha `--auto-update on` au `--auto-update off` kwa `get.sh`; kwenye Windows, weka `$env:CBB_AUTO_UPDATE = "on"` au `"off"` kabla ya kuendesha `get.ps1` (au pitisha `-AutoUpdate on|off` kwa `install.ps1`).
- **Baada ya kusakinisha:** Endesha `sudo cbb update -auto on` au `sudo cbb update -auto off` (bila `sudo` kwenye Linux bila root; kwenye terminal ya msimamizi wa mfumo kwenye Windows).

Masasisho ya kiotomatiki yakiwa yamewashwa, ratiba ya kila siku hukagua matoleo yaliyotiwa sahihi: kipima muda cha `systemd` kwenye Linux (kipima muda cha mtumiaji kwa usakinishaji bila root), kazi ya `launchd` kwenye macOS, kazi iliyoratibiwa kama `SYSTEM` kwenye Windows, au `cron` kwenye OpenWrt na FreeBSD.

Kila ukaguzi hupakua faili ndogo za metadata zilizotiwa sahihi kutoka GitHub (hurejea `dl.cbb.tools` ikiwa GitHub haijibu). GitHub huona anwani ya IP ya kifaa na kwamba inaomba metadata ya Connect Beyond Borders, lakini hakuna chochote kuhusu kikundi chako. Ili kutumia kioo maalum badala yake, endesha `sudo cbb update -mirror https://...`; kioo hakihitaji kuaminiwa kwa sababu sahihi bado zinathibitishwa.

Kumbukumbu za masasisho ya kiotomatiki huandikwa katika `update.log` ndani ya:

| Mfumo | Folda ya kumbukumbu za sasisho |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (bila root) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

Vifaa katika kikundi hushiriki taarifa za toleo jipya zaidi lililotiwa sahihi ambalo kimojawapo kimeona, kwa hiyo `cbb status` na programu za kompyuta hukuarifu sasisho linapopatikana. Kila kifaa bado huthibitisha sahihi chenyewe na kupakua kumbukumbu yake.

## Kukagua upakuaji

Kila kumbukumbu ya toleo hukaguliwa kwa njia tatu:

1. **Checksum (`SHA256SUMS`):** `get.sh` na `get.ps1` zote mbili huthibitisha kumbukumbu iliyopakuliwa dhidi ya faili ya `SHA256SUMS` ya toleo.
2. **Sahihi za matoleo za mradi:** Matoleo hutiwa sahihi kwa funguo za mzizi za mradi zilizo nje ya mtandao na ufunguo wa toleo (ambavyo havigusi CI kamwe): `keys.json` huthibitisha funguo za toleo chini ya funguo za mzizi za mradi, `release.json` huorodhesha ukubwa na hashi ya SHA-256 ya kila faili, na `stable.json` hutaja toleo thabiti la sasa ([Itifaki](../protocol.md), sehemu ya 16). `get.sh` (ikihusisha `openssl`) na `get.ps1` zote mbili hubeba funguo za mzizi zilizojengwa ndani za mradi na hukataa kusakinisha toleo lolote ambalo sahihi zake hazithibitishwi. `get.sh` hukagua ES256 na SLH-DSA-SHA2-128s zote mbili wakati OpenSSL 3.5 au mpya zaidi imesakinishwa (ES256 kwenye OpenSSL ya zamani zaidi); `get.ps1` hukagua ES256. Ili kusakinisha bila kukagua sahihi za mradi, weka `CBB_VERIFY=skip`.
3. **Uthibitisho wa asili ya ujenzi:** Kila faili ya toleo ina uthibitisho wa asili ya ujenzi wa GitHub unaoihusisha na mtiririko wa kazi wa matoleo wa hazina hii. Kwa [GitHub CLI](https://cli.github.com/) (`gh`), unaweza kuthibitisha faili yoyote kwa mkono:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   `get.sh` na `get.ps1` zote mbili huendesha ukaguzi huu kiotomatiki wakati `gh` imesakinishwa na kuingiliwa (`gh auth login`; kwa `get.sh` chini ya `sudo`, endesha `sudo gh auth login`). Weka `CBB_ATTESTATION=require` ili kukataa usakinishaji bila uthibitisho uliothibitishwa, au `CBB_ATTESTATION=skip` ili kuruka ukaguzi wa uthibitisho.

## Kuiondoa

Endesha amri ya kuondoa kwa mfumo wako:

| Mfumo | Amri au hatua |
|---|---|
| Linux na macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (bila root) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (au kwa `doas`) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (au `apk del cbb` ikiwa ilisakinishwa kutoka hazina) |
| Windows | Fungua **Settings > Apps > CBB > Uninstall**, au endesha `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` kama msimamizi wa mfumo |

Ikiwa ulisakinisha kwa Homebrew, endesha hati ya kuondoa kwanza kisha uendeshe `brew uninstall cbb`.

Kuondoa hufuta programu, huduma ya chinichini, wakala wa ubao wa kunakili, kipima muda cha sasisho, kanuni za ngome zilizoongezwa na kisakinishi, na (kwenye macOS) `/Applications/CBB.app` ikiwa ilisakinishwa kutoka `.pkg`. Funguo za kifaa chako na hali ya kikundi hubaki kwenye diski ili kusakinisha upya kujiunge tena na kikundi kilekile.

- **Futa funguo na hali ya kikundi pia:** Ongeza `--purge` kwenye mifumo ya Unix, au endesha `uninstall.ps1 -Purge` kwenye PowerShell ya msimamizi wa mfumo kwenye Windows. Baada ya hapo, ondoa kifaa kutoka kwenye kikundi ukitumia kifaa cha msimamizi (`sudo cbb remove NAME` au katika programu ya simu).
- **Ondoka kwenye kikundi bila kuondoa usakinishaji:** Endesha `sudo cbb leave` (bila `sudo` kwenye Linux bila root, au `cbb leave` kwenye terminal ya msimamizi wa mfumo kwenye Windows). Hii hufuta funguo za kifaa na faili za kikundi huku ikibakiza Connect Beyond Borders ikiwa imesakinishwa ili kifaa kiweze kujiunga na kikundi tena.
