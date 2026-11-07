<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# Kusakinisha

Copy Beyond Borders huendeshwa kama huduma ndogo ya chinichini kwenye kila kompyuta. Amri yake ni `cbb`. Kila njia iliyo hapa chini husakinisha programu ile ile; chagua unayopenda.

## Linux

Linux yoyote yenye systemd (x86-64, ARM64, ARMv7, ARMv6): laptopu, kompyuta ya mezani, Raspberry Pi, seva, Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

Kisha toka na uingie tena mara moja, ili mtumiaji wako aweze kutumia `cbb` bila `sudo`. Mashine isiyo na eneo-kazi hupata kunakili na kubandika ndani ya tmux kwa `--console` (`... | sudo sh -s -- --console`).

Kwenye eneo-kazi lenye GTK 4 na WebKitGTK 6.0 (x86-64 na ARM64) pia husakinisha programu ya trei, inayoanza pamoja na kipindi chako na iko kwenye menyu ya programu. Bila hivyo hutaja vifurushi vya kuongeza; kisha iendeshe tena ili kupata programu ya trei.

Kubandika kwa mbali kwenye GNOME na KDE huuliza mara moja, kwenye kisanduku cha mazungumzo kwenye kompyuta, kabla ya kubandika kwa kwanza kwa msimamizi kuweza kubonyeza vitufe. Ili kuruka kisanduku hicho, ongeza `--uinput` (`... | sudo sh -s -- --uinput`): msaidizi mdogo kisha hubonyeza vitufe vya kubandika (Shift+Insert na Enter) kwa niaba ya anayetumia skrini, kamwe si kwenye skrini ya kuingia au ya kufunga.

Vifaa vidogo vinavyopaswa kusawazisha tu, kama kipanga njia au Raspberry Pi Zero, vinaweza kutumia [mwanachama mwepesi](../../member/README.md) mwepesi zaidi badala yake: `... | sudo sh -s -- --lite`.

### Bila sudo (bila root)

Kwenye kompyuta ya Linux ambapo huwezi au hutaki kutumia `sudo`, isakinishe kwa mtumiaji wako mwenyewe, bila `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

Huendeshwa kama huduma yako ya chinichini wakati umeingia, na husawazisha kama mwanachama yeyote. Itumie tu pale usakinishaji wa kawaida hauwezekani: kila programu unayoendesha inaweza kunakili funguo zake, kwa hiyo kamwe haiwezi kuwa mzizi wa kikundi, msimamizi wala kitovu ([jinsi inavyofanya kazi](how-it-works.md#rootless-members)), na haina kanuni za ngome ya moto, wala TPM, wala `--console` au `--uinput`. Ili iendelee kufanya kazi baada ya kutoka, msimamizi wa mfumo huendesha `sudo loginctl enable-linger YOUR-USER` mara moja. Kuiondoa: `sh ~/.local/share/cbb/uninstall.sh`. Mwanachama mwepesi pia husakinishwa hivi, kwa `--lite --rootless` ([mwanachama mwepesi](../../member/README.md#without-sudo-rootless)).

### SteamOS (Steam Deck)

Badilisha kwenda Hali ya Eneo-kazi, fungua Konsole, mpe mtumiaji `deck` nenosiri mara moja kama hana (`passwd`), kisha endesha amri ile ile. SteamOS hubadilisha faili zake za mfumo kila inaposasishwa, kwa hiyo kisakinishi huweka Copy Beyond Borders katika `/opt/cbb` badala ya `/usr/local`, na kuiambia SteamOS ni faili zipi zake katika `/etc` za kuhifadhi (`/etc/atomic-update.conf.d/cbb.conf`). Hubaki imesakinishwa na ndani ya kikundi chake katika masasisho ya SteamOS.

- `cbb` iko kwenye njia ya Konsole mpya baada ya kutoka na kuingia tena. `sudo` haitafuti huko, kwa hiyo amri zinazoihitaji huchukua njia kamili: `sudo /opt/cbb/bin/cbb pair`.
- Katika Hali ya Eneo-kazi ubao wa kunakili husawazisha kama kwenye eneo-kazi lolote la KDE Plasma.
- Katika Hali ya Mchezo hakuna ubao wa kunakili wa eneo-kazi, kwa hiyo hakuna kinachosawazishwa huko; huduma inaendelea kufanya kazi na kuzikamata katika Hali ya Eneo-kazi.
- Kuiondoa: `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Apple silicon au Intel, macOS 14 au mpya zaidi: pakua `cbb-X.Y.Z.pkg` kutoka
[toleo la karibuni](https://github.com/HunterEwok/cbb/releases/latest) na uifungue. Inasakinisha programu
ya CBB kwenye upau wa menyu na huduma, zote zimesainiwa na mradi na kukaguliwa na Apple.

Au kwenye Terminal, bila programu, amri ile ile kama kwenye Linux:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

Au kwa Homebrew, ambayo pia huisasisha. Endesha mstari wa pili tena baada ya kila `brew upgrade`:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

Windows 10 (1809 au mpya zaidi) au 11, x86-64 au ARM64, kwenye PowerShell iliyofunguliwa kwa "Run as administrator":

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

Humruhusu mtumiaji aliyeingia kwenye skrini kutumia `cbb` (kwenye terminal mpya) na kumwanzishia wakala wa ubao wa kunakili. Amri zinazobadilisha kikundi huendeshwa kwenye terminal iliyofunguliwa kama msimamizi, mahali ambapo Linux na macOS hutumia `sudo`.

Pia husakinisha programu ya trei, inayoanza unapoingia na iko kwenye menyu ya Anza kama CBB.

Kwa winget, pindi kifurushi kitakapokuwa kwenye hazina ya winget:

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

Kipanga njia chenye OpenWrt 25.12 au mpya zaidi na nafasi ya programu ya MB 25 (MB 128 za flash au zaidi, au eMMC; MB 256 za RAM), kama root kupitia SSH:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Husakinisha `cbb` kama huduma inayofanya kazi kwenye eneo la `lan` pekee na isiyojibu kamwe kwenye `wan`. Funguo ziko katika `/etc/cbb`, ambayo sysupgrade huihifadhi; baada ya sysupgrade yenye usimamizi (ASU, owut), endesha amri tena. Eneo jingine, kama mtandao wa IoT, ngome ya moto na ukaguzi viko katika [vipanga njia na FreeBSD](../admin/routers.md#openwrt).

Au kutoka kwenye hazina yetu ya vifurushi, ambayo `apk upgrade` huiweka mpya. Usanifu wa hazina hufuata CPU ya kipanga njia (`grep DISTRIB_ARCH /etc/openwrt_release`): `arm64` kwa `aarch64_*`, `armv7` kwa `arm_cortex-a*` yenye `neon` au `vfp` kwenye jina, `mipsle` kwa `mipsel_*`, `mips` kwa `mips_*`, `amd64` kwa `x86_64`. Weka wako mahali pa `arm64` katika mstari wa pili:

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

`apk del cbb` huiondoa na kuacha funguo katika `/etc/cbb`.

## FreeBSD

FreeBSD 15, amd64 au arm64, kama root (kwa `sudo` au `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Husakinisha `cbb`, hati ya rc.d inayoendesha huduma kupitia daemon(8), na kuongeza mstari `cbb_enable="YES"` kwenye rc.conf. Funguo ziko katika `/var/db/cbb`.

Kwenye OPNsense kisakinishi hicho hicho pia huongeza ndoano ya programu-jalizi: huduma huonekana chini ya System > Diagnostics > Services, na kanuni zake za ngome ya moto (katika nanga ya pf `cbb`) hufuata kila upakiaji upya wa kichujio. Zima kirudiaji cha mDNS (Services > mDNS Repeater) wakati huduma inafanya kazi: vyote viwili vinahitaji mlango wa UDP 5353, na huduma hujibu mDNS yenyewe kwenye kila kiolesura cha nyumbani. pfSense haiungwi mkono: kisakinishi huendeshwa huko pia, lakini huchapisha kanuni za ngome ya moto za Firewall > Rules badala ya kuziongeza, na sasisho la pfSense linaweza kuondoa Copy Beyond Borders.

Kwenye eneo-kazi la FreeBSD (X11, au Wayland yenye itifaki ya data control, kama KDE, sway na Hyprland), kipindi huanzisha `cbb agent` kutoka XDG autostart na ubao wa kunakili hujiunga na kikundi; ingia tena baada ya usakinishaji. Kubandika kwa mbali huandika kupitia XTEST kwenye X11 na kibodi pepe kwenye maeneo-kazi ya wlroots; GNOME haikubali kubandika kwa mbali kwenye FreeBSD, kwa kuwa bila logind hakuna kinachoonyesha kama skrini yake imefungwa.

## Docker

Kwa NAS au seva ya nyumbani inayowaka kila wakati ([README ya taswira](../../packaging/docker/README.md); huchapishwa na kila toleo kuanzia 0.5). Hujiunga kama mwanachama wa kawaida: tengeneza kikundi kwenye simu au kompyuta unayoishikilia.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## Ngome ya moto

Copy Beyond Borders inahitaji mlango mmoja wa TCP, 8764, na mDNS (UDP 5353), vyote kutoka mtandao wa nyumbani pekee. Kisakinishi hupata ngome ya moto (ufw, firewalld, nftables au iptables kwenye Linux, pf au ipfw kwenye FreeBSD, ngome ya programu ya Mac, Windows Firewall), huorodhesha kila kanuni, na kuuliza `Add these rules now? [y/N]`:

- **Ndiyo**: huziongeza, huziweka mpya kwa kila sasisho na kuziondoa unapoondoa usakinishaji. Hakigusi kanuni nyingine kamwe.
- **Hapana** (chaguo-msingi, na pia pale ambapo hakuna terminal ya kuulizia): haiongezi chochote na huchapisha amri kamili, ili uziendeshe mwenyewe.
- `--express` (`-Express` kwenye Windows) huziongeza bila kuuliza; `--no-firewall` hujibu Hapana.

nftables na iptables hupata amri tu kila mara, kwa kuwa kanuni zinazoongezwa wakati wa kuendesha hazinusuriki kuwashwa upya huko. Kwenye FreeBSD, pf hupata kanuni katika nanga yake yenyewe, ambayo pf huisoma kupitia mistari mitatu iliyotiwa alama ambayo kisakinishi huiongeza mwishoni mwa `/etc/pf.conf` na kuiondoa tena; ipfw huzipata katika seti ya kanuni 17, zinazoongezwa tena kila inapoanza. Ukiwasha ngome ya moto baadaye, endesha kisakinishi tena.

**Mlango mwingine**, kama 8764 umekaliwa: `... | sudo sh -s -- --port 9000` (kwenye Windows, `$env:CBB_PORT = "9000"` kabla ya kisakinishi). Programu ya simu hujifunza mlango kutoka kwenye msimbo wa QR.

Chaguo zote za kisakinishi ziko katika [marejeo ya amri](../reference/cli.md#installers).

## Kusasisha

Matoleo husainiwa kuanzia 0.6. Ili kuhamia 0.6 kutoka toleo la awali, endesha amri ya usakinishaji tena; kuanzia hapo `cbb update` hufanya hivyo.

`sudo cbb update` (kwenye Windows `cbb update` kwenye terminal iliyofunguliwa kama msimamizi) husakinisha toleo jipya zaidi kwenye kompyuta au mwanachama mwepesi aliyesakinishwa kwa `get.sh`, `get.ps1` au kumbukumbu ya toleo; `cbb update -check` husema tu kama lipo. Mipangilio yako hubaki. Husakinisha tu toleo lililosainiwa na mradi, na kamwe si la zamani zaidi. Toleo jipya lisipoanza ndani ya dakika moja, lile la awali hurudi lenyewe. Jinsi inavyokagua saini imo katika [itifaki](../protocol.md), sehemu ya 16.

Visakinishi huuliza mara moja kama visasishe kiotomatiki (`--auto-update on|off`, au `-AutoUpdate on|off` na `$env:CBB_AUTO_UPDATE` kwenye Windows, ili ujibu mapema); `sudo cbb update -auto on|off` huibadilisha baadaye. Ikiwa imewashwa, kipima muda hukagua mara moja kwa siku kwa wakati wake: kipima muda cha systemd kwenye Linux, kazi ya launchd kwenye Mac, kazi iliyopangwa kama SYSTEM kwenye Windows, cron kwenye OpenWrt na FreeBSD. Kila ukaguzi hupakua faili ndogo zile zile kutoka GitHub (au kutoka `dl.cbb.tools` GitHub isipojibu), kwa hiyo GitHub hujua anwani ya kifaa hiki na kwamba kinatumia Copy Beyond Borders, kama kwa upakuaji wowote; hakitumi chochote kuhusu kikundi. `sudo cbb update -mirror https://...` huchukua masasisho kutoka kioo kingine badala yake, jambo ambalo halihitaji kuaminiwa, kwa kuwa saini hukaguliwa. Kumbukumbu ya kipima muda ni `update.log` katika `/var/lib/cbb-update` (Linux), `/etc/cbb-update` (OpenWrt), `/var/db/cbb-update` (FreeBSD), `/Library/Application Support/cbb-update` (Mac) au `C:\Program Files\cbb-update` (Windows).

Vifaa vya kikundi huambiana kuhusu toleo jipya zaidi lililosainiwa ambalo kimojawapo kimeliona, kwa hiyo ukaguzi wa kifaa kimoja unatosha kwa `cbb status` na programu ya trei kwenye vingine kusema kwamba toleo jipya limetoka ("Update to X" kwenye programu ya trei huendesha `cbb update` kama msimamizi). Kila kifaa bado hukagua saini chenyewe na kupakua kumbukumbu yake.

Kuendesha amri ile ile ya usakinishaji tena pia husasisha. Kwa Homebrew au winget, sasisha huko na uendeshe mstari wa pili tena; `cbb update` husema hivyo. Docker na kifurushi cha OpenWrt husasishwa kwa `docker compose pull` na `apk upgrade`.

## Kukagua faili uliyopakua

Visakinishi vya mstari mmoja hukagua upakuaji dhidi ya `SHA256SUMS` ya toleo. Kila faili ya toleo pia ina cheti cha asili ya ujenzi kinachoifunga na hazina hii na ujenzi uliolitengeneza; kwa [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

`get.sh` hukikagua chenyewe wakati `gh` imesakinishwa na kuingiliwa kwa root (`sudo gh auth login`); `CBB_ATTESTATION=require` hukataa kusakinisha bila hicho.

Matoleo pia husainiwa kwa funguo za mradi wenyewe, ambazo hazigusi CI kamwe (funguo za mzizi ziko kwenye funguo za maunzi zisizounganishwa, ufunguo wa toleo uko kwenye Secure Enclave ya mtunzaji): `keys.json` hutaja funguo za toleo chini ya funguo za mzizi za mradi, `release.json` huorodhesha kila faili ya toleo pamoja na hashi yake, na `stable.json` husema ni toleo lipi la sasa. Funguo za mzizi zikishajengwa ndani ya visakinishi, `get.sh` (pamoja na `openssl`) na `get.ps1` hukagua haya kabla ya kusakinisha, na kukataa toleo ambalo halijasainiwa; hadi hapo hukagua `SHA256SUMS` na cheti cha asili pekee. `CBB_VERIFY=skip` husakinisha bila ukaguzi.

## Kuiondoa

Kwenye Linux na Mac:

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

Kwenye SteamOS ni `sudo sh /opt/cbb/share/uninstall.sh`. Kwa Homebrew, endesha `brew uninstall cbb` baada yake.

Kwenye Windows: Mipangilio, Programu, "CBB", Ondoa.

Hii huondoa programu, huduma, kanuni za ngome ya moto zilizoongezwa na kisakinishi na, kwenye Mac, programu iliyosakinishwa na `.pkg`. Funguo za kifaa hubaki, kwa hiyo kusakinisha tena hukirudisha kwenye kikundi chake. Ili kuzifuta pia, ongeza `--purge` (`-Purge` kwenye Windows, kwa `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge`), kisha ondoa kifaa kutoka kwenye kikundi kupitia kifaa kingine (`sudo cbb remove NAME`, au kwenye simu). Ili kuondoka kwenye kikundi na kubaki na CBB, endesha badala yake `sudo cbb leave`: hufuta funguo na faili za kikundi, na kifaa kinaweza kujiunga na kikundi tena.
