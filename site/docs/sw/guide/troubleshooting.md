<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 50c1a7a6666c -->
# Utatuzi wa matatizo

Kwa yeyote ambaye vifaa vyake havisawazishi, vinashindwa kuoanishwa, au vinatoa hitilafu. Kila kipengee hapa chini kinaorodhesha **dalili**, **chanzo**, na **suluhisho**.

## Anza na uchunguzi

Kabla ya kubadilisha mipangilio, angalia kile Connect Beyond Borders inaripoti:

- **Kwenye programu ya simu au kompyuta:** Fungua **Mipangilio**, washa **Mipangilio ya kina**, na uangalie **Kwa nini haisawazishi** kwa maelezo ya maneno rahisi na hatua inayofuata. Ili kuonyesha hitilafu za kiufundi chini ya ujumbe mfupi, gusa **Toleo** mara saba katika **Mipangilio** na uwashe **Onyesha maelezo ya hitilafu**.
- **Kwenye terminal:** Endesha `cbb status` ili kuona kama huduma inaendeshwa, hali ya kikundi chako, vifaa vilivyounganishwa, na hali ya usawazishaji ukiwa mbali na nyumbani. Tanguliza amri yoyote kwa `CBB_DEBUG=1` (kwenye Windows PowerShell, endesha `$env:CBB_DEBUG = "1"` kwanza) ili kuchapisha hitilafu ya msingi:

  ```sh
  CBB_DEBUG=1 cbb status
  ```

- **Kagua kumbukumbu za huduma:** Kwenye Linux, endesha `journalctl -u cbb` kwa huduma na `journalctl --user` kwa wakala wa ubao wa kunakili wa eneo-kazi. Njia za kumbukumbu za macOS, Windows, FreeBSD, na OpenWrt ziko katika [Vifaa, milango na faili](../reference/devices.md#files-and-logs), na swichi za uchunguzi za kila sehemu ziko katika [Ujumbe wa hitilafu na maelezo yake](../reference/errors.md).

## Amri na huduma

### "the Connect Beyond Borders service is not running"

- **Chanzo:** Huduma ya chinichini imesimama au ilishindwa kuanza.
- **Suluhisho:** Anzisha huduma kwa mfumo wako wa uendeshaji na uchunguze kumbukumbu yake ikiwa itatoka tena:
  - **Linux:** `sudo systemctl start cbb` (bila root: `systemctl --user start cbb`)
  - **macOS:** `sudo launchctl kickstart -k system/tools.cbb`
  - **Windows (PowerShell ya msimamizi wa mfumo):** `Start-Service cbb`
  - **FreeBSD:** `sudo service cbb start`
  - **OpenWrt:** `/etc/init.d/cbb start`

### "permission denied" kwenye soketi ya udhibiti baada ya kusakinisha

- **Chanzo:** Kisakinishi kiliongeza akaunti yako ya mtumiaji kwenye kikundi `cbb` (`_cbb` kwenye macOS), na uanachama mpya wa kikundi huanza kufanya kazi baada ya kuingia kwako kunakofuata pekee.
- **Suluhisho:** Toka na uingie tena (kwenye Windows, fungua dirisha jipya la terminal). Hadi utakapoingia tena, endesha amri kwa `sudo cbb ...`.

## Vifaa havionani nyumbani

### `cbb status` inaonya kuwa vifaa vya nyumbani haviwezi kuunganishwa na kompyuta hii

- **Chanzo:** Ngome ya kompyuta inazuia **mlango wa TCP 8764** unaoingia (au mlango wako maalum wa mwanachama) au **mlango wa UDP 5353** (mDNS).
- **Suluhisho:** Endesha kisakinishi tena na ujibu `y` kwenye swali la ngome, au ongeza kanuni kwa mkono ukitumia amri zilizo katika [Kusakinisha: ngome](install.md#the-firewall).

### `cbb status` inasema "Quiet on" kwa mtandao wako wa nyumbani

- **Chanzo:** Kompyuta hujitangaza na kukubali miunganisho ya ndani kwenye mitandao ya nyumbani inayojulikana pekee. Ikiwa ulibadilisha kipanga njia chako au kubadilisha subnet, kompyuta inauchukulia mtandao kuwa usiojulikana.
- **Suluhisho:** Weka mtandao wa sasa kama mtandao wa nyumbani: endesha `sudo cbb network` kwenye kompyuta, au bofya **Huu ni mtandao wangu wa nyumbani** katika programu ya Mac au programu ya trei.

### Vifaa viko kwenye subnet au VLAN tofauti

- **Chanzo:** Ugunduzi wa mtandao wa ndani (mDNS) hauvuki vipanga njia kati ya subnet tofauti (kwa mfano, `192.168.0.x` na `192.168.20.x`).
- **Suluhisho:** Unganisha mitandao yote miwili kupitia kitovu ([Mbali na nyumbani](away-from-home.md)), endesha `cbb` kwenye kipanga njia kilichounganishwa na subnet zote mbili, au pitisha `-peer HOST:PORT` kwa huduma kwenye kifaa kidogo ([Vifaa vidogo](../../member/README.md#install)).

### Vifaa kwenye Wi-Fi haviwezi kuunganishwa kati yao kabisa

- **Chanzo:** Kipanga njia kimewasha **Guest Wi-Fi** au **AP / client isolation**, jambo linalozuia vifaa visivyotumia waya kuwasiliana moja kwa moja.
- **Suluhisho:** Hamisha vifaa vyako kwenye mtandao wako mkuu wa Wi-Fi ya nyumbani au zima client isolation kwenye kipanga njia.

### Vifaa viwili viko mtandaoni lakini havibadilishani nakala kamwe

- **Chanzo:** Kifaa kimoja kiko kwenye kikundi tofauti, **Sawazisha** imezimwa, au msimamizi alinyamazisha kifaa hicho.
- **Suluhisho:**
  - Kagua **Sawazisha** kwenye vifaa vyote viwili (`cbb status` au **Mwanzo** katika programu) na uhakikishe hakuna kifaa kilichonyamazishwa.
  - Kagua lebo ya kikundi katika `cbb status`. Ikiwa kompyuta iko kwenye kikundi kisicho sahihi, endesha `sudo cbb leave` juu yake, ioanishe na kikundi sahihi, na uondoe ingizo lake la zamani kutoka kwenye kikundi kisicho sahihi.

### `cbb status` au programu inasema kifaa hiki kiliondolewa kwenye kikundi

- **Chanzo:** Msimamizi aliondoa kifaa hiki, kwa hiyo wanachama wengine wote wa kikundi wanakataa miunganisho yake.
- **Suluhisho:** Endesha `sudo cbb leave` kwenye kompyuta (au gusa **Ondoka kwenye kikundi** katika programu ya simu au kompyuta), kisha uoanishe kifaa tena kama kifaa kipya.

## Kuoanisha kunashindwa

### Kuoanisha kunaripoti "wrong code" au dirisha linafungwa

- **Chanzo:** Kila dirisha la kuoanisha hukaa wazi kwa dakika 5 na hufungwa kiotomatiki baada ya majaribio 3 yasiyo sahihi.
- **Suluhisho:** Fungua dirisha jipya la kuoanisha (`sudo cbb pair` kwenye kompyuta ya msimamizi, au **+ > Ongeza kifaa** katika programu) na uweke msimbo mpya wa tarakimu 6 au uchanganue msimbo mpya wa QR.

### Simu haiwezi kufikia kompyuta baada ya kuchanganua msimbo wa QR

- **Chanzo:** Simu na kompyuta ziko kwenye mitandao tofauti, ngome ya kompyuta inazuia mlango wa TCP 8764, au ufikiaji wa Mtandao wa Ndani wa iOS umekataliwa.
- **Suluhisho:**
  1. Thibitisha kuwa vifaa vyote viwili viko kwenye Wi-Fi au LAN moja ya nyumbani.
  2. Hakikisha ngome ya kompyuta inaruhusu mlango wa TCP 8764 ([ngome](install.md#the-firewall)).
  3. Kwenye iPhone, washa **Settings > Privacy & Security > Local Network > CBB**.

## Kusawazisha ukiwa mbali na nyumbani

### Kifaa kilicho mbali hakiwezi kuunganishwa na kitovu

- **Chanzo:** Mojawapo ya matatizo manne ya kawaida:
  - Kipanga njia chako hakielekezi mlango wa UDP 8764 kwenye kitovu, ngome ya kitovu inaudondosha, au anwani ya umma iliyopewa `cbb global hub` iko nyuma ya carrier-grade NAT.
  - Kifaa kilicho mbali hakijakutana na kitovu kwenye mtandao wako wa nyumbani tangu usawazishaji ukiwa mbali na nyumbani uwashwe au tangu kitovu kibadilishe mipangilio yake ya handaki (`-no-obfuscate`, `-no-vless`).
  - Anwani ya IP ya nyumbani kwako imebadilika na kanuni ya mfumo ya mtandao unaotoka nje ya kompyuta bado inaruhusu anwani ya zamani pekee.
  - Mtandao unaotembelea unazuia trafiki ya WireGuard au UDP.
- **Suluhisho:**
  1. Endesha `cbb global` kwenye kifaa kilicho mbali na kwenye kitovu vyote viwili ili kusoma hitilafu halisi.
  2. Ikiwa nyumba yako iko nyuma ya carrier-grade NAT au uelekezaji wa milango unashindwa, badilisha kitovu kitumie kisambazaji (`sudo cbb global hub` kwa kisambazaji cha mradi; tazama [Mbali na nyumbani](away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)).
  3. Ikiwa `cbb global` inasema kanuni ya mfumo ya mtandao unaotoka nje iko nyuma, endesha `sudo cbb global allow` kwenye kompyuta hiyo.
  4. Ikiwa kifaa hakijawahi kukutana na kitovu nyumbani baada ya badiliko la mipangilio, kiunganishe na mtandao wako wa nyumbani mara moja (na ufungue programu ya simu kwa muda mfupi).
  5. Ikiwa mtandao unaotembelea unachuja VPN, hakikisha AmneziaWG na VLESS zimewashwa kwenye kitovu ([Mitandao inayozuia VPN](blocked-networks.md)). Ikiwa milango ya kuingilia ya kisambazaji cha mradi imepitwa na wakati, ingiza milango mipya iliyotiwa sahihi kwa `sudo cbb global entries import STRING`.
  6. Ili kuweka kumbukumbu za mikono ya salamu ya WireGuard kwenye Linux, weka `CBB_DEBUG=1` kwenye huduma na uianzishe upya:

     ```sh
     sudo systemctl edit cbb
     ```

     Ongeza mistari hii, hifadhi, na uanzishe upya:

     ```ini
     [Service]
     Environment=CBB_DEBUG=1
     ```

     ```sh
     sudo systemctl restart cbb
     ```

     Kisha chunguza `journalctl -u cbb`.

## Simu

### Android: "Restricted setting" inazuia kuwasha huduma ya ufikivu

- **Chanzo:** Android 13 na mpya zaidi huzuia ruhusa za ufikivu kwa programu zilizosakinishwa kutoka APK nje ya duka la programu.
- **Suluhisho:** Fungua **Settings > Apps > CBB** (Maelezo ya programu) kwenye Android, gusa menyu ya **⋮** kwenye kona ya juu, gusa **Ruhusu mipangilio iliyozuiliwa**, kisha uwashe **Usawazishaji wa ubao wa kunakili** katika mipangilio ya Ufikivu.

### Android: nakala kutoka kompyuta zinaacha kufika chinichini

- **Chanzo:** Uboreshaji wa betri ulisimamisha huduma ya mbele ya chinichini ya programu.
- **Suluhisho:** Fungua **Settings > Apps > CBB > Battery** kwenye Android na uweke kuwa **Unrestricted**.

### iPhone: iOS inaomba ruhusa ya kubandika kila mara unaposawazisha

- **Chanzo:** iOS huweka **Bandika kutoka Programu Nyingine** kuwa **Uliza** kwa chaguo-msingi.
- **Suluhisho:** Fungua **Settings > Apps > CBB > Paste from Other Apps** kwenye iPhone na uchague **Allow**.

### Aurora OS 5: ufunguo wa msimamizi umefungwa

- **Chanzo:** Majaribio saba yasiyo sahihi ya PIN ya msimamizi hufunga ufunguo wa msimamizi kabisa katika kipengele salama cha simu. Simu inabaki kwenye kikundi kama mwanachama wa kawaida.
- **Suluhisho:** Ondoka kwenye kikundi, sakinisha **CBB** upya, na ujiunge tena kama kifaa kipya.

## Bado umekwama

Fungua [suala kwenye GitHub](https://github.com/HunterEwok/cbb/issues) na ujumuishe:

- Matokeo ya `CBB_DEBUG=1 cbb status` (na `cbb global` kwa matatizo ya kusawazisha ukiwa mbali na nyumbani)
- Mistari husika kutoka kwenye kumbukumbu ya huduma au programu
- Mifumo ya uendeshaji na matoleo ya Connect Beyond Borders yanayohusika

Ondoa maandishi yoyote uliyonakili, anwani binafsi, au majina ya vifaa usiyotaka kushiriki. Ripoti udhaifu wa usalama kwa faragha kwa kufuata [SECURITY.md](../../SECURITY.md).
