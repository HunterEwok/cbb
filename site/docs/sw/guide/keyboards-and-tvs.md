<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 30d3986ec6a3 -->
# Kibodi na televisheni

Kwa yeyote anayetaka kuandika nywila ndefu, URL, au utafutaji kwenye televisheni, kompyuta kibao, konsoli ya michezo, au kompyuta isiyoendesha Connect Beyond Borders. Kifaa kimoja katika kikundi chako hufanya kazi kama kibodi ya Bluetooth, kibodi ya USB, au rimoti ya televisheni ya mtandao.

Kibodi na rimoti za televisheni ni vipengele vya majaribio katika [Maabara](lab.md). Kwa hali ya sasa ya majaribio kwenye maunzi halisi, tazama [Usawa wa majukwaa](../parity.md#on-real-devices).

## Chagua njia

| Njia | Huandika kwenye | Mahitaji |
|---|---|---|
| [Simu kama kibodi ya Bluetooth](#a-phone-as-a-bluetooth-keyboard) | Chochote kinachokubali kibodi ya Bluetooth: televisheni, kompyuta kibao, simu, kompyuta, Steam Deck, PlayStation 5 | Simu ya Android 10 au mpya zaidi (yenye wasifu wa Bluetooth HID), Aurora OS, au HarmonyOS |
| [Kompyuta ya Linux kama kibodi ya Bluetooth](#a-linux-computer-as-a-bluetooth-keyboard) | Chochote kinachokubali kibodi ya Bluetooth LE | Linux yenye BlueZ 5.50 au mpya zaidi, adapta ya Bluetooth 4.0+, na `cbb-helper` |
| [Arduino Nano ESP32 kama kibodi ya USB au ya Bluetooth](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | Chochote chenye uingizaji wa kibodi ya USB au BLE — ikiwemo BIOS/UEFI, maombi ya usimbaji wa diski, Xbox, na Nintendo Switch kupitia USB | Arduino Nano ESP32 iliyowekwa programu dhibiti ya `esp32/` |
| [Kompyuta kama rimoti ya televisheni](#a-computer-as-the-tvs-remote) | Android TV, Google TV, Apple TV, au Roku kwenye mtandao wako wa nyumbani | Kompyuta ya Linux, macOS, Windows, au FreeBSD nyumbani yenye `cbb-helper` |

Xbox na Nintendo Switch hukubali kibodi za USB pekee, kwa hiyo tumia Arduino Nano ESP32 kwa konsoli hizo. iPhone, macOS, na Windows haziruhusu programu kufanya kazi kama kibodi ya Bluetooth.

## Linganisha mpangilio wa kibodi na kasi

Kibodi ya Bluetooth au USB hutuma misimbo halisi ya vitufe, si herufi: kifaa lengwa hugeuza kila msimbo wa kitufe kuwa herufi kwa kutumia mpangilio wake wa kibodi unaotumika.

- **Mpangilio:** Weka mpangilio wa kibodi katika Connect Beyond Borders ulingane na mpangilio unaotumika kwenye kifaa lengwa — **Kiingereza (Marekani)** (`us`) au **Kirusi** (`ru`). Ikiwa maandishi yako yana herufi ambayo mpangilio uliochaguliwa hauwezi kuandika, Connect Beyond Borders hukataa maandishi yote na kutaja herufi zisizotumika badala ya kuandika zisizo sahihi. Mistari mipya hutuma Enter na vichupo hutuma Tab.
- **Kasi:** Uandishi huwekwa kwa chaguo-msingi kuwa **herufi 20 kwa sekunde** kwa sababu baadhi ya televisheni huacha vitufe vinavyofika haraka zaidi. Punguza kasi (kwa mfano, hadi herufi 10 kwa sekunde) ikiwa herufi zinapotea.
- **Mpaka wa urefu:** Kibodi ya Bluetooth au USB huandika zisizozidi **herufi 4,096** kwa wakati mmoja.

## Simu kama kibodi ya Bluetooth

Inatumika kwenye simu za **Android**, **Aurora OS**, na **HarmonyOS**.

1. Fungua **CBB**, nenda **Mipangilio**, washa **Mipangilio ya kina**, kisha ufungue **Maabara > Kibodi ya Bluetooth**.
2. Washa **Fanya kazi kama kibodi ya Bluetooth** na uruhusu ruhusa ya Bluetooth ukiulizwa.
   - Kwenye Android, ikiwa programu inaripoti kuwa simu haiwezi kufanya kazi kama kibodi, mtengenezaji wa kifaa aliacha wasifu wa Bluetooth HID Device; tumia njia nyingine. Ikiwa programu nyingine inashikilia wasifu wa kibodi, izime huko kwanza kwa sababu Android huruhusu programu moja tu ya kibodi kwa wakati mmoja.
3. Oanisha kifaa lengwa na simu yako:
   - **Android:** Gusa **Fanya simu hii ionekane** (huonekana kwa dakika 2), oanisha simu yako kwenye mipangilio ya Bluetooth ya kifaa lengwa, kisha uchague kifaa lengwa chini ya **Andika kwenye**.
   - **Aurora OS:** Gusa **Fanya simu hii ionekane** (huonekana kwa dakika 2) na uunganishe na `CBB keyboard` kutoka mipangilio ya Bluetooth ya kifaa lengwa.
   - **HarmonyOS:** Swichi ya kibodi ikiwa imewashwa, unganisha na simu yako kwa jina lake la kifaa kutoka mipangilio ya Bluetooth ya kifaa lengwa.

   **Matokeo:** Skrini huonyesha `Imeunganishwa na …` (au `Kifaa kimeunganishwa.`).

4. Weka **Mpangilio wa kibodi wa kifaa** (`Kiingereza (Marekani)` au `Kirusi`) na, ikihitajika, **Kasi** (`10`, `20`, au `40` herufi kwa sekunde).
5. Elekeza kwenye sehemu ya maandishi kwenye kifaa lengwa, kisha uguse **Andika ubao wa kunakili** (kwenye HarmonyOS, gusa kitufe cha mfumo cha **Bandika** kilicho karibu na **Andika ubao wa kunakili**).

**Matokeo:** Simu yako huandika maandishi ya ubao wa kunakili katika sehemu iliyolengwa kwenye kifaa lengwa.

## Kompyuta ya Linux kama kibodi ya Bluetooth

Endesha amri hizi kwenye kompyuta ya Linux iliyosakinishwa `cbb-helper`:

1. Sajili kibodi ya Bluetooth LE na BlueZ:

   ```sh
   sudo cbb keyboard on -layout us
   ```

   Bendera za hiari: `-rate N` (herufi 5 hadi 60 kwa sekunde; chaguo-msingi 20) na `-pastes` (huelekeza [ubandikaji wa mbali](remote-paste.md) unaoingia kwenye kifaa cha Bluetooth kilichooanishwa badala ya skrini ya kompyuta hii; mistari mipya inahitaji `sudo cbb paste-receive on -enter`).

2. Fanya kompyuta ionekane kwa dakika 2:

   ```sh
   sudo cbb keyboard pair
   ```

3. Kwenye kifaa lengwa, fungua mipangilio yake ya Bluetooth na uoanishe na `CBB <your computer name>`.
4. Kagua muunganisho na uandike maandishi:

   ```sh
   cbb keyboard
   echo 'the text' | sudo cbb keyboard type
   ```

**Matokeo:** `cbb keyboard` huthibitisha kuwa kifaa kimeunganishwa, na `cbb keyboard type` huchapisha `Typed.` baada ya kutuma maandishi. Kibodi na panya za Bluetooth za kompyuta yako ya Linux huendelea kufanya kazi kawaida.

Ili kuzima kibodi ya Bluetooth, endesha `sudo cbb keyboard off`.

## Nano ESP32 kama kibodi ya USB au ya Bluetooth

[Programu dhibiti ya Arduino Nano ESP32](../../esp32/README.md) huendesha kibodi ya kuwasha ya USB na kibodi ya Bluetooth LE zinazodhibitiwa kutoka kiweko chake cha serial (kujiunga na kikundi na kusawazisha ubao wa kunakili viko kwenye [ramani ya njia](../roadmap.md)).

1. Unganisha na kiweko cha serial cha bodi na uchague hali:
   - **Kibodi ya USB:** Endesha `usb keyboard`. Bodi huanza upya huku mlango wake wa USB-C ukifanya kazi kama kibodi ya kuwasha (inayofanya kazi katika BIOS/UEFI, maombi ya usimbaji wa diski, na konsoli) na kiweko cha serial kwa wakati mmoja. Chomeka bodi kwenye kifaa lengwa.
   - **Kibodi ya Bluetooth LE:** Endesha `ble on`, kisha `ble pair`, na uoanishe `CBB Nano ESP32` katika mipangilio ya Bluetooth ya kifaa lengwa ndani ya dakika 2. Bodi hukumbuka hadi vifaa 4 vilivyooanishwa (`ble forget` huvifuta).
2. Weka mpangilio na kasi ya uandishi ya kifaa lengwa:

   ```text
   layout us
   rate 20
   ```

   Tumia `layout ru` kwa Kirusi.
3. Kwenye programu dhibiti iliyojengwa na `--features console-type`, andika maandishi kwa:

   ```text
   type hello world
   ```

**Matokeo:** Bodi huandika kwenye kifaa cha Bluetooth kilichounganishwa ikiwa kimoja kinatumika, au kwenye kibodi ya USB vinginevyo.

## Kompyuta kama rimoti ya televisheni

Kompyuta yoyote ya Linux, macOS, Windows, au FreeBSD yenye `cbb-helper` kwenye mtandao wako wa nyumbani inaweza kuandika kwenye Android TV, Google TV, Apple TV, au Roku kupitia mtandao wa ndani. Hakuna kinachosakinishwa kwenye televisheni, na televisheni haijiungi kamwe na kikundi chako. Tumia `sudo` kwenye mifumo ya Unix (acha `sudo` kwenye terminal ya msimamizi wa mfumo kwenye Windows).

### 1. Oanisha au ongeza televisheni

Chagua amri za televisheni yako:

- **Android TV au Google TV:**

  ```sh
  sudo cbb remote add -name living-room-tv living-room-tv.lan
  sudo cbb remote code
  ```

  Andika msimbo wa tarakimu 6 unaoonyeshwa kwenye skrini ya televisheni ndani ya dakika 2.

- **Apple TV:** Kwanza weka **Settings > AirPlay and HomeKit > Allow Access** kwenye Apple TV kuwa **Everyone on the Same Network** (**Only People Sharing This Home** hukataa uoanishaji). Kisha endesha:

  ```sh
  sudo cbb remote add -appletv -name lounge 192.168.1.30
  sudo cbb remote code
  ```

  Andika PIN ya tarakimu 4 inayoonyeshwa kwenye Apple TV ndani ya dakika 2.

- **Roku:** Itifaki ya Udhibiti wa Nje ya Roku (External Control Protocol) hutumia HTTP isiyosimbwa bila uoanishaji. Kwanza weka **Settings > System > Advanced system settings > Control by mobile apps** kwenye Roku kuwa **Enabled** au **Permissive**. Kisha iongeze kwa `-consent`:

  ```sh
  sudo cbb remote add -roku -consent 192.168.1.40
  ```

**Matokeo:** Endesha `cbb remote` bila hoja zozote ili kuhakikisha kuwa televisheni inaonekana kwenye orodha yako.

### 2. Andika kwenye televisheni au elekeza ubandikaji wa mbali

1. Fungua kisanduku cha utafutaji au sehemu ya maandishi kwenye televisheni kwa kutumia rimoti yake yenyewe.
2. Andika maandishi kutoka kwenye kompyuta:

   ```sh
   echo 'the film' | sudo cbb remote type
   ```

   Ongeza `-tv NAME` unapokuwa na zaidi ya televisheni moja iliyosanidiwa. Kwenye Android TV na Roku, mistari mipya hubonyeza Enter; kwenye Apple TV, mistari mipya hubaki ndani ya maandishi.

   **Matokeo:** Maandishi huonekana kwenye sehemu ya maandishi iliyolengwa kwenye televisheni na `cbb remote type` huchapisha `Typed.`

3. Kwa hiari, elekeza [ubandikaji wa mbali](remote-paste.md) unaoingia kutoka kwa wasimamizi wa kikundi chako kwenda kwenye televisheni (televisheni moja kwa wakati mmoja; mistari mipya inahitaji `sudo cbb paste-receive on -enter`):

   ```sh
   sudo cbb remote pastes living-room-tv on
   ```

Ili kusahau televisheni, endesha `sudo cbb remote remove NAME`. Ikiwa Android TV au Apple TV imewekwa upya au imesahau kompyuta yako, ioanishe tena.

## Usalama

- **Kibodi za Bluetooth:** Kibodi ya Bluetooth huandika popote kifaa kilichooanishwa kina lengo la kibodi. Oanisha tu na vifaa unavyokusudia kuvidhibiti, na sahau uoanishaji pande zote mbili unapoacha kuitumia.
- **Ubandikaji wa mbali kwa kibodi na televisheni:** Wakati uelekezaji wa kubandika kwa mbali umewashwa (`-pastes` au `cbb remote pastes TV on`), msimamizi yeyote katika kikundi chako anaweza kuandika kwenye kifaa hicho. Kuzima kubandika kwa mbali husimamisha uelekezaji pia.
- **Mtandao wa nyumbani pekee kwa televisheni:** `cbb remote` huunganisha tu na anwani zilizo kwenye mtandao wako wa nyumbani na hukataa anwani yoyote nje yake.
- **Hakuna nywila kwenda Roku:** Maandishi yanayotumwa kwa Roku hupita kwenye mtandao wako wa nyumbani kama HTTP wazi. Usitume kamwe nywila au siri nyingine kwa Roku.

Kwa bendera zote za CLI, tazama [Amri](../reference/cli.md). Kwa milango ya mtandao ya televisheni, tazama [Vifaa, milango na faili](../reference/devices.md#ports).
