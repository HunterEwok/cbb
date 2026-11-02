<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 3a3178c99395 -->
# Programu

Clipboard Bridge ina programu za simu, saa na kompyuta za mezani. Programu za simu hushikilia kikundi; programu za kompyuta ni dirisha la kuangalia huduma ambayo tayari inaendeshwa kwenye kompyuta.

| Programu | Mahali pa kuipata | Hali |
|---|---|---|
| Android | `clipboardbridge-X.Y.Z.apk` katika kila [toleo](https://github.com/HunterEwok/clipboardbridge/releases) | imejengwa na kujaribiwa katika CI, bado haijajaribiwa kwenye simu halisi |
| Android bila Google | `clipboardbridge-fdroid-X.Y.Z.apk`, na F-Droid itakapokubaliwa: programu ile ile bila saa ya Wear OS | imejengwa na kujaribiwa katika CI |
| iPhone na iPad | TestFlight, itakapofunguliwa | imejengwa na kujaribiwa katika CI, bado haijajaribiwa kwenye simu halisi |
| Wear OS | `clipboardbridge-wear-X.Y.Z.apk`, huwekwa kwenye saa kutoka kwenye kompyuta kwa `adb install` kupitia utatuzi usiotumia waya wa saa, hadi programu iwe kwenye Google Play | imejengwa |
| Apple Watch | pamoja na programu ya iPhone | imejengwa |
| Programu ya Mac | si ya kupakua bado: kwa sasa hujengwa kutoka `apps/macos` | imejengwa |
| Programu ya trei ya Linux na Windows | si ya kupakua bado: kwa sasa hujengwa kutoka `apps/desktop` | imejengwa |

## Simu

### Anzisha kikundi

1. [Sakinisha](install.md) Clipboard Bridge kwenye kompyuta na uendeshe `sudo cbb pair` hapo. Huonyesha msimbo wa QR.
2. Fungua programu na ugonge **Connect a new device**, kisha changanua msimbo. Programu huunda ufunguo wa kikundi ndani ya chipu ya usalama ya simu (Secure Enclave kwenye iPhone, Keystore kwenye Android), huongeza kompyuta na kufungua Mwanzo.
3. Ongeza kila kompyuta nyingine kwa **+** kwenye Mwanzo. Mwanachama mwepesi hujiunga vivyo hivyo (`sudo -u clipboardbridge cbb pair` kwenye kifaa hicho huonyesha msimbo wake).

Kamera isipoweza kutumika: kwenye iPhone, andika tarakimu sita ambazo kompyuta inaonyesha; kwenye Android, bandika maandishi ya msimbo wa QR, ambayo `cbb pair` pia huyachapisha.

### Kila siku

- **Mwanzo** huonyesha kila kifaa cha kikundi, kama vigae au orodha, na kitone kinachoonyesha kama kiko mtandaoni. Kitufe kikubwa hutuma kile ambacho simu inashikilia, au huleta nakala ya karibuni ya kompyuta kama ilifanywa muda mfupi uliopita.
- **iPhone**: iOS huruhusu programu kutumia ubao wa kunakili ikiwa mbele tu, kwa hiyo iPhone husawazisha kwa ishara moja: kitendo cha "Sync clipboard" kwenye Back Tap au kitufe cha Action, kidhibiti cha Kituo cha Udhibiti, au wijeti ya skrini ya kwanza. Shiriki, Clipboard Bridge hutuma maandishi au kiungo mara moja.
- **Android**: nakala kutoka kwenye kompyuta hufika zenyewe. Ili nakala za simu nazo zitumwe zenyewe, washa **Send my copies by themselves** (huduma ya ufikivu; programu hueleza inachosoma). Bila hiyo, mguso mmoja: kigae cha **Send clipboard** kwenye Mipangilio ya Haraka, Send kwenye arifa, wijeti ya skrini ya kwanza, au Shiriki na uteuzi wa maandishi, Clipboard Bridge.
- **Arifa** husema kifaa kinapojiunga au kuondolewa, kinapokuwa msimamizi, au kitovu kisipojibu ukiwa mbali na nyumbani. Kila aina ina swichi yake kwenye Mipangilio.

### Vifaa

Gusa kifaa kuona aina yake, mfumo, toleo na jukumu. Kwenye simu ya msimamizi unaweza pia:

- **Kukipa jina jipya** au **Kukiondoa**; kuondoa huuliza mara moja, kisha uso wako, alama ya kidole au nambari ya siri.
- **Make it an admin**, kwa kompyuta: kisha inaweza kuongeza na kuondoa vifaa kwa `sudo cbb pair` na `sudo cbb revoke`. Ufunguo wake ni faili kwenye kompyuta, isipokuwa ni kompyuta ya Linux yenye TPM, na programu inakuonya kuhusu hilo kwanza; kwa hiyo chagua kompyuta unayoiamini, ikiwezekana inayowaka kila wakati na ambayo pia ni [kitovu](away-from-home.md).

### Simu ya pili, na simu iliyopotea

- **Simu ya pili**: kwenye simu hiyo gusa **I already use Clipboard Bridge on another phone**; huonyesha msimbo wa QR, ambao simu ya kwanza huuchanganua kwa **+**. Simu ya kwanza, mzizi, huifanya msimamizi, ili kupoteza simu moja kusipoteze chochote.
- **Simu iliyopotea**: kwenye simu yako nyingine, iondoe kwenye orodha ya vifaa. Kompyuta hubaki kwenye kikundi; kama simu iliyopotea ilikuwa mzizi, simu nyingine huchukua kikundi katika hatua ile ile. Zaidi katika [kifaa kikipotea au kuibwa](lost-device.md).

### Mipangilio

- **Sync away from home**: tazama [Mbali na nyumbani](away-from-home.md#3-turn-it-on-on-the-other-devices).
- **Mandhari**: rangi kumi, kila moja ya giza na mwanga, au ile ya mfumo; kwenye Android pia rangi za mandhari ya skrini.
- **Lugha**: ya mfumo, Kiingereza au Kirusi.
- **Arifa**, swichi moja kwa kila aina.
- **Show error details**: gusa toleo mara saba ili kuonyesha swichi hii. Ikiwa imewashwa, hitilafu huonyesha chanzo chake chini ya ujumbe mfupi, jambo linalosaidia unaporipoti tatizo.

## Saa

Programu za Apple Watch na Wear OS huonyesha vifaa vya kikundi na kama viko mtandaoni, matukio ya karibuni, na swichi ya usawazishaji ukiwa mbali na nyumbani. Hufanya kazi kupitia simu iliyooanishwa.

## Programu za kompyuta

Programu ya Mac na programu ya trei ya Linux na Windows huonyesha yale yale kama simu: vifaa kama vigae, orodha au mizunguko, maelezo ya kifaa, **Send the clipboard** na **Fetch**, na swichi ya usawazishaji ukiwa mbali na nyumbani. Mabadiliko ya kikundi (kubadilisha jina, kuondoa, kufanya msimamizi) huomba nenosiri la msimamizi. Kuongeza kifaa bado hufanyika kwenye terminal (`sudo cbb pair`). Huduma inaendelea kusawazisha programu ikiwa wazi au la.

Kitu kisipofanya kazi, tazama [Utatuzi wa matatizo](troubleshooting.md).
