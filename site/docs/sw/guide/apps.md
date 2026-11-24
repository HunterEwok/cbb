<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 36f5c3ab297b -->
# Programu

Connect Beyond Borders ina programu za simu, saa na kompyuta za mezani. Programu za simu hushikilia kikundi; programu za kompyuta ni dirisha la kuangalia huduma ambayo tayari inaendeshwa kwenye kompyuta.

| Programu | Mahali pa kuipata | Hali |
|---|---|---|
| Android | `cbb-X.Y.Z.apk` katika kila [toleo](https://github.com/HunterEwok/cbb/releases) | imejengwa na kujaribiwa katika CI, bado haijajaribiwa kwenye simu halisi |
| Android bila Google | `cbb-fdroid-X.Y.Z.apk`, na F-Droid itakapokubaliwa: programu ile ile bila saa ya Wear OS | imejengwa na kujaribiwa katika CI |
| iPhone na iPad | TestFlight, itakapofunguliwa | imejengwa na kujaribiwa katika CI; inaendeshwa kwenye iPhone ikijengwa kwa timu ya msanidi mwenyewe |
| Wear OS | `cbb-wear-X.Y.Z.apk`, huwekwa kwenye saa kutoka kwenye kompyuta kwa `adb install` kupitia utatuzi usiotumia waya wa saa, hadi programu iwe kwenye Google Play | imejengwa |
| Apple Watch | pamoja na programu ya iPhone | imejengwa; inaendeshwa kwenye Apple Watch pamoja na programu ya iPhone |
| Programu ya Mac | si ya kupakua bado: kwa sasa hujengwa kutoka `apps/macos` | imejengwa |
| Programu ya trei ya Linux na Windows | katika kumbukumbu za Windows na Linux za kila toleo, husakinishwa pamoja na huduma | imejengwa; imeendeshwa kwenye mashine pepe ya Windows 11 |

## Simu

### Anzisha kikundi

1. Fungua programu na ugonge **Unda kikundi**. Programu huunda ufunguo wa kikundi ndani ya chipu ya usalama ya simu (Secure Enclave kwenye iPhone, Keystore kwenye Android), huuliza jinsi ya kuhifadhi ufunguo wa urejeshaji (**Andika kwenye karatasi** au **Andika kwenye YubiKey**) na kufungua Mwanzo.
2. Gonga **+** kwenye Mwanzo (Ongeza kifaa). Huonyesha msimbo wa QR na tarakimu sita, na husubiri dakika chache skrini ikiwa wazi.
3. Kwenye kompyuta, [sakinisha](install.md) Connect Beyond Borders na uendeshe `sudo cbb pair -code`, au bofya **Jiunge na kikundi** kwenye programu yake ya trei au ya upau wa menyu, na uandike tarakimu sita. Kifaa kidogo hujiunga vivyo hivyo (`sudo -u cbb cbb pair -code` kwenye kifaa hicho). Simu mpya hugonga **Jiunge na kikundi** na kuchanganua msimbo, au kuandika tarakimu.

### Kila siku

- **Mwanzo** huonyesha kila kifaa cha kikundi, kama vigae au orodha, na kitone kinachoonyesha kama kiko mtandaoni. Kitufe kikubwa huchukua nakala kutoka kifaa kingine kama bado ni hai (dakika moja kwa chaguo-msingi; msimamizi huibadilisha kwenye Mipangilio), na vinginevyo hutuma kile ambacho simu inashikilia.
- **iPhone**: iOS huruhusu programu kutumia ubao wa kunakili ikiwa mbele tu, kwa hiyo iPhone husawazisha kwa ishara moja: kitendo cha "Sync clipboard" kwenye Back Tap au kitufe cha Action, kidhibiti cha Kituo cha Udhibiti, au wijeti ya skrini ya kwanza. Shiriki, Connect Beyond Borders hutuma maandishi au kiungo mara moja.
- **Android**: nakala kutoka kwenye kompyuta hufika zenyewe. Ili nakala za simu nazo zitumwe zenyewe, washa **Clipboard sync** (huduma ya ufikivu; programu hueleza inachosoma). Bila hiyo, mguso mmoja: kigae cha **Send clipboard** kwenye Mipangilio ya Haraka, Send kwenye arifa, wijeti ya skrini ya kwanza, au Shiriki na uteuzi wa maandishi, Connect Beyond Borders.
- **Arifa** husema kifaa kinapojiunga au kuondolewa, kinapokuwa msimamizi, au kitovu kisipojibu ukiwa mbali na nyumbani. Kila aina ina swichi yake kwenye Mipangilio.

### Vifaa

Gusa kifaa kuona aina yake, mfumo, toleo na jukumu. Kwenye simu ya msimamizi unaweza pia:

- **Kukipa jina jipya** au **Kukiondoa**; kuondoa huuliza mara moja, kisha uso wako, alama ya kidole au nambari ya siri. Kwenye Android kila sahihi huuliza: kuongeza kompyuta ya kwanza huuliza mara tano (vyeti vya kikundi chenyewe, kisha vya kompyuta), kila inayofuata mara mbili, na kila kitendo kingine mara moja; kila ombi husema ni la ngapi ("Signature 2 of 5"). Cheti cha kompyuta kinapohitaji kufanywa upya, au funguo za kikundi za kusawazisha ukiwa mbali na nyumbani, programu huuliza unapoifungua.
- **Make it an admin**, kwa kompyuta: kisha inaweza kuongeza na kuondoa vifaa kwa `sudo cbb pair` na `sudo cbb remove`. Ufunguo wake ni faili kwenye kompyuta, isipokuwa ni kompyuta ya Linux yenye TPM, na programu inakuonya kuhusu hilo kwanza; kwa hiyo chagua kompyuta unayoiamini, ikiwezekana inayowaka kila wakati na ambayo pia ni [kitovu](away-from-home.md).

### Simu ya pili, na simu iliyopotea

- **Simu ya pili**: gonga **+** kwenye simu ya kwanza; kwenye ya pili, gonga **Jiunge na kikundi** na uchanganue msimbo. Simu ya kwanza, mzizi, huifanya kuwa msimamizi, ili kupoteza simu moja kusipoteze chochote.
- **Simu iliyopotea**: kwenye simu yako nyingine, iondoe kwenye orodha ya vifaa. Kompyuta hubaki kwenye kikundi; kama simu iliyopotea ilikuwa mzizi, badala yake fungua urejeshaji kwenye simu nyingine na uipe ufunguo wa urejeshaji, ambao huiacha nje simu iliyopotea. Zaidi katika [kifaa kikipotea au kuibwa](lost-device.md).

### Mipangilio

- **Sync away from home**: tazama [Mbali na nyumbani](away-from-home.md#3-turn-it-on-on-the-other-devices).
- **Mandhari**: rangi kumi, kila moja ya giza na mwanga, au ile ya mfumo; kwenye Android pia rangi za mandhari ya skrini.
- **Lugha**: ya mfumo, Kiingereza au Kirusi.
- **Arifa**, swichi moja kwa kila aina.
- **Show error details**: gusa toleo mara saba ili kuonyesha swichi hii. Ikiwa imewashwa, hitilafu huonyesha chanzo chake chini ya ujumbe mfupi, jambo linalosaidia unaporipoti tatizo.

## Saa

Programu za Apple Watch na Wear OS huonyesha vifaa vya kikundi na kama viko mtandaoni, matukio ya karibuni, na swichi ya usawazishaji ukiwa mbali na nyumbani. Hufanya kazi kupitia simu iliyooanishwa.

## Programu za kompyuta

Programu ya Mac na programu ya trei ya Linux na Windows huonyesha yale yale kama simu: vifaa kama vigae, orodha au mizunguko, maelezo ya kifaa, **Send the clipboard** na **Fetch**, na swichi ya usawazishaji ukiwa mbali na nyumbani. Mabadiliko ya kikundi (kubadilisha jina, kuondoa, kufanya msimamizi) huomba nenosiri la msimamizi. **+** hufungua dirisha la kuoanisha lenye msimbo wa QR na tarakimu sita kwa kifaa kipya, na nje ya kikundi **Jiunge na kikundi** hujiunga na dirisha kwa tarakimu zake sita. Huduma inaendelea kusawazisha programu ikiwa wazi au la.

Kitu kisipofanya kazi, tazama [Utatuzi wa matatizo](troubleshooting.md).
