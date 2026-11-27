<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: b8e7e372d74f -->
# Programu

Kwa yeyote anayetumia programu za Connect Beyond Borders kwenye simu, kompyuta kibao, saa, TV, au kompyuta. Kwa kusakinisha huduma ya chinichini kwenye kompyuta, vipanga njia, na seva, tazama [Kusakinisha](install.md). Kwa maelezo ya kihandisi, tazama [Vipimo vya programu](../apps.md).

Connect Beyond Borders hutoa programu asilia kwa simu, kompyuta kibao, saa, Android TV, na kompyuta za mezani. Programu za simu zinaweza kushikilia ufunguo mkuu wa kikundi na kusimamia vifaa; programu za kompyuta hutoa dirisha na ikoni ya menyu juu ya huduma ya chinichini inayoendeshwa kwenye kompyuta hiyo.

## Programu zinazopatikana

| Programu | Mahali pa kuipata | Maelezo |
|---|---|---|
| **Android** (Android 10 au mpya zaidi) | `cbb-X.Y.Z.apk` katika kila [toleo la GitHub](https://github.com/HunterEwok/cbb/releases) | Inajumuisha msaada wa saa ya Wear OS, kujisasisha yenyewe, na arifa za kusukuma |
| **Android bila Google** (toleo la F-Droid) | `cbb-fdroid-X.Y.Z.apk` katika kila [toleo la GitHub](https://github.com/HunterEwok/cbb/releases) | Ujenzi unaoweza kuzalishwa upya bila huduma za Google Play; hutumia UnifiedPush kwa arifa programu ikiwa imefungwa na huacha Wear OS |
| **Android TV, Google TV, na Fire OS** | APK ileile ya Android (`cbb-X.Y.Z.apk` au `cbb-fdroid-X.Y.Z.apk`) | Kiolesura cha D-pad; hujiunga kama mwanachama wa kupokea tu |
| **iPhone na iPad** (iOS 17 au mpya zaidi) | TestFlight (unapoalikwa) au iliyojengwa kutoka `apps/ios` kwa Xcode | Swichi ya Control Center inahitaji iOS 18 au mpya zaidi |
| **Apple Watch** (watchOS 10 au mpya zaidi) | Imejumuishwa na programu ya iPhone | Hufanya kazi kupitia iPhone iliyooanishwa |
| **Wear OS** (Wear OS 3 au mpya zaidi) | `cbb-wear-X.Y.Z.apk` katika kila [toleo la GitHub](https://github.com/HunterEwok/cbb/releases) (sakinisha kwa `adb install`) | Hufanya kazi kupitia simu ya Android iliyooanishwa (toleo kamili) |
| **Aurora OS na Sailfish OS** | Imejengwa kutoka `apps/silica` (RPM zilizotiwa sahihi kwa Aurora OS 5.1.5) | Huhifadhi funguo za msimamizi katika OP-TEE nyuma ya PIN ya programu kwenye Aurora 5; funguo za faili kwenye Aurora 4 na Sailfish OS |
| **HarmonyOS** (HarmonyOS 5 au mpya zaidi, simu, kompyuta kibao, na saa) | Imejengwa kutoka `apps/harmony` | Huhifadhi funguo katika HUKS; programu ya saa hufanya kazi kupitia simu ya HarmonyOS iliyooanishwa |
| **Programu ya Mac** (macOS 14 au mpya zaidi) | `cbb-X.Y.Z.pkg` katika kila [toleo la GitHub](https://github.com/HunterEwok/cbb/releases) | Programu ya upau wa menyu inayosakinishwa pamoja na huduma ya chinichini |
| **Programu ya trei ya Linux na Windows** | Imejumuishwa katika kumbukumbu za matoleo ya Windows na Linux (x86-64, ARM64) | Husakinishwa kiotomatiki pamoja na huduma (inahitaji GTK 4 na WebKitGTK 6.0 kwenye Linux) |

Ili kuona ni programu zipi zimejaribiwa kwenye maunzi halisi dhidi ya viigaji na CI, tazama [Usawa wa majukwaa](../parity.md#on-real-devices).

## Simu

### Anzisha au jiunge na kikundi

Unapofungua programu bila kikundi kilichosanidiwa, una chaguo tatu:

- **Unda kikundi:** Programu inaunda ufunguo mkuu wa kikundi ndani ya maunzi ya usalama ya simu yako (Secure Enclave kwenye iPhone, Keystore kwenye Android, OP-TEE kwenye Aurora OS 5, au HUKS kwenye HarmonyOS) na kukuomba uthibitishe kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN ya programu yenyewe. Kisha inaonyesha **ufunguo wa urejeshaji** wa kikundi mara moja na kutoa chaguo la **Andika kwenye karatasi**, **Andika kwenye YubiKey** (kupitia NFC au USB-C inapoungwa mkono), au vyote viwili. Baada ya kuuhifadhi, programu inafungua dirisha la kuoanisha la **Ongeza kifaa**.
- **Jiunge na kikundi:** Huchanganua msimbo wa QR unaoonyeshwa na **Ongeza kifaa** kwenye simu iliyopo au kompyuta ya msimamizi kwenye mtandao wako wa nyumbani, au hukuruhusu kuandika tarakimu zake sita. Simu hujiunga kama mwanachama kila mara; kifaa kikuu kinaweza kuipandisha cheo kuwa msimamizi baadaye.
- **Jiunge kwa mwaliko:** Huchanganua msimbo wa QR wa mwaliko, hubandika maandishi yake, au hufungua faili ya mwaliko ili kujiunga na kikundi ukiwa mbali na nyumbani kupitia kitovu cha kikundi.

Ili kuongeza kifaa kutoka **Mwanzo** kwenye kifaa kikuu au simu ya msimamizi, gusa **+** na uchague **Ongeza kifaa** (huonyesha msimbo wa QR na tarakimu sita kwa dakika tano) au **Tuma mwaliko** (kwa kifaa kilicho mbali na nyumbani).

### Usawazishaji wa kila siku

Skrini ya **Mwanzo** huonyesha vifaa vingapi viko mtandaoni pamoja na swichi mbili:

- **Sawazisha** (ikoni ya nyumba): Gusa ili kuzima au kuwasha usawazishaji kwa simu hii. Gusa na ushikilie ili kusitisha usawazishaji kwa dakika 15, saa 1, saa 8, au hadi ukiwashe tena. Wakati usawazishaji umezimwa, ubao wako wa kunakili unabaki wa faragha kwenye simu hii.
- **Kila mahali** (ikoni ya dunia): Huwasha au kuzima usawazishaji ukiwa mbali na nyumbani. Wakati **Sawazisha** imezimwa, **Kila mahali** husubiri hadi uwashe **Sawazisha** tena.

Chini ya kichwa, **Mwanzo** huonyesha taarifa zozote za kikundi, nakala ya karibuni iliyopokelewa (ikiwa na kitufe cha **Nakili** ili kuiweka tena kwenye ubao wako wa kunakili), na vifaa vya kikundi chako kama vigae au orodha. Kila kigae cha kifaa huonyesha hali yake ya mtandaoni kama kitone na pia kama maandishi kwenye ukurasa wake wa maelezo.

Jinsi kunakili na kubandika vinavyofanya kazi inategemea mfumo wa uendeshaji wa simu yako:

- **Kufungua programu (simu zote):** Unapofungua **CBB** au kurudi kwake kutoka chinichini, hutuma ubao wako wa kunakili ikiwa ulinakili kitu kipya; vinginevyo huleta nakala ya karibuni zaidi ya kikundi. Programu ikibaki wazi kwenye skrini, nakala zinazoingia huingia kwenye ubao wako wa kunakili kiotomatiki.
- **iPhone:** iOS huruhusu programu kusoma ubao wa kunakili zikiwa mbele pekee. Wakati wa usanidi wa kwanza, ruhusu **Bandika kutoka Programu Nyingine** katika Mipangilio ya iOS ili iOS isiulize kila mara (ukikataa, kitufe cha kubandika cha mfumo huonekana kwenye **Mwanzo**). Nje ya programu, badilishana ubao wako wa kunakili na kikundi kwa ishara moja ukitumia njia ya mkato ya **Sawazisha ubao wa kunakili** (iliyowekwa kwenye Back Tap au kitufe cha Kitendo) au wijeti ya skrini ya mwanzo ya **Sawazisha ubao wa kunakili**. Tumia kidhibiti cha **Sawazisha** katika Control Center (iOS 18 au mpya zaidi) kuwasha au kuzima usawazishaji. **Shiriki → Connect Beyond Borders** huweka kwenye foleni maandishi, viungo, picha, au faili (hadi MB 50 kwa pamoja) na kuzituma utakapofungua **CBB** tena. Kwenye iOS 17 au mpya zaidi, Dynamic Island na Skrini ya Kufunga huonyesha kuoanisha kunakoendelea, muda wa muunganisho wa handaki, na uthibitisho wa usawazishaji (kamwe si maandishi ya ubao wa kunakili).
- **Android:** Nakala kutoka kwenye kompyuta zako hufika kwenye ubao wa kunakili wa simu yako kiotomatiki chinichini. Ili kutuma nakala kutoka simu yako kiotomatiki pia, washa **Usawazishaji wa ubao wa kunakili** katika **Mipangilio** (huduma ya ufikivu; kwenye Android 13 au mpya zaidi, usakinishaji wa APK unahitaji **Ruhusu mipangilio iliyozuiliwa** katika Maelezo ya programu kwanza). Bila **Usawazishaji wa ubao wa kunakili**, tuma kwa mguso mmoja ukitumia:
  - **Tuma** kwenye arifa inayoendelea ya CBB
  - Wijeti ya skrini ya mwanzo ya **Tuma ubao wa kunakili**
  - **Shiriki → Connect Beyond Borders** au menyu ya uteuzi wa maandishi (hadi MB 100 kwa faili)
  - Kipengee cha kizinduzi cha **cbb send** (kinachoweza kutumika na Pixel Quick Tap au Samsung Back-Tap)
  - Kigae cha **Sawazisha** katika Mipangilio ya Haraka ya Android huwasha au kuzima usawazishaji (bonyeza kwa muda mrefu ili kufungua programu).
- **Aurora OS na HarmonyOS:** Kufungua programu husawazisha kama ilivyo hapo juu. **Shiriki → Connect Beyond Borders** hutuma maandishi, picha, na faili (hadi MB 50 kwa pamoja). Aurora OS huonyesha hali na vitendo vya haraka vya usawazishaji kwenye jalada lake la programu; HarmonyOS inajumuisha wijeti ya skrini ya mwanzo na hali ya Live View.

Kwa picha, maandishi yenye muundo, na mahali faili zilizopokelewa zinapohifadhiwa, tazama [Picha, faili na maandishi yenye muundo](images-and-files.md).

### Kupanga vifaa

Unaweza kupanga vifaa vyako kwa mpangilio wako mwenyewe na kuvigawa katika **mikusanyiko** (kwa mfano, "Ofisi" au "Nyumbani"). Mpangilio wako na mikusanyiko hubaki kwenye kifaa hicho pekee na kamwe havishirikiwi na kikundi wala seva yoyote.

- Badilisha kati ya **Vigae** na **Orodha** (na **Obiti** kwenye kompyuta kibao na kompyuta za mezani) kutoka kwenye menyu kwenye **Mwanzo**.
- Anzisha **Panga vifaa** kutoka kwenye menyu (au bonyeza kigae kwa muda mrefu) ili kuburuta vifaa katika mpangilio au kuvidondosha kwenye mikusanyiko, au tumia **Rudi kwenye mpangilio wa kikundi** ili kuweka upya.
- Kikundi kinapokuwa na vifaa zaidi ya 12, **Mwanzo** huonyesha upau wa utafutaji na vichujio vya **Mtandaoni** / **Inahitaji uangalifu**.

### Kusimamia vifaa

Gusa kifaa chochote kwenye **Mwanzo** ili kuona hali yake, jukumu lake, mfumo wake wa uendeshaji, na toleo la Connect Beyond Borders, pamoja na maelezo ya ziada ya kiufundi (aina ya kifaa, anwani ya MAC, kitambulisho cha kifaa) chini ya **Zaidi**.

Ikiwa simu yako ni kifaa kikuu au msimamizi, ukurasa wa kifaa hukuruhusu:

- **Sawazisha** au **Nyamazisha / Ondoa unyamazishaji:** Washa au zima usawazishaji kwenye kompyuta iliyounganishwa, au nyamazisha kifaa chochote kwa dakika 15, saa 1, saa 8, au hadi msimamizi aondoe unyamazishaji (unaweza pia kunyamazisha moja kwa moja kutoka kitufe cha kona kwenye kigae cha kifaa).
- **Bandika:** Tuma maandishi, picha, au faili moja kwa moja kwenye programu iliyolengwa kwenye kompyuta iliyowasha kubandika kwa mbali ([Kubandika kwa mbali](remote-paste.md)).
- **Vitendo vya haraka:** Endesha vitendo vilivyoruhusiwa kama kufunga au kulaza kompyuta ([Vitendo vya haraka](quick-actions.md)).
- **Badilisha jina:** Badilisha jina la kifaa katika kikundi kizima.
- **Kifanye msimamizi** (kifaa kikuu pekee): Ruhusu simu nyingine au kompyuta kuongeza na kuondoa vifaa. Mac zenye Apple silicon au chipu ya T2 huhifadhi funguo za msimamizi kwenye Secure Enclave, na kompyuta za Linux na Windows zenye TPM huzihifadhi kwenye TPM. Ikiwa kompyuta huhifadhi funguo zake kwenye faili, programu hukuonya kabla ya kuipandisha cheo ([Funguo na uthibitisho](keys.md#the-three-levels)).
- **Kifanye kitovu:** Badilisha kompyuta ya msimamizi kuwa kitovu kwa ajili ya kusawazisha ukiwa mbali na nyumbani (simu kamwe si kitovu).
- **Gandisha / Yeyusha:** Gandisha kompyuta ya msimamizi iliyoibiwa ili hakuna kitu kinachotiwa sahihi nacho kinachohesabika hadi kifaa kikuu kikiyeyushe au kukiondoa.
- **Ondoa:** Ondoa kifaa kwenye kikundi mara moja.

Kila kitendo kinachobadilisha kikundi huomba uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi. Kwenye Aurora OS 5, kipengele salama cha simu hutekeleza PIN hiyo, na PIN saba zisizo sahihi hufunga ufunguo wa msimamizi kabisa (simu inabaki kwenye kikundi kama mwanachama). Kwenye kifaa kikuu, programu pia huomba kufanya upya vitambulisho vya seva vya kikundi vya kusawazisha ukiwa mbali na nyumbani kila baada ya siku 30.

### Simu ya pili na simu iliyopotea

- **Ongeza simu ya pili:** Gusa **+** kwenye simu yako kuu, kisha uguse **Jiunge na kikundi** kwenye simu ya pili na uchanganue msimbo wa QR. Simu ya pili inajiunga kama mwanachama. Ifungue kwenye **Mwanzo** kwenye simu yako kuu na uguse **Kifanye msimamizi** ili uwe na simu ya pili ya msimamizi.
- **Simu ikipotea:** Iondoe kutoka **Mwanzo** kwenye simu nyingine ya msimamizi. Vifaa vyako vingine hubaki kwenye kikundi. Ikiwa simu iliyopotea ilikuwa **kifaa kikuu**, fungua **Mipangilio > Hamishia kikundi kwenye simu hii** kwenye kifaa kingine cha kikundi, weka ufunguo wako wa urejeshaji (karatasi au YubiKey), na uache simu iliyopotea bila alama ili kikundi kiikatae. Tazama [Kifaa kikipotea](lost-device.md).

### Mipangilio

Mipangilio ya msingi huonekana kwanza kwenye skrini ya **Mipangilio**:

- **Mwonekano na mandhari:** Chagua mwonekano wa **Mfumo**, **Giza**, au **Mwanga** na mojawapo ya **mandhari kumi na moja** (Ubao, Ramani, Sahihi, Kioo, Laini, Uswisi, Maunzi, Art Deco, Kioo kiowevu, Terminal, na Zamani). Android 12 na mpya zaidi pia hutoa **Material You** (rangi za mandhari ya skrini); Aurora OS hufuata mandhari ya mfumo.
- **Lugha:** Fuata lugha ya mfumo au chagua kutoka lugha nane: Kiingereza, Kichina (Kilichorahisishwa), Kihispania, Kirusi, Kiarabu, Kiswahili, Kiebrania, na Kihindi. Kiarabu na Kiebrania hupanga kiolesura kutoka kulia kwenda kushoto.
- **Arifa:** Washa au zima swichi moja moja kwa vifaa vinavyojiunga au kuondoka, mabadiliko ya wasimamizi, ugandishaji, mabadiliko ya kifaa kikuu, na matatizo ya muunganisho wa kitovu. Kwenye iPhone na Android, **Niarifu programu ikiwa imefungwa** huwasha arifa zilizofungwa zinazoiamsha simu bila kufichua nakala zako.
- **Ufunguo wa urejeshaji** (kwenye kifaa kikuu) au **Hamishia kikundi kwenye simu hii** (kwenye simu nyingine).
- **Ondoka kwenye kikundi:** Hufuta funguo za simu hii na data ya kikundi huku ikibakiza mapendeleo yako.
- **Kuhusu na maelezo ya hitilafu:** Gusa safu ya **Toleo** mara saba ili kufichua **Onyesha maelezo ya hitilafu**, ambayo huonyesha chanzo chini ya ujumbe mfupi wa hitilafu unaporipoti tatizo. Kwenye Android (APK ya toleo kamili), **Kuhusu** pia hujumuisha ukaguzi wa masasisho na mipangilio ya masasisho ya kiotomatiki.

Washa **Mipangilio ya kina** ili kufikia:

- **Kwa nini haisawazishi:** Hueleza kwa maneno rahisi kwa nini kifaa hiki hakisawazishi na la kufanya baadaye.
- **Mbali na nyumbani** na **Relei pofu:** Huonyesha hali ya handaki na huruhusu kifaa kikuu kusanidi relei pofu kwa vikundi visivyo na kitovu ([Mbali na nyumbani](away-from-home.md)).
- **Kikundi** (wasimamizi pekee): Weka **Muda wa nakala** (dakika 1 hadi saa 1; dakika 5 kwa chaguo-msingi), **Muda wa siri** (sekunde 5 hadi dakika 1; sekunde 60 kwa chaguo-msingi), na **Funguo za msimamizi** (kiwango cha funguo cha kikundi, kwenye kifaa kikuu).
- **Maabara** (Android, Aurora OS, na HarmonyOS): Vipengele vya majaribio kama kibodi ya Bluetooth ([Maabara](lab.md)).

### Kompyuta kibao na simu zinazokunjika

Kwenye skrini pana—iPad, kompyuta kibao za Android, kompyuta kibao za Aurora, kompyuta kibao za HarmonyOS, na simu zinazokunjika zikiwa zimekunjuliwa—programu hubadilika kiotomatiki hadi mwonekano uliogawanyika wenye upau wa pembeni (sehemu za **Vifaa vyote**, **Inahitaji uangalifu**, mikusanyiko, na mipangilio), chaguo la mpangilio wa **Obiti**, kidirisha cha maelezo ya kifaa upande kwa upande, njia za mkato za kibodi, na kuburuta na kudondosha (dondosha maandishi au faili kwenye kigae cha kifaa ili kubandika kwa mbali, au pembeni mwa vigae ili kunakili kwenye kikundi). Kwenye dirisha jembamba, kama hali ya skrini iliyogawanyika, hurudi kwenye mpangilio wa simu.

### Android TV

Kusakinisha APK ya Android kwenye Android TV, Google TV, au Fire OS hutoa kiolesura kinachoendeshwa kwa D-pad. TV hujiunga na kikundi kwa kuandika msimbo wa kuoanisha wa tarakimu sita kutoka simu au kompyuta ya msimamizi na huendeshwa kama mwanachama wa kupokea tu.

## Saa

Programu za **Apple Watch**, **Wear OS**, na **saa ya HarmonyOS** hufanya kazi kupitia simu yake iliyooanishwa na kamwe hazishikilii ubao wako wa kunakili. Kila programu ya saa huonyesha:

- Vifaa vingapi viko mtandaoni na orodha ya vifaa (iliyopangwa kulingana na mikusanyiko ya simu yako)
- Matukio ya karibuni ya kikundi
- Swichi za simu yako za **Sawazisha** (nyumba) na **Kila mahali** (dunia)

## Programu za kompyuta

**Programu ya Mac** (upau wa menyu) na **programu ya trei ya Linux na Windows** (trei ya mfumo) huunganishwa na huduma ya chinichini ambayo tayari inaendeshwa kwenye kompyuta yako. Ubao wako wa kunakili husawazisha kiotomatiki iwe dirisha la programu liko wazi au limefungwa, kwa hiyo hakuna vitufe vya mkono vya Tuma au Leta.

Programu zote mbili za kompyuta hutoa:

- **Ikoni ya trei ya mfumo au upau wa menyu:** Huonyesha idadi ya vifaa vilivyo mtandaoni, **Sawazisha** (pamoja na muda wa kusitisha), **Kila mahali**, **Fungua CBB**, **Mipangilio**, arifa za sasisho, na **Acha**.
- **Dirisha kuu:** Huonyesha vifaa kama **Vigae**, **Orodha**, au **Obiti**, huunga mkono mpangilio maalum na **mikusanyiko**, huonyesha taarifa na arifa za kikundi, na hufungua kidirisha cha maelezo ya kifaa kando ya orodha.
- **Kuanza na kuoanisha:** Isipokuwa kwenye kikundi, hutoa **Unda kikundi**, **Jiunge na kikundi**, **Jiunge kwa mwaliko**, na **Hamishia kikundi kwenye kompyuta hii** (kwa kutumia ufunguo wa urejeshaji). Ikiwa kwenye kikundi kama msimamizi, **+** hufungua dirisha la kuoanisha (msimbo wa QR na tarakimu sita) au hutuma mwaliko.
- **Vidhibiti vya msimamizi na kitovu:** Hukuruhusu kubadilisha jina, kunyamazisha, kugandisha, kuondoa, kupandisha cheo wasimamizi, kusanidi kompyuta kama kitovu (ikiwemo mipangilio ya AmneziaWG, VLESS, na kisambazaji), na kurekebisha muda wa nakala na viwango vya funguo vya kikundi. Vitendo vinavyobadilisha kikundi huomba nywila yako ya msimamizi wa mfumo au uthibitisho wa mfumo (Touch ID, Windows Hello, au polkit).
- **Kubandika kwa mbali kwenye macOS:** Programu ya Mac hufanya kazi kama kipokeaji cha kubandika kwa mbali ikiwa wazi, mara unapoiwekea ruhusa ya Ufikivu katika **Mipangilio ya Mfumo > Faragha na Usalama > Ufikivu**.
- **Mipangilio:** Mwonekano, mandhari zote kumi na moja, lugha nane, **Fungua wakati wa kuingia**, **Mipangilio ya kina** (ikiwemo **Kwa nini haisawazishi**), na **Onyesha maelezo ya hitilafu** (kubofya mara saba kwenye toleo).

Kitu kisipofanya kazi kama inavyotarajiwa, tazama [Utatuzi wa matatizo](troubleshooting.md).
