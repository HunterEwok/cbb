<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ee7b34adad9e -->
# Picha, faili na maandishi yenye muundo

Kwa yeyote anayenakili zaidi ya maandishi matupu. Kwenye ukurasa huu, unajifunza aina zipi za maudhui husawazishwa kati ya kompyuta na simu, jinsi ya kutuma na kuhifadhi picha na faili kutoka kwenye mstari wa amri au simu, na jinsi ya kubadilisha mipaka ya ukubwa kwa kila kifaa.

Unaponakili picha, faili kutoka kwenye kidhibiti faili, au maandishi yenye muundo kwenye kifaa kimoja, kifaa kinachonakili hufunga maudhui mwisho hadi mwisho na kuyatangaza kwa kikundi chako. Vifaa vingine vilivyowasha **Sawazisha** huyaleta kiotomatiki hadi kufikia mipaka yao ya ukubwa. Kwa jinsi usimbaji wa mwisho hadi mwisho unavyofanya kazi, tazama [Jinsi inavyofanya kazi](how-it-works.md#what-happens-when-you-copy).

## Nini kinakwenda wapi

| Maudhui yaliyonakiliwa | Kompyuta zenye eneo-kazi | Simu | Kompyuta na vifaa vidogo visivyo na eneo-kazi |
|---|---|---|---|
| **Maandishi yenye muundo** (HTML kutoka kivinjari au programu ya ofisi) | Hubandikwa yakiwa na muundo (hadi MiB 8 za HTML) | Hubandikwa kama maandishi matupu | Maandishi matupu |
| **Picha** (PNG, JPEG, GIF; TIFF kwenye macOS na HEIC kwenye simu hubadilishwa) | Hubandikwa moja kwa moja kama picha | Husawazishwa kwenye ubao wa kunakili unapofungua **CBB** au kugusa kitufe cha kusawazisha; pia huhifadhiwa kwenye matunzio kwenye Android na Aurora OS au **Picha** kwenye iPhone inapopokelewa kama faili | Maandishi matupu tu; hifadhi picha kwa `cbb paste -o DIR` |
| **Faili na folda** | Hubandikwa kama faili kwenye kidhibiti faili au programu | **Android:** huhifadhiwa katika `Downloads/CBB` (picha moja au video moja huenda kwenye albamu ya matunzio `CBB`). **iPhone:** huhifadhiwa katika **Faili > Kwenye iPhone Yangu > CBB** (picha moja au video moja huenda kwenye **Picha**). **Aurora OS:** huhifadhiwa katika `Downloads/CBB` (picha kwenye matunzio). **HarmonyOS:** huhifadhiwa kwa kitufe cha **Hifadhi faili zilizopokelewa** | Hifadhi kwa `cbb paste -o DIR` |

Kukata faili kwenye kidhibiti faili huchukuliwa kama kunakili: Connect Beyond Borders kamwe haifuti faili asili kwenye kifaa chochote. Wakati ubao wa kunakili wa eneo-kazi una maandishi na picha pamoja bila uteuzi tofauti wa faili, maandishi matupu huchukua kipaumbele isipokuwa picha imenakiliwa mahususi.

## Tuma na uhifadhi kutoka kwenye simu

1. **Tuma faili au picha kutoka kwenye simu:** Fungua kidhibiti faili, matunzio, au programu nyingine, chagua **Shiriki > Connect Beyond Borders**, na uthibitishe ukiulizwa. Kwenye Android, iPhone, Aurora OS, na HarmonyOS, picha na faili zilizoshirikiwa husawazishwa kwenye kompyuta za kikundi chako.
2. **Hifadhi faili zilizopokelewa kwenye simu:** Fungua **CBB** (au anzisha usawazishaji). Kwenye Android, iPhone, na Aurora OS, faili huhifadhiwa kiotomatiki katika maeneo yaliyo kwenye jedwali hapo juu. Kwenye HarmonyOS, gusa **Hifadhi faili zilizopokelewa** kwenye **Mwanzo** unapoarifiwa kuwa faili ziko tayari.

**Matokeo:** Picha zilizoshirikiwa huonekana kwenye ubao wa kunakili wa kompyuta zako, na faili zilizopokelewa huonekana kwenye folda ya vipakuliwa, faili, au matunzio ya simu yako.

## Tuma na uhifadhi kutoka kwenye mstari wa amri

Endesha amri hizi kwenye kompyuta yoyote au kifaa kidogo bila `sudo`:

1. **Tuma faili na folda kama nakala moja:**

   ```sh
   cbb copy photo.jpg notes/
   ```

   Ongeza `-text "summary"` ili kujumuisha maandishi matupu mbadala kwa vifaa vinavyopokea maandishi pekee.

   **Matokeo:** Connect Beyond Borders huchapisha idadi ya faili na baiti ilizonakili kwa kikundi.

2. **Tuma picha moja au faili ya HTML kama data ya ubao wa kunakili:**

   ```sh
   cbb copy -type png screenshot.png
   ```

   `-type` inakubali `png`, `jpeg` (au `jpg`), `gif`, au `html`.

   **Matokeo:** Kompyuta zenye eneo-kazi hupokea faili hiyo kama picha ya ubao wa kunakili au data ya HTML badala ya kiambatisho cha faili.

3. **Hifadhi picha au faili zilizopo kwenye ubao wa kunakili kwenye folda:**

   ```sh
   cbb paste -o ~/Downloads
   ```

   **Matokeo:** `cbb` husubiri ikiwa nakala bado inatumwa, huandika faili na folda kwa majina yake (au `image.png`, `image.jpg`, `image.gif`, au `clipboard.html` kwa data ya ubao wa kunakili), na kuchapisha kila njia ya ngazi ya juu iliyoiunda. Kamwe haibadilishi faili zilizopo na haifanyi chochote kitekelezeke.

4. **Kagua maendeleo ya uhamishaji:** Endesha `cbb status` ili kuona kama nakala kubwa bado inafika au ilirukwa kwa sababu inazidi mpaka wa ukubwa wa kifaa hiki.

## Badilisha mipaka ya ukubwa

Kila kifaa hutekeleza mipaka yake ya ukubwa kwa picha na faili. Ukiwa mbali na nyumbani, mpaka wa `max-copy-away` wa kitovu huweka ukomo kwa kila kifaa kinachounganishwa kupitia kitovu hicho.

| Wigo | Chaguo-msingi | Masafa yanayoruhusiwa | Jinsi ya kubadilisha |
|---|---|---|---|
| **Nyumbani** (kompyuta na vifaa vidogo) | MiB 100 kwa kila nakala | MiB 1 hadi GiB 1 | `cbb config max-copy SIZE` |
| **Kupitia handaki la kikundi** (kompyuta, vifaa vidogo, na vitovu) | MiB 25 kwa kila nakala | MiB 1 hadi `max-copy` | `cbb config max-copy-away SIZE` |
| **Karatasi ya kushiriki ya simu** | MiB 100 kwenye Android; MB 50 kwenye iPhone, Aurora OS, na HarmonyOS | Haibadiliki | Haiwezi kubadilishwa |

Kuona au kubadilisha mipaka kwenye kompyuta:

1. Tazama mipaka ya sasa:

   ```sh
   cbb config
   ```

2. Pandisha au shusha mpaka (kwa mfano, hadi MiB 250 nyumbani au MiB 50 ukiwa mbali na nyumbani):

   ```sh
   cbb config max-copy 250MiB
   cbb config max-copy-away 50MiB
   ```

**Matokeo:** Kifaa hutumia mpaka mpya mara moja. Kushusha `max-copy` chini ya `max-copy-away` kunashusha `max-copy-away` ilingane. Nakala kubwa kuliko mpaka wa kifaa haziletwi kwenye kifaa hicho, na `cbb status` husema kuwa nakala hiyo ilirukwa.

Kwa mipaka yote ya ukubwa na sehemu za nakala (ikiwa ni pamoja na mpaka wa sehemu 10,000 na mpaka wa KiB 256 wa maandishi mbadala), tazama [Mipaka na muda](../reference/limits.md#copies).

## Usalama

- **Hifadhi ya muda ya faragha:** Kwenye kompyuta zenye eneo-kazi, wakala wa ubao wa kunakili hufungua faili zilizopokelewa kwenye folda ya faragha ndani ya akiba ya mtumiaji wako (`~/.cache/cbb/received` kwenye Linux na FreeBSD, `~/Library/Caches/cbb/received` kwenye macOS, `%LocalAppData%\cbb\received` kwenye Windows) inayosomeka na mtumiaji wako pekee, na kufuta folda za nakala za zamani dakika 10 baada ya nakala mpya kufika.
- **Maonyo ya upakuaji:** Faili zilizopokelewa haziwekwi kamwe alama ya kutekelezeka. macOS huongeza sifa ya `com.apple.quarantine` na Windows huongeza Mark of the Web (`Zone.Identifier`) ili mfumo wa uendeshaji uonye kabla ya kufungua programu iliyopokelewa.
- **Majina salama ya faili:** Connect Beyond Borders husafisha majina ya faili kati ya mifumo ya uendeshaji na kuruka viungo vya ishara (symbolic links) na faili maalum ndani ya folda zilizonakiliwa.
- **Siri za maandishi matupu:** Muundo hausomwi kamwe kwa siri; siri husafiri kama maandishi matupu pekee.
- **Akiba ya huduma:** Huduma ya chinichini huhifadhi nakala zisizozidi 8 za mwisho zilizofungwa katika saraka yake ya hali ikiwa inafanya kazi na hufuta akiba hiyo kila inapoanzishwa upya.
