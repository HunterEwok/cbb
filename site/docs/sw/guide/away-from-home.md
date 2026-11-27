<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 8a4822a1fdc4 -->
# Mbali na nyumbani

Kwa yeyote anayetaka vifaa vyake viendelee kusawazisha nje ya mtandao wake wa nyumbani. Kwenye ukurasa huu, unaweka kompyuta nyumbani kama **kitovu**, unawasha usawazishaji ukiwa mbali na nyumbani kwenye vifaa vyako vingine, kwa hiari unasanidi **kisambazaji** au **relei pofu**, na unaalika vifaa ambavyo haviko nyumbani.

Nyumbani, vifaa vyako huunganishwa moja kwa moja kwenye mtandao wako wa ndani. Ukiwa mbali na nyumbani, vinafikia kitovu nyumbani kupitia handaki la WireGuard lililosimbwa la kikundi chako chenyewe. Kwa jinsi vitovu, visambazaji, na relei pofu vinavyofanya kazi, tazama [Jinsi inavyofanya kazi](how-it-works.md#away-from-home-the-hub). Kwa kile ambacho kila seva inaweza kuona, tazama [Faragha: nani anaona nini](privacy.md).

Usawazishaji ukiwa mbali na nyumbani hubaki umezimwa hadi uuwashe kwenye kitovu na kwenye kila kifaa kinachouhitaji. Uusanidi **wakati vifaa vyote viko kwenye mtandao wako wa nyumbani**, kwa sababu vifaa hubadilishana funguo za handaki ndani ya mtandao wa nyumbani na kitovu.

## 1. Chagua kitovu

**Kitovu** ni kompyuta, kipanga njia, au bodi ndogo nyumbani (Linux, macOS, Windows, FreeBSD, OpenWrt, au OPNsense). Simu, saa, au [usakinishaji wa Linux bila root](install.md#without-sudo-rootless) kamwe si kitovu. Chagua kifaa kinachobaki kimewashwa muda mwingi, kama seva ya nyumbani, NAS, kipanga njia, au Raspberry Pi. Wakati kitovu kimezimwa, usawazishaji ukiwa mbali na nyumbani husitishwa, huku vifaa vilivyo nyumbani vikiendelea kusawazisha moja kwa moja.

Chagua aina ya kitovu unayotaka:

- **Kitovu kinachosoma nakala:** **Kifaa kikuu** cha kikundi chako (ikiwa ni kompyuta) au kompyuta ya **msimamizi**. Vifaa hufunga nakala kwa ajili yake kama kwa kifaa kingine chochote kinachosoma, na [kiwango cha funguo](keys.md#the-three-levels) cha kikundi chako hutumika kwenye funguo zake.
- **Kitovu kinachopitisha nakala tu:** Kompyuta yoyote ya kawaida au bodi ndogo katika kikundi chako. Vifaa hufunga nakala mwisho hadi mwisho bila kukihusisha, kwa hiyo hakisomi nakala zozote, hakitengenezi nakala zake zenyewe, hakikubali kubandika kwa mbali wala vitendo vya haraka, na hakihitaji chipu ya usalama ya maunzi. Kifaa kikuu cha kikundi pekee ndicho kinaweza kuteua kitovu kinachopitisha nakala tu.

Kikundi kinaweza kuwa na vitovu kadhaa kwa mpangilio wa kipaumbele; ni kitovu kilicho mtandaoni chenye kipaumbele cha juu zaidi pekee kinachohudumu kwa wakati mmoja. Ili kuweka mpangilio kutoka kwenye kifaa kikuu (au kompyuta ya msimamizi inayoweza kuwa kitovu), endesha `sudo cbb global hubs NAME...`.

## 2. Kiwashe kwenye kitovu

Unaweza kusanidi kitovu kutoka programu ya kompyuta, kutoka simu ya msimamizi, au kutoka terminal.

### Kwa kutumia programu ya Mac au programu ya trei

1. Fungua **CBB** kwenye kompyuta unayotaka kutumia kama kitovu.
2. Fungua ukurasa wa kifaa cha kompyuta hiyo yenyewe na ubofye **Kifanye kitovu**.
3. Ukiulizwa, chagua **Kitovu kinachosoma nakala** au **Kitovu kinachozipitisha tu**, na uthibitishe kuwasha usawazishaji ukiwa mbali na nyumbani.

**Matokeo:** Programu inawasha usawazishaji ukiwa mbali na nyumbani kwa kompyuta hii na inaisanidi kama kitovu kwa kutumia kisambazaji cha mradi kwenye `cbb.tools`, kwa hiyo huhitaji kufungua mlango wowote kwenye kipanga njia chako.

### Kwa kutumia simu ya msimamizi

1. Kwenye kompyuta unayotaka kuifanya kitovu, washa usawazishaji ukiwa mbali na nyumbani kwanza (`sudo cbb global on`, au washa **Kila mahali** katika programu ya kompyuta).
2. Kwenye simu yako, fungua **CBB** na uguse kompyuta kwenye **Mwanzo**.
3. Ikiwa kompyuta bado si msimamizi (na unataka kitovu kinachosoma nakala), gusa **Kifanye msimamizi** na uthibitishe.
4. Gusa **Kifanye kitovu** na uthibitishe kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi.

**Matokeo:** Kompyuta inakuwa kitovu kupitia kisambazaji cha mradi kwenye `cbb.tools`.

### Kwa kutumia terminal

Kwenye Linux, macOS, au FreeBSD, endesha amri hizi kwenye kompyuta ya kitovu (kwenye Windows, acha `sudo` na utumie terminal ya msimamizi wa mfumo):

1. Washa usawazishaji ukiwa mbali na nyumbani:

   ```sh
   sudo cbb global on
   ```

   Ikiwa kompyuta huhifadhi funguo zake kwenye faili, soma onyo na uandike `yes`.

   **Matokeo:** Huduma inaruhusu miunganisho ya handaki inayotoka nje kwenda kwenye seva za kikundi chako na inaacha maeneo mengine yote ya intaneti yakiwa yamezuiwa.

2. Fanya kompyuta kuwa kitovu. Chagua mojawapo ya zifuatazo:
   - **Muunganisho wa moja kwa moja na anwani ya umma ya nyumbani** (IPv4, IPv6, au jina la kikoa linaloelekeza nyumbani kwako):

     ```sh
     sudo cbb global hub 203.0.113.7:8764
     ```

   - **Kupitia kisambazaji** (wakati nyumba yako haina anwani ya umma au hutaki kufungua mlango wa kipanga njia):

     ```sh
     sudo cbb global hub
     ```

   **Matokeo:** Ikiwa uliweka anwani ya nyumbani, `cbb global hub` huorodhesha kanuni ya ngome ya UDP inayohitaji na huuliza kabla ya kuiongeza. Bila anwani, kitovu hujisajili kwenye kisambazaji cha mradi kwenye `cbb.tools`.

3. Ikiwa uliweka anwani ya umma ya nyumbani na kitovu chako kiko nyuma ya kipanga njia, fungua mipangilio ya kipanga njia chako na uelekeze **mlango wa UDP 8764** (au mlango ulioweka kwa `-port`) kwenye anwani ya IP ya ndani ya kitovu. Tafuta **Port Forwarding** au **Virtual Server** katika mipangilio ya kipanga njia chako.

   Kwenye **kipanga njia cha OpenWrt** kinachofanya kazi kama kitovu, endesha amri zilizo hapo juu kama `root` bila `sudo`. Hakuna uelekezaji wa milango unaohitajika isipokuwa kipanga njia kiko nyuma ya kipanga njia kingine (double NAT): unapothibitisha swali la ngome, Connect Beyond Borders huongeza kanuni ya UDP ya WAN kwenye kanuni za ngome za huduma yenyewe bila kuhariri `/etc/config/firewall`.

Ili kuifanya kompyuta nyingine kuwa kitovu kinachopitisha nakala tu kutoka kwenye kifaa kikuu (kinachoitwa *root* katika zana za mstari wa amri), washa usawazishaji ukiwa mbali na nyumbani kwenye kompyuta hiyo kwanza, kisha uendeshe kwenye kifaa kikuu:

```sh
sudo cbb global hub -on DEVICE -forward-only
```

## 3. Kiwashe kwenye vifaa vingine

Wakati vifaa vyote viko kwenye mtandao wako wa nyumbani na kitovu kinafanya kazi:

- **Kompyuta na vifaa vidogo:** Endesha `sudo cbb global on` (kwenye terminal ya msimamizi wa mfumo bila `sudo` kwenye Windows), au washa **Kila mahali** katika programu ya Mac au programu ya trei. Kumbuka kwamba matoleo ya vipanga njia vya MIPS husawazisha kwenye mtandao wa nyumbani pekee; tazama [Vifaa, milango na faili](../reference/devices.md).
- **Simu:** Fungua **CBB** na uwashe **Kila mahali** (swichi ya dunia) kutoka **Mwanzo**, kisha uache programu wazi kwa muda mfupi nyumbani ili ibadilishane funguo za handaki na kitovu. Simu za Android huendelea kusawazisha zikiwa mbali na nyumbani chinichini; iPhone, Aurora OS, na HarmonyOS husawazisha programu ikiwa wazi.

**Matokeo:** Kila kifaa hupokea ofa ya handaki ya kitovu na hubadilishana nacho funguo za handaki.

## 4. Kikague

1. Kwenye kila kompyuta, endesha:

   ```sh
   cbb global
   ```

   **Matokeo:** Matokeo yanaonyesha kama usawazishaji ukiwa mbali na nyumbani umewashwa, ni kifaa kipi ni kitovu, kama handaki limeunganishwa, na hitilafu yoyote iliyopo.

2. Ondoa simu au kompyuta mpakato kutoka kwenye Wi-Fi yako ya nyumbani (kwa mfano, badilisha simu kwenda data ya simu) na unakili mstari wa maandishi.

   **Matokeo:** Maandishi uliyonakili yanafika kwenye vifaa vyako nyumbani.

Ikiwa handaki haliunganishwi, kagua uelekezaji wa mlango wa UDP wa kipanga njia chako na anwani ya umma, au tazama [Utatuzi wa matatizo: kusawazisha ukiwa mbali na nyumbani](troubleshooting.md#sync-away-from-home).

Ikiwa anwani ya umma ya nyumbani kwako itabadilika baadaye, kitovu hushiriki anwani mpya wakati ujao vifaa vyako vitakapokutana. Wakati `cbb global` au `cbb status` inaripoti kuwa kanuni ya mfumo ya mtandao unaotoka nje iko nyuma, endesha `sudo cbb global allow` kwenye kompyuta hiyo ili kusasisha kanuni.

## 5. Intaneti isipoweza kufikia nyumbani kwako: kisambazaji

Watoa huduma wengi wa intaneti huweka nyumba nyuma ya carrier-grade NAT (anwani ya IP ya umma inayoshirikiwa), jambo linalozuia miunganisho inayoingia hata kwa uelekezaji wa milango. **Kisambazaji** hutatua hili: kitovu chako hufungua muunganisho unaotoka nje kwenda kwenye kisambazaji, na vifaa vilivyo mbali hutuma pakiti zilizosimbwa za handaki kwenda kwenye kitovu kupitia kwacho. Hakuna milango ya kipanga njia inayohitaji kufunguliwa, na kisambazaji hakishikilii funguo zozote za kikundi.

Chagua mojawapo ya chaguo mbili kwenye kitovu chako:

- **Tumia kisambazaji cha mradi kwenye `cbb.tools`:** Endesha `sudo cbb global hub` bila anwani, au ongeza `-forwarder default` pamoja na anwani za umma za kitovu chako mwenyewe:

  ```sh
  sudo cbb global hub -forwarder default 203.0.113.7:8764
  ```

- **Tumia kisambazaji chako mwenyewe:** Endesha kisambazaji kwenye seva yoyote yenye anwani ya umma ([Kuendesha seva zako mwenyewe](../admin/self-hosting.md#a-forwarder)), kisha pitisha anwani na ufunguo wake kwenye kitovu:

  ```sh
  sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
  ```

**Matokeo:** Wakati kitovu kina anwani za moja kwa moja na kisambazaji vyote viwili, vifaa vilivyo mbali hujaribu anwani za moja kwa moja kwanza na hurejea kwenye kisambazaji ikiwa miunganisho ya moja kwa moja itashindwa.

## 6. Mitandao inayozuia VPN

Hoteli, ofisi, watoa huduma wa simu, na baadhi ya nchi huzuia WireGuard. Kwa chaguo-msingi, kitovu huficha handaki lake kwa **AmneziaWG** na (unapotumia kisambazaji kinachounga mkono) **VLESS** kupitia HTTPS. Ili kusanidi au kurekebisha ufichaji wa handaki, tazama [Mitandao inayozuia VPN](blocked-networks.md).

## Kompyuta isiyo nyumbani: mwaliko

Mara usawazishaji ukiwa mbali na nyumbani unapofanya kazi kupitia kitovu, unaweza kualika kompyuta au simu ambayo haiko kwenye mtandao wako wa nyumbani. Mwaliko hufanya kazi mara moja na hudumu saa 1 kwa chaguo-msingi (hadi saa 24 kwa `-for`).

### Alika na ukubali kifaa

1. Kwenye kifaa kikuu au msimamizi, unda mwaliko:
   - **Kwenye terminal kwenye kompyuta ya msimamizi:** Endesha `sudo cbb invite` kwa kompyuta (huandika `cbb.cbbinvite`), au `sudo cbb invite -phone` kwa simu (huchapisha msimbo wa QR). Acha amri ikiendeshwa hadi kifaa kipya kijiunge.
   - **Kwenye programu ya simu au kompyuta:** Gusa **+** kwenye **Mwanzo** (au chagua **Ongeza kifaa > Kifaa kiko mbali? Tuma mwaliko** katika programu ya kompyuta) na ufuate maelekezo.
2. Tuma faili ya mwaliko, maandishi (`cbb://join#...`), au msimbo wa QR kwenye kifaa kipya kupitia njia unayoiamini. Yeyote anayeshikilia mwaliko ambao haujatumika anaweza kuomba kujiunga, ingawa bado unaidhinisha kukubaliwa kwa kulinganisha alama za funguo.
3. Kwenye kifaa kipya, tumia mwaliko:
   - **Kwenye kompyuta (terminal):** Endesha `sudo cbb pair -invite cbb.cbbinvite` (au `sudo cbb pair -invite -` na ubandike maandishi ya `cbb://join#...` kwenye ingizo la kawaida).
   - **Kwenye kompyuta (programu ya kompyuta):** Chagua **Jiunge kwa mwaliko** na ubandike maandishi ya mwaliko.
   - **Kwenye simu:** Fungua **CBB**, gusa **Jiunge kwa mwaliko**, na uchanganue msimbo wa QR, ubandike maandishi ya mwaliko, au ufungue faili ya mwaliko.

   **Matokeo:** Vifaa vyote viwili huonyesha alama ya ufunguo wa kifaa kipya.

4. Linganisha alama ya ufunguo inayoonyeshwa kwenye kifaa kinachoalika na alama inayoonyeshwa kwenye kifaa kipya. Andika `yes` (au gusa **Kubali**) ikiwa tu zinalingana kabisa.

**Matokeo:** Kifaa kipya kinajiunga na kikundi chako na kuanza kusawazisha kupitia kitovu. `cbb invite` hufuta faili ya muda ya mwaliko inapomaliza.

Ili kuongeza kompyuta kutoka mtandao mwingine kupitia SSH au VPN yako mwenyewe badala yake, tazama [Bila programu: kujiunga kutoka mtandao mwingine](without-app.md#joining-from-another-network).

## Hakuna kompyuta ya kuwa kitovu

Simu kamwe si kitovu. Ikiwa kikundi chako hakina kompyuta, kipanga njia, au bodi ndogo ya kufanya kazi kama kitovu (kwa mfano, kikundi cha simu pekee), vifaa vyako vinaweza kukutana kwenye **relei pofu** badala yake. Vifaa vyote viwili lazima viwe mtandaoni kwa wakati mmoja ili kubadilishana nakala.

Relei pofu haiwezi kusoma ubao wako wa kunakili, lakini huona ni majina gani ya bandia ya muda ya vifaa yaliyo mtandaoni pamoja, anwani zao za IP, muda, na kiasi cha trafiki. **Kifaa kikuu** cha kikundi pekee ndicho huwasha au kuzima relei pofu kwa kikundi, na baada ya wewe kukubali kile relei inachoona pekee.

### Washa relei pofu

- **Kwenye simu (kifaa kikuu):** Fungua **Mipangilio**, washa **Mipangilio ya kina**, gusa **Relei pofu**, na uchague relei ya mradi au uweke anwani na ufunguo wa relei yako mwenyewe. Thibitisha swali.
- **Kwenye kompyuta (kifaa kikuu):**
  - Tumia relei ya wazi ya mradi kwenye `cbb.tools:8765`:

    ```sh
    sudo cbb global relay default
    ```

  - Tumia relei yako mwenyewe ([Kuendesha seva zako mwenyewe](../admin/self-hosting.md#a-blind-relay)):

    ```sh
    sudo cbb global relay 198.51.100.9:8764 -key KEY
    ```

  Soma kile relei inaweza kuona na uandike `yes`.

**Matokeo:** Mipangilio ya kikundi chako inataja relei hiyo, na vifaa vilivyowasha **Kila mahali** hukutana huko.

Ili kuacha kutumia relei pofu, endesha `sudo cbb global relay off` kwenye kompyuta kuu, au fungua **Mipangilio > Mipangilio ya kina > Relei pofu** kwenye simu kuu na uguse **Ondoka kwenye relei**.

## Kuzima

### Simamisha kompyuta isiwe kitovu

Ili kusimamisha kompyuta isifanye kazi kama kitovu huku usawazishaji ukiwa mbali na nyumbani ukibaki umewashwa juu yake:

- **Kwenye programu ya Mac au programu ya trei:** Fungua ukurasa wa kifaa cha kitovu na ubofye **Acha kuwa kitovu**.
- **Kwenye terminal:** Endesha `sudo cbb global hub off` kwenye kitovu, au `sudo cbb global hub off -on NAME` kutoka kompyuta ya msimamizi.

**Matokeo:** Vifaa vilivyo mbali vilivyounganishwa huhamia kiotomatiki kwenye kitovu kinachofuata cha kikundi. Ikiwa kikundi hakina kitovu kingine, Connect Beyond Borders huomba uthibitisho kabla ya kusimamisha (pitisha `-yes` katika hati ili kuthibitisha), kwa sababu vifaa vilivyo mbali huacha kusawazisha hadi kitovu kingine kisanidiwe.

### Zima usawazishaji ukiwa mbali na nyumbani kwenye kifaa

- **Kwenye kompyuta:** Endesha `sudo cbb global off` (kwenye Windows, `cbb global off` kwenye terminal ya msimamizi wa mfumo), au zima **Kila mahali** katika programu ya kompyuta.
- **Kwenye simu:** Zima **Kila mahali** kwenye **Mwanzo**.

**Matokeo:** Kifaa husahau funguo zake za handaki na kuacha kusawazisha kikiwa mbali na nyumbani. Kwenye Linux na Windows, `cbb global off` pia huondoa seva za kikundi kutoka kwenye kanuni ya mfumo ya mtandao unaotoka nje. Kwa sababu funguo mpya za handaki hubadilishanwa na kitovu kwenye mtandao wako wa nyumbani, kifaa kinachozima usawazishaji ukiwa mbali na nyumbani kikiwa mbali huendelea na usawazishaji wa mbali baada tu ya kuunganishwa tena nyumbani.
