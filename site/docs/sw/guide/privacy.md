<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ecfb35897e1b -->
# Faragha: nani anaona nini

Kwa yeyote anayetaka kujua data gani inaondoka kwenye vifaa vyake, kile ambacho kila seva na jukwaa vinaweza kuona, na jinsi ya kupunguza au kuzima kila ufichuzi. Connect Beyond Borders haitumii akaunti, hifadhi ya ubao wa kunakili ya wingu, wala telemetria ya uchanganuzi.

## Nini hutokea kwa nakala zako

Kila nakala — maandishi matupu, siri, maandishi yenye muundo, picha, na faili — husimbwa mwisho hadi mwisho kabla ya kuondoka kwenye kifaa ulipoinakili:

1. Kifaa kinachonakili hutengeneza ufunguo mpya wa baiti 32 kwa ajili ya nakala hiyo moja na kusimba maudhui kwa ChaCha20-Poly1305.
2. Hufunga ufunguo huo kipekee kwa kila kifaa kinachosoma katika kikundi chako kwa kutumia HPKE na **X-Wing** (inayounganisha X25519 na ML-KEM-768 sugu kwa kompyuta za kwantamu) na kutia sahihi nakala hiyo kwa ufunguo wake wa mwanachama (ECDSA P-256).
3. Nakala iliyofungwa husafiri ndani ya muunganisho wa **TLS 1.3** wa pande zote mbili kwa kutumia funguo za vifaa vya kikundi chako, na ukiwa mbali na nyumbani pia ndani ya handaki la **WireGuard** la kikundi chako.

Hakuna seva, mtandao, mtoa huduma wa intaneti, wala kifaa cha katikati kisicho na ufunguo wa kusoma kinachoweza kusoma, kubadilisha, au kughushi nakala. Kifaa kilichoondolewa hakipokei nakala za baadaye, na kifaa kilichojiunga upya hakiwezi kusimbua nakala zilizofanywa kabla hakijajiunga.

## Vifaa vilivyo katikati vinaona nini

Nakala inaweza kupitia kifaa kingine katika kikundi chako kabla ya kufika inakoenda — kwa mfano, kupitia kitovu chako ukiwa mbali na nyumbani au kupitia mwanachama mwingine kwenye mtandao wako wa nyumbani. Kifaa kinachopitisha nakala tu hakiwezi kufungua muhuri, kwa hiyo huona tu metadata ya bahasha inayohitajika kwa uwasilishaji:

- **Mtumaji na muhuri wa muda:** Kifaa kipi kilinakili kipengee na lini (inahitajika kuamua nakala ipi ni mpya zaidi).
- **Orodha ya wapokeaji:** Nakala imefungwa kwa ajili ya vifaa vipi (tayari inajulikana na wanachama wa kikundi kutoka kwenye rekodi za vifaa za kikundi).
- **Ukubwa uliokadiriwa kwa ngazi:** Ukubwa wa maandishi uliokadiriwa kwa hatua maalum (`1`, `4`, `16`, `64`, `256` KB, `1` MB, kisha kwa kila megabaiti), na kama kuna kiambatisho cha picha au faili pamoja na jumla yake iliyokadiriwa kwa `64` KB. Faili zote za nakala moja husafiri ndani ya kipande kimoja kilichofungwa, kwa hiyo idadi ya faili imefichwa.

Vifaa vya katikati havioni kamwe kama nakala ni maandishi matupu, siri, picha, au faili; havioni kamwe maandishi wala majina ya faili; na havioni kamwe ukubwa halisi kwa baiti.

## Vighairi vya kuchagua mwenyewe

Baadhi ya vipengele vinahusisha njia zilizo nje ya muhuri wa mwisho hadi mwisho wa Connect Beyond Borders. Kila kimoja kinahitaji chaguo lako wazi:

- **Rimoti ya televisheni ya Roku (`cbb remote add -roku -consent`):** Itifaki ya Udhibiti wa Nje ya Roku hutumia HTTP isiyosimbwa kwenye mtandao wako wa nyumbani. Usitume nywila kwa Roku ([Kibodi na televisheni](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- **Kitovu kinachosoma nakala:** Kifaa kikuu au kompyuta ya msimamizi inayofanya kazi kama kitovu hupokea nakala zilizofungwa kwa ajili yake kama kifaa kingine chochote kinachosoma. Ikiwa kitovu chako kinachowashwa kila wakati huhifadhi funguo kwenye faili (kama Raspberry Pi au NAS), kisanidi kama **kitovu kinachopitisha nakala tu** ili nakala zisifungwe kamwe kwa ajili yake ([Mbali na nyumbani](away-from-home.md)). Amri zilizotiwa sahihi (kama kubandika kwa mbali na vitendo vya haraka) hufungwa kila wakati kwa ajili ya kifaa chake kimoja lengwa pekee.
- **Saa zilizooanishwa (Apple Watch, Wear OS, saa ya HarmonyOS):** Saa huwasiliana na simu iliyooanishwa nayo kupitia njia iliyosimbwa ya mfumo wa uendeshaji kati ya simu na saa (WatchConnectivity, Wearable Data Layer, au Wear Engine) na huonyesha hali ya vifaa, matukio, na swichi badala ya maudhui ya ubao wako wa kunakili.
- **Kibodi za Bluetooth na USB:** Maandishi yanayoandikwa kupitia simu, kompyuta ya Linux, au kibodi ya Arduino Nano ESP32 husafiri kupitia Bluetooth au USB moja kwa moja kwenda kifaa lengwa kilichooanishwa.

## Kila mtu aliye nje ya kikundi chako

Kusawazisha ukiwa mbali na nyumbani kukiwa kumezimwa, huduma ya chinichini huwasiliana kwenye mtandao wako wa nyumbani pekee. Kusawazisha ukiwa mbali na nyumbani kukiwa kumewashwa, huduma huwasiliana tu na mtandao wako wa nyumbani na kitovu, kisambazaji, na relei ya kikundi chako mwenyewe (inavyosimamiwa katika msimbo kwenye kila mfumo wa uendeshaji na kwa kanuni za ngome/sandbox za mfumo kwenye Linux na Windows).

Wala kisambazaji wala relei pofu havioni kamwe orodha ya vifaa vya kikundi chako, majina ya vifaa, au vitambulisho vya kudumu vya vifaa. Badala yake, kikundi chako hutengeneza **vitambulisho vya seva** vya muda tofauti kwa kila seva na kuvibadilisha kila baada ya siku 30 (na kifaa kinapoondolewa), ili seva mbili zisiweze kuunganisha trafiki ya kikundi chako pamoja.

Jedwali hapa chini linaorodhesha kila upande nje ya kikundi chako unaoweza kuona trafiki au metadata yoyote:

| Upande | Wanachoweza kuona | Jinsi ya kuepuka au kupunguza |
|---|---|---|
| **Vifaa vingine kwenye mtandao wako wa nyumbani** | Matangazo ya mDNS yanayoonyesha kuwa vifaa vinaendesha Connect Beyond Borders, vitambulisho vyao vya kifaa vya nasibu, lebo ya kikundi, na mlango; anwani zipi za IP za ndani zinaunganisha na kiasi gani cha data kinapita. Kamwe si majina ya vifaa wala maudhui ya ubao wa kunakili | Kompyuta hutangaza kwenye mitandao ya nyumbani inayojulikana pekee na hukaa kimya kwenye Wi-Fi isiyojulikana |
| **Mitandao ukiwa mbali na nyumbani** (mkahawa, hoteli, mwendeshaji wa simu, ISP) | Pakiti za UDP za WireGuard/AmneziaWG zilizosimbwa — au kwa VLESS, muunganisho wa HTTPS kwenda kikoa cha kisambazaji (inayoonekana katika TLS SNI) — pamoja na nyakati na kiasi cha trafiki | Endesha VPN ya mfumo kwenye kifaa chako ili kuficha vituo na nyakati |
| **Kisambazaji** (cha mradi kwenye `cbb.tools`, au chako mwenyewe) | Anwani za IP zinazobadilishana pakiti zilizosimbwa za WireGuard na kitovu chako, nyakati za pakiti, na ukubwa wa pakiti; lebo za vitambulisho vya seva zinazobadilika pekee, kamwe si majina ya vifaa, uanachama wa kikundi, wala maudhui ya ubao wa kunakili | Elekeza mlango wa UDP 8764 moja kwa moja kwenye kitovu chako ili kisambazaji kisitumike, au [endesha kisambazaji chako mwenyewe](../admin/self-hosting.md#a-forwarder) |
| **Relei pofu** (ya mradi kwenye `cbb.tools`, au yako mwenyewe) | Majina bandia yanayobadilika ya vifaa vilivyo mtandaoni kwa wakati mmoja, anwani zao za IP, majina bandia yapi yanazungumza, nyakati, na kiasi (huhifadhiwa kwenye kumbukumbu pekee, kamwe hayaandikwi kwenye kumbukumbu za faili). Kamwe si maudhui ya ubao wa kunakili wala majina ya vifaa | Tumia kitovu chako mwenyewe badala ya relei pofu, au [endesha relei yako mwenyewe](../admin/self-hosting.md#a-blind-relay) |
| **Mtoa huduma wa upangishaji wa kisambazaji au relei** | Anwani za IP zinazounganisha na seva, nyakati za muunganisho, na kiasi cha trafiki | Tumia VPN ya mfumo kwenye vifaa vyako, au panga seva mwenyewe kwa mtoa huduma unayemchagua |
| **Huduma ya arifa za kusukuma ya mradi** (`cbb.tools`) | Tokeni ya arifa ya simu, lebo ya nje ya kikundi inayobadilika, anwani ya IP ya mtumaji, na muhuri wa muda wa arifa wakati wa kuamsha programu ya simu iliyofungwa. Kila ujumbe wa arifa umefungwa kwa ajili ya simu hiyo na kujazwa hadi ukubwa maalum, kwa hiyo huduma haiwezi kuusoma | Zima **Niarifu programu ikiwa imefungwa** katika **Mipangilio** ya simu |
| **Majukwaa ya arifa za simu** (Apple APNs, Google FCM, au msambazaji wako wa UnifiedPush kama ntfy) | Kwamba arifa ya kusukuma ilitumwa kwa Connect Beyond Borders kwenye simu yako, na lini; kamwe si maudhui yaliyofungwa | Zima **Niarifu programu ikiwa imefungwa** katika **Mipangilio** ya simu, au tumia toleo la Android la F-Droid pamoja na seva yako ya UnifiedPush badala ya Google FCM |
| **Seva za masasisho** (GitHub Releases, `raw.githubusercontent.com`, `dl.cbb.tools`, na `cbb.tools/openwrt` kwa chanzo cha OpenWrt) | Anwani yako ya IP na kwamba ulikagua au ulipakua toleo la Connect Beyond Borders; hakuna chochote kuhusu kikundi chako au nakala zako | Zima masasisho ya kiotomatiki (`sudo cbb update -auto off`, au kwenye Android **Mipangilio > Kuhusu**), au elekeza masasisho kwenye kioo chako cha HTTPS (`sudo cbb update -mirror https://...`) |
| **Orodha zilizotiwa sahihi za mradi na kioo cha uthibitisho** (`cbb.tools`) | Anwani yako ya IP unapopata orodha zilizotiwa sahihi za milango ya kuingilia ya seva, au kifaa kikuu kinapopata nakala ya kila siku iliyotiwa sahihi ya orodha ya Google ya ubatilishaji wa uthibitisho wa Android (`https://cbb.tools/attest/`) | Faili zilezile za umma hutolewa kwa kila mtu; kutumia kioo huepuka kuwasiliana na Google moja kwa moja |
| **Mpokeaji wa ripoti za hitilafu wa mradi** (`https://bug.cbb.tools/`) | Hakuna chochote katika toleo hili: programu bado hazitumi ripoti za hitilafu, kwa sababu ufunguo unaozifunga haumo kwenye ujenzi. Ukishakuwepo, ripoti hutumwa tu baada ya programu kuanguka **na** ukigusa **Ruhusu** (au **Ruhusu kila mara**): anwani yako ya IP, toleo la programu, alama ya kuanguka, na ripoti iliyofungwa kwa roboti ya mtunzaji, yenye kumbukumbu za hitilafu zilizochujwa, matoleo, na muundo wa kifaa — kamwe si maandishi ya ubao wa kunakili, faili, funguo, misimbo ya kuoanisha, majina ya vifaa, wala anwani za IP | Gusa **Ghairi** kwenye ombi baada ya kuanguka; hakuna kinachotumwa bila idhini yako |
| **Maduka ya programu na wasimamizi wa vifurushi** (Apple App Store / TestFlight, Google Play, F-Droid, Homebrew, winget) | Kwamba ulisakinisha au ulisasisha Connect Beyond Borders, kama ilivyo kwa programu yoyote kutoka duka hilo | Sakinisha kumbukumbu za matoleo zilizotiwa sahihi au APK moja kwa moja kutoka GitHub Releases |
| **Takwimu za tovuti** (`cbb.tools`) | Mionekano ya kurasa unapovinjari `cbb.tools` kwenye kivinjari cha wavuti, ikihesabiwa na GoatCounter inayoendeshwa kwenye seva yetu wenyewe bila vidakuzi na bila kushiriki na wahusika wengine | Programu na huduma ya chinichini kamwe hazipakii kurasa za tovuti wala takwimu |

Kumbukumbu hubaki ndani ya kila kifaa. Kuwasha maelezo ya hitilafu (`CBB_DEBUG=1` au **Onyesha maelezo ya hitilafu** katika mipangilio ya programu) huongeza maelezo ya msingi ya hitilafu ndani ya kifaa pekee na kamwe hakuyatumi popote kiotomatiki.

## Maelezo zaidi

- Kile ambacho kisambazaji na relei pofu huhifadhi kwenye diski: [Kuendesha seva zako mwenyewe: seva huhifadhi nini](../admin/self-hosting.md#what-the-server-keeps).
- Sehemu kamili za mtandao zinazoonwa na seva na huduma za arifa za kusukuma: [Itifaki](../protocol.md), sehemu ya 13 na 14.
- Vitisho vinavyozuiliwa na hatari zilizobaki: [Mfano wa vitisho](../threat-model.md).
