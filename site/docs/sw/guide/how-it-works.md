<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 03894eb46cc0 -->
# Jinsi inavyofanya kazi

Kwa yeyote anayetaka kuelewa kinachotokea kwa nakala zake na jinsi Connect Beyond Borders inavyounganisha vifaa vyake. Connect Beyond Borders hushiriki ubao mmoja wa kunakili kati ya vifaa vyako mwenyewe bila akaunti, huduma ya wingu, wala seva kuu.

Kwa hatua za usanidi, tazama [Kuanza haraka](quickstart.md). Kwa maelezo ya kihandisi na muundo wa data kwenye mtandao, tazama [Muundo](../design.md) na [Itifaki](../protocol.md).

## Kinachotokea unaponakili

Unaponakili maandishi, picha, au faili kwenye kifaa kimoja, Connect Beyond Borders husimba nakala hiyo kwa ajili ya vifaa vyako vingine na kuituma kupitia mtandao wako wa nyumbani—au kupitia handaki lililosimbwa la kikundi chako unapokuwa mbali na nyumbani.

Jinsi kila kifaa kinavyotuma na kupokea nakala inategemea kile mfumo wake wa uendeshaji unachoruhusu:

- **Kompyuta na vifaa vidogo**: Kunakili hutuma nakala kwenye kikundi chako kiotomatiki, na nakala zinazoingia huingia kwenye ubao wako wa kunakili kiotomatiki wakati **Sawazisha** imewashwa.
- **Simu za Android**: Programu hupokea nakala chinichini kiotomatiki. Ili kutuma nakala, unaweza kuwasha huduma yake ya ufikivu kwa utumaji wa kiotomatiki, au uguse kitufe cha kusawazisha cha programu.
- **iPhone, simu za Aurora OS, na HarmonyOS**: Mifumo ya uendeshaji ya simu huzuia ufikiaji wa ubao wa kunakili chinichini. Programu ikiwa wazi kwenye skrini, husikiliza kiotomatiki kama kompyuta. Unapotumia kitufe cha kusawazisha au ishara (kama kitufe cha Kitendo au kugusa mara mbili nyuma kwenye iPhone), simu hubadilisha ubao wake wa kunakili na nakala mpya zaidi ya kikundi. Ikiwa ubao wa kunakili wa simu yako hauna kitu, hupokea nakala ya kikundi bila kuifuta.

Connect Beyond Borders hulinda kila nakala kwa tabaka kadhaa:

- **Usimbaji wa mwisho hadi mwisho**: Kabla nakala haijaondoka kwenye kifaa ulichoinakilia, kifaa hicho huisimba (huifunga) kwa ajili ya vifaa vya kikundi chako vinavyosoma nakala pekee na huitia sahihi kwa ufunguo wake wenyewe. Nakala iliyofungwa husafiri ndani ya muunganisho uliosimbwa (TLS 1.3) ambapo vifaa vyote viwili huthibitisha funguo za kila kimoja. Vifaa vinavyopitisha nakala tu, na seva zozote zilizo nje ya kikundi chako, haziwezi kusoma, kubadilisha, wala kughushi nakala.
- **Maandishi, picha, na faili**: Maandishi ya kawaida husafiri moja kwa moja ndani ya ujumbe wa usawazishaji. Unaponakili picha, faili, au maandishi yenye muundo, kifaa kinachonakili hutuma taarifa fupi kwanza; kila kifaa kinachopokea huleta maudhui yaliyofungwa hadi kufikia mpaka wake wa ukubwa. Tazama [Picha, faili na maandishi yenye muundo](images-and-files.md) na [Mipaka na muda](../reference/limits.md#copies).
- **Nywila na siri**: Connect Beyond Borders huruka vipengee ambavyo kidhibiti nywila hukiwekea alama ya siri. Siri unazotuma kwa makusudi hubaki kwenye kumbukumbu pekee, huisha muda wake baada ya muda mfupi (sekunde 60 kwa chaguo-msingi), na hufutwa kutoka kwenye mbao za kunakili muda wake unapokwisha.
- **Hakuna historia ya ubao wa kunakili**: Connect Beyond Borders haihifadhi historia ya nakala zilizopita. Kila nakala ina muda wa maisha unaotumika kwenye kikundi kizima (dakika 5 kwa chaguo-msingi kwa nakala za kawaida, na sekunde 60 kwa siri). Muda huo ukipita, vifaa huacha kuandika nakala hiyo kwenye mbao za kunakili.
- **Kusitisha usawazishaji**: Kila kifaa kina swichi ya **Sawazisha**. Kuzima **Sawazisha** huweka ubao wako wa kunakili kuwa wa faragha kwenye kifaa hicho huku kifaa kikiendelea kuunganishwa na kikundi. Msimamizi anaweza pia kunyamazisha kifaa ambacho ubao wake wa kunakili unafanya kazi vibaya.

## Kikundi

Vifaa vyako huunda **kikundi** kinachoshiriki ubao mmoja wa kunakili. Kila kifaa huhifadhi nakala ya rekodi za vifaa za kikundi zilizotiwa sahihi, zinazoorodhesha kila kifaa kwenye kikundi, jukumu lake, na vifaa vyovyote vilivyoondolewa. Kwa sababu kila kifaa huthibitisha rekodi hizi zilizotiwa sahihi chenyewe, kikundi chako hakihitaji seva kuu.

Kikundi ni cha mtu mmoja. Watu wawili wanaotaka mbao tofauti za kunakili huunda vikundi viwili.

Ni vifaa unavyoviruhusu kwa msimbo wa kuoanisha au msimbo wa QR pekee vinavyoweza kujiunga na kikundi chako. Ukipoteza kifaa, kukiondoa husambaza rekodi iliyotiwa sahihi ya kuondolewa ili kila kifaa kingine kikikatae mara moja. Tazama [Kifaa kikipotea](lost-device.md).

Kila kifaa kina jukumu katika kikundi:

| Jukumu | Vifaa vipi | Kinafanya nini |
|---|---|---|
| **Kifaa kikuu** (kinaitwa *root* katika zana za mstari wa amri na michoro) | Simu inayounda kikundi, au kompyuta unapoendesha [bila programu](without-app.md) | Hushikilia ufunguo mkuu wa kikundi, huongeza na kuondoa vifaa, huchagua wasimamizi, na kuweka kanuni za kikundi |
| **Msimamizi** | Simu nyingine au kompyuta iliyochaguliwa na kifaa kikuu | Huongeza na kuondoa vifaa vya kawaida, hugandisha kompyuta ya msimamizi iliyoibiwa, na hutuma vitendo vya usimamizi kama [kubandika kwa mbali](remote-paste.md); simu ya msimamizi inaweza pia kumwondoa msimamizi mwingine |
| **Mwanachama** | Kila kompyuta, simu, na kifaa kidogo (kama kipanga njia au Raspberry Pi; tazama [vifaa vidogo](../../member/README.md)) | Husawazisha ubao wa kunakili |
| **Mwanachama bila root** | Kompyuta ya Linux iliyosakinishwa bila haki za msimamizi (`sudo`) | Husawazisha kama mwanachama yeyote, lakini haiwezi kuwa kifaa kikuu, msimamizi, wala kitovu ([wanachama bila root](#rootless-members)) |
| **Kitovu** | Kompyuta, kipanga njia, au bodi ndogo nyumbani | Huunganisha vifaa vyako vikiwa mbali na nyumbani; kitovu kinachopitisha nakala tu hakisomi yoyote |

Apple Watch, saa ya Wear OS, au saa ya HarmonyOS iliyooanishwa hufanya kazi kupitia simu yake kuonyesha vifaa vya kikundi na kuwasha au kuzima usawazishaji ukiwa mbali na nyumbani; tazama [Programu](apps.md).

Mahali kifaa kinapohifadhi funguo zake huamua kile mwizi anachoweza kuchukua kifaa kikiibiwa:

- **Simu** huunda funguo zake ndani ya maunzi ya usalama—Secure Enclave kwenye iPhone, Android Keystore (StrongBox au TEE), kipengele salama kwenye Aurora OS, au HUKS kwenye HarmonyOS—ambapo funguo hizo hubaki. Kutia sahihi mabadiliko ya usimamizi huomba uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN ya programu yenyewe; usawazishaji wa kila siku hufanya kazi bila kuuliza.
- **Kompyuta** huhifadhi funguo zake za mwanachama na msimamizi kwenye maunzi zinapopatikana: Secure Enclave kwenye Mac zenye chipu ya Apple au chipu ya T2, na chipu ya usalama ya maunzi (TPM) kwenye kompyuta za Linux na Windows; kompyuta ambayo ni kifaa kikuu huhifadhi ufunguo wake mkuu humo pia. Kompyuta zisizo na maunzi hayo na vifaa vidogo huhifadhi funguo kwenye faili ambazo Connect Beyond Borders pekee ndiyo inaweza kusoma.

Kwa maelezo kamili kuhusu uhifadhi na uthibitishaji wa funguo, tazama [Funguo na uthibitisho](keys.md).

### Wanachama bila root

Usakinishaji wa kawaida wa Linux huomba haki za msimamizi (`sudo`) mara moja ili Connect Beyond Borders iweze kufanya kazi chini ya akaunti yake ya mfumo ndani ya mazingira finyu yaliyotengwa. Utengaji huo huzuia kivinjari chako, michezo, na programu nyingine kusoma funguo za kifaa chako.

Kwenye kompyuta ya Linux ambapo huna `sudo` (kama kompyuta ya kazini), usakinishaji bila root hufanya kazi chini ya akaunti yako mwenyewe ya mtumiaji. Husawazisha kama mwanachama yeyote, lakini programu yoyote unayoiendesha inaweza kunakili faili zake za funguo na kujifanya kifaa hicho. Kwa sababu hiyo, mwanachama bila root hawezi kamwe kuwa kifaa kikuu, msimamizi, wala kitovu. Orodha ya vifaa humwekea lebo **Mwanachama, bila root**.

Steam Deck inasaidia usakinishaji wa kawaida kwa sababu mtumiaji wake ana `sudo`; tazama [Kusakinisha kwenye SteamOS](install.md#steamos-steam-deck).

## Aina mbili za kikundi

Kikundi kinaweza kujumuisha angalau kompyuta moja au kifaa kidogo, au kinaweza kuwa na simu pekee. Mipangilio yote miwili hufanya kazi, na unaweza kuongeza kompyuta kwenye kikundi cha simu pekee wakati wowote.

| | Na kompyuta au kifaa kidogo | Simu pekee |
|---|---|---|
| Kifaa kikuu | Simu (ndani ya maunzi yake ya usalama), au kompyuta [bila programu](without-app.md) | Simu (ndani ya maunzi yake ya usalama) |
| Usawazishaji nyumbani | Miunganisho ya moja kwa moja iliyosimbwa kwenye mtandao wako wa nyumbani | Kupitia relei pofu wakati programu zinafanya kazi |
| Usawazishaji mbali na nyumbani | Kupitia kompyuta au kifaa kidogo kinachofanya kazi kama kitovu | Kupitia relei pofu wakati programu zinafanya kazi |
| Kifaa cha ziada kinachohitajika | Kompyuta, kipanga njia, au bodi ndogo | Hakuna |

Simu hufungua miunganisho inayotoka nje pekee kwa sababu mifumo ya uendeshaji ya simu hairuhusu programu kusubiri chinichini kwa miunganisho inayoingia. Kompyuta na vifaa vidogo husikiliza miunganisho inayoingia.

Kuongeza kompyuta inayobaki imewashwa—kama kompyuta ya mezani, seva ya nyumbani, kipanga njia, au Raspberry Pi—hukupa usawazishaji wa moja kwa moja wa ndani bila seva yoyote. Unaweza pia kuifanya kompyuta hiyo kuwa kitovu kutoka kwenye ukurasa wa kifaa chake ndani ya programu ili usawazishaji mbali na nyumbani ufanye kazi hata programu za simu zikiwa zimefungwa.

## Nyumbani

Kwenye mtandao mmoja wa nyumbani, vifaa vyako hupatana kiotomatiki kupitia ugunduzi wa mtandao wa ndani (mDNS) na kuunganishwa moja kwa moja kupitia miunganisho iliyosimbwa ya TLS 1.3. Hakuna kinachotoka nje ya mtandao wako, na hakuna seva katikati ya vifaa vyako. Unaweza kuzima kifaa chochote huku vifaa vilivyobaki vikiendelea kusawazisha.

![Nyumbani, simu, kompyuta mpakato, kompyuta ya mezani, na Raspberry Pi huunganishwa moja kwa moja kati yao kwa miunganisho iliyosimbwa inayopatikana kwa mDNS, bila seva kati yao](../images/at-home.svg)

Usawazishaji wa moja kwa moja nyumbani unahitaji angalau kompyuta moja au kifaa kidogo kwenye mtandao, kwa sababu simu huanzisha miunganisho inayotoka nje pekee.

**Mitandao ya nyumbani inayojulikana**: Kompyuta hukumbuka mitandao ya nyumbani ambako hukutana na kikundi chako (ikiwa imetambuliwa na mtandao na kipanga njia chake). Kwenye mtandao usiojulikana, kama Wi-Fi ya mkahawa au hoteli, kompyuta hubaki kimya: haijitangazi kwenye mtandao wa ndani wala haipokei miunganisho inayoingia.

**Mitandao tofauti nyumbani**: Ugunduzi wa mtandao wa ndani (mDNS) hauvuki vipanga njia kati ya mitandao tofauti ya ndani, kama mtandao maalum wa vifaa mahiri. Unaweza kuunganisha mitandao miwili ya nyumbani kwa njia tatu:

- Endesha Connect Beyond Borders kwenye kipanga njia kilichounganishwa na mitandao yote miwili.
- Ipe kompyuta au kifaa kidogo anwani ya kompyuta iliyo kwenye mtandao mwingine ([vifaa vidogo](../../member/README.md#install)).
- Unganisha mitandao yote miwili kupitia kitovu ([mbali na nyumbani](#away-from-home-the-hub)).

## Mbali na nyumbani: kitovu

Kompyuta mpakato au simu inapoondoka kwenye mtandao wako wa nyumbani, haiwezi kupata vifaa vyako vya nyumbani kupitia ugunduzi wa ndani. Ili kuendelea kusawazisha, mojawapo ya kompyuta, vipanga njia, au bodi zako ndogo nyumbani hufanya kazi kama **kitovu**: vifaa vyako vilivyo mbali huunganishwa tena nacho kupitia handaki lililosimbwa la kikundi chako (WireGuard), na kitovu hupitisha nakala kati yavyo na vifaa vilivyo nyumbani.

![Mbali na nyumbani, kompyuta mpakato na simu huunganishwa kupitia handaki la WireGuard la kikundi kwenye kitovu kilicho nyumbani, ambacho husawazisha na kompyuta ya mezani na Raspberry Pi kwenye mtandao wa nyumbani](../images/hub.svg)

Ndani ya handaki la WireGuard, vifaa huendesha miunganisho ileile ya TLS ya pande zote na nakala zilizofungwa mwisho hadi mwisho vinavyotumia nyumbani. Handaki hufanya kazi ndani ya Connect Beyond Borders yenyewe: hubeba trafiki ya Connect Beyond Borders pekee na halichukui nafasi ya VPN ya simu yako, kwa hiyo VPN yako mwenyewe huendelea kufanya kazi.

Unaweza kuchagua kati ya aina mbili za kitovu:

- **Kitovu kinachosoma nakala**: Kifaa chako kikuu (ikiwa ni kompyuta) au kompyuta ya msimamizi. Vifaa vyako hufunga nakala kwa ajili yake kama kwa kifaa kingine chochote kinachosoma, na [kiwango cha funguo](keys.md#the-three-levels) cha kikundi chako hutumika kwenye funguo zake.
- **Kitovu kinachopitisha nakala tu**: Kompyuta ya kawaida au bodi ndogo (kama Raspberry Pi au NAS) ambayo kifaa chako kikuu huichagua. Vifaa vyako hufunga nakala mwisho hadi mwisho bila kukihusisha, kwa hiyo hakisomi yoyote, hakitengenezi nakala zake zenyewe, na hakihitaji chipu ya usalama ya maunzi.

Sifa kuu za kitovu:

- **Kufikia kitovu moja kwa moja**: Kipanga njia chako huelekeza mlango mmoja wa UDP (8764 kwa chaguo-msingi) kwenye kitovu, au nyumba yako hutoa ufikiaji wa moja kwa moja wa IPv6.
- **Kitovu kikiwa kimezimwa**: Usawazishaji ukiwa mbali husitishwa wakati kitovu kimezimwa, na vifaa vilivyo nyumbani huendelea kusawazisha moja kwa moja bila hicho.
- **Usanidi nyumbani**: Vifaa hubadilishana funguo za handaki na kitovu vikiwa kwenye mtandao wako wa nyumbani, kwa hiyo washa **Kila mahali** (sawazisha ukiwa mbali na nyumbani) kabla ya kuondoka.
- **Vitovu kadhaa**: Kikundi kinaweza kuwa na vitovu kadhaa kwa mpangilio thabiti wa kipaumbele. Ni kitovu kilicho mtandaoni chenye kipaumbele cha juu zaidi pekee kinachohudumu kwa wakati mmoja; vitovu vya akiba husubiri bila handaki na kuchukua nafasi kiotomatiki ikiwa kitovu kinachofanya kazi kitasimama au kuwa nje ya mtandao kwa zaidi ya dakika moja.

Kwa hatua za usanidi, tazama [Mbali na nyumbani](away-from-home.md).

## Nyuma ya NAT ya mtoa huduma: kisambazaji

Watoa huduma wengi wa intaneti huweka nyumba nyuma ya anwani moja ya umma inayoshirikiwa (carrier-grade NAT), jambo linalozuia miunganisho inayoingia kufika nyumbani kwako hata kwa uelekezaji wa milango. Katika hali hiyo, kitovu chako hujisajili kwenye **kisambazaji**—seva kwenye intaneti inayopitisha pakiti zilizosimbwa za handaki kati ya vifaa vyako vilivyo mbali na kitovu chako. Kwa sababu kitovu chako hufungua muunganisho unaotoka nje kwenda kwenye kisambazaji, hufungui mlango wowote kwenye kipanga njia chako.

![Kitovu kilicho nyuma ya NAT ya mtoa huduma wa intaneti hufungua muunganisho unaotoka nje kwenda kwenye kisambazaji, kinachopitisha pakiti zilizosimbwa za handaki kati ya kompyuta mpakato na simu zilizo mbali na kitovu kilicho nyumbani](../images/forwarder.svg)

Kisambazaji hakishikilii funguo zozote za kikundi na hakiwezi kusoma ubao wako wa kunakili. Hupitisha tu pakiti za WireGuard zilizosimbwa kati ya vifaa vyako vilivyo mbali na kitovu chako.

Unaweza kutumia mojawapo ya visambazaji viwili:

- **Kisambazaji chako mwenyewe** kwenye seva yoyote yenye anwani ya umma, kama seva ndogo pepe ([Kuendesha seva zako mwenyewe](../admin/self-hosting.md#a-forwarder)).
- **Kisambazaji cha mradi** kwenye `cbb.tools`, ambacho anwani na ufunguo wake vimejengwa ndani ya Connect Beyond Borders na husasishwa kupitia orodha zilizotiwa sahihi.

Vifaa hujaribu anwani za moja kwa moja za kitovu chako kwanza na hutumia kisambazaji pale tu miunganisho ya moja kwa moja isipojibu.

## Mitandao inayozuia VPN

Baadhi ya mitandao ya Wi-Fi ya hoteli na ofisi, watoa huduma wa simu, na nchi huzuia trafiki ya kawaida ya WireGuard. Kwa chaguo-msingi, kitovu huficha handaki lake ili miunganisho ipite:

- **AmneziaWG**: Hubadilisha vichwa vya pakiti kwa nasibu na kuongeza mjazo ili handaki lisionekane kama WireGuard kwenye mtandao.
- **VLESS** (unapotumia kisambazaji): Hubeba handaki lililofichwa ndani ya kinachoonekana kama muunganisho wa kawaida wa HTTPS kwenda kwenye tovuti ya kisambazaji.

Vifaa hujaribu AmneziaWG kupitia UDP kwanza kwa sababu ni haraka zaidi, na huhamia VLESS kupitia HTTPS wakati UDP imezuiwa. Wakati VLESS imewashwa, vifaa havirejei kamwe kwenye WireGuard ya kawaida, kwa hiyo mitandao inayochuja haioni trafiki ya VPN isiyofichwa.

Kompyuta, vifaa vidogo (isipokuwa vipanga njia vya MIPS, ambavyo husawazisha nyumbani pekee; tazama [Vifaa, milango na faili](../reference/devices.md)), na kila programu ya simu zinaunga mkono AmneziaWG na VLESS zote mbili. Bila kujali jinsi handaki linavyofichwa, nakala hubaki ndani ya WireGuard, TLS ya pande zote, na usimbaji wa mwisho hadi mwisho. Ili kubadilisha mipangilio hii, tazama [Mitandao inayozuia VPN](blocked-networks.md) na [Amri](../reference/cli.md).

## Bila kitovu: relei pofu

Simu haiwi kitovu kamwe: simu hulala, hubadilisha mitandao, na haziwezi kupokea miunganisho ya chinichini kwa uhakika. Wakati kikundi hakina kompyuta, kipanga njia, au bodi ndogo inayofanya kazi kama kitovu—kama kikundi cha simu pekee—vifaa vyake hukutana kwenye **relei pofu**.

![Kompyuta mpakato iliyo mbali na nyumbani na Mac iliyo nyumbani huunganishwa kupitia mahandaki kwenye relei pofu, huku usimbaji wa mwisho hadi mwisho ukifanya kazi moja kwa moja kati ya vifaa hivyo viwili](../images/relay.svg)

Relei pofu ni mahali pa kukutana, si mwanachama wa kikundi. Kila kifaa hufungua handaki lililosimbwa kwenda kwenye relei, na relei huunganisha vifaa viwili vya kikundi kimoja ili TLS yao ya pande zote na nakala zilizofungwa mwisho hadi mwisho zipite moja kwa moja kati yao. Relei haiwezi kusoma ubao wako wa kunakili wala kujifanya kifaa.

Kwa sababu relei pofu haihifadhi chochote, vifaa vyote viwili lazima viwe mtandaoni kwa wakati mmoja ili kubadilishana nakala. Kompyuta na kila programu ya simu zinaweza kutumia relei pofu—ama relei ya wazi ya mradi kwenye `cbb.tools` au moja kwenye seva yako mwenyewe. Kifaa kikuu huwasha relei pofu kwa kikundi kwa idhini yako pekee. Tazama [Mbali na nyumbani](away-from-home.md#no-computer-for-a-hub) na [Kuendesha seva zako mwenyewe](../admin/self-hosting.md#a-blind-relay).

## Kila seva inaweza kuona nini

Wala kisambazaji wala relei pofu hakipokei kamwe orodha ya vifaa ya kikundi chako, majina ya vifaa, wala vitambulisho vya kudumu vya vifaa. Badala yake, kikundi chako hutengeneza **vitambulisho vya muda vya seva**—seti tofauti kwa kila seva—na kuvibadilisha takriban mara moja kwa mwezi (na mara moja unapoondoa kifaa). Kila seva huona vitambulisho vya nasibu vya muda (majina ya bandia) kwa kipindi hicho pekee, na seva mbili haziwezi kuunganisha trafiki ya kikundi chako pamoja.

| Seva | Inasoma ubao wa kunakili | Inajua ni vifaa vipi vinavyozungumza na lini | Inaendeshwa na |
|---|---|---|---|
| Kitovu kinachosoma nakala | Ndiyo (ni kifaa chako kikuu au kompyuta ya msimamizi) | Ndiyo | Wewe |
| Kitovu kinachopitisha nakala tu | Hapana (nakala zimefungwa bila kukihusisha) | Ndiyo (huona mtumaji, muda, na ukubwa uliokadiriwa) | Wewe |
| Kisambazaji | Hapana | Hapana (huona anwani za mtandao zinazobadilishana pakiti zilizosimbwa na kitovu chako, muda wa pakiti, na ukubwa wa pakiti) | Wewe, au mradi kwenye `cbb.tools` |
| Relei pofu | Hapana | Ndiyo (huona majina ya bandia ya muda ya vifaa vilivyo mtandaoni pamoja, anwani zake za mtandao, muda, na kiasi cha data) | Wewe, au mradi kwenye `cbb.tools` |

Connect Beyond Borders haitumii akaunti, hifadhi ya wingu, wala telemetria. Usawazishaji ukiwa mbali na nyumbani ukiwa umezimwa, huduma kwenye kompyuta huwasiliana kwenye mtandao wako wa nyumbani pekee. Usawazishaji ukiwa mbali na nyumbani ukiwa umewashwa, huduma huwasiliana na mtandao wako wa nyumbani na kitovu, kisambazaji, na relei ya kikundi chako pekee. Programu hutekeleza mpaka huu kwenye kila mfumo, na Linux na Windows pia huutekeleza kwa kanuni za mtandao za mfumo.

Programu ya simu ikiwa imefungwa na arifa zikiwa zimewashwa, vifaa vyako vinaweza kuiamsha simu kwa arifa iliyofungwa inayotumwa kupitia `cbb.tools` na huduma ya arifa ya simu. Ni simu yako pekee inayoweza kufungua arifa hiyo; hakuna huduma yoyote ya arifa kati ya hizo mbili inayoweza kusoma nakala zako.

Kwa orodha kamili ya kile pande nyingine (kama mtandao wako wa Wi-Fi, ukaguzi wa masasisho, na maduka ya programu) zinaweza kuona, soma [Faragha: nani anaona nini](privacy.md). Kwa maelezo kamili ya kiufundi, tazama [Muundo](../design.md) na [Itifaki](../protocol.md).
