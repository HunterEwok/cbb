<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 8cc314e35203 -->
# Faragha: nani anaona nini

Kwa yeyote anayetaka kujua kinachotoka kwenye vifaa vyake. Copy Beyond Borders haina akaunti, wingu wala telemetri: unachonakili kimesimbwa mwisho hadi mwisho, kimefungwa kwenye kifaa kinachokinakili kwa ajili ya vifaa vya kikundi chako vinavyosoma nakala, na hakuna kingine kinachoweza kukifungua: wala seva, wala mtandao, wala kifaa kilicho katikati. Ukurasa huu unaeleza kile ambacho vifaa vinavyopitisha nakala bado vinaweza kuona, na kila kitu ambacho mtu nje ya kikundi anaweza kuona, na jinsi ya kukizima.

## Unachonakili

Maandishi, picha na faili husimbwa mwisho hadi mwisho. Kifaa kinachonakili husimba kila nakala kwa ufunguo uliotengenezwa kwa ajili ya nakala hiyo tu, hufunga ufunguo huo kwa kila kifaa cha kikundi kinachosoma nakala (X-Wing, unaounganisha X25519 na ML-KEM-768 sugu kwa kompyuta za kwantamu) na kutia nakala sahihi kwa ufunguo wake wa mwanachama. Ni vifaa hivyo tu vinavyoweza kuifungua; kila kifaa hukagua sahihi, kwa hiyo hakuna kinachoweza kubadilisha nakala au kutengeneza moja kwa jina la kingine. Kisha nakala iliyofungwa husafiri ndani ya TLS 1.3 kwa vyeti vya kikundi chenyewe, na ukiwa mbali na nyumbani pia ndani ya WireGuard, kupitia kitovu chako na labda kisambazaji au relei. Hakuna seva, mtandao wala mtoa huduma anayeweza kuisoma, hata seva za mradi. Kifaa kinachoondolewa kwenye kikundi hakipati kitu tena, na kifaa kinachojiunga husoma nakala kuanzia inayofuata, si zile zilizotengenezwa kabla yake.

## Vifaa vilivyo katikati vinaona nini

Mara nyingi nakala hufika kwenye kifaa kupitia kingine: kupitia kitovu ukiwa mbali na nyumbani, au kupitia kompyuta inayoipitisha nyumbani. Vifaa hivyo havisomi chochote cha nakala ambayo haikufungwa kwa ajili yao, lakini kuipitisha kunahitaji kidogo, ambacho hubaki nje ya ufungaji:

- **Kifaa kipi kiliituma, na lini.** Muda huamua nakala ipi ni mpya zaidi, jambo ambalo kila kifaa kinahitaji, ikiwemo kitovu kinachopitisha nakala tu.
- **Imefungwa kwa ajili ya vifaa vipi.** Hiyo ni orodha ya vifaa vya kikundi, ambayo tayari wanaijua.
- **Ukubwa wake kwa ngazi** (1, 4, 16, 64 na 256 KB, 1 MB, kisha kila megabaiti inayofuata), na kama ina picha au faili, pamoja na jumla yake hadi 64 KB. Faili zote za nakala moja ni kipande kimoja kilichofungwa, kwa hiyo idadi yake haionekani.

Kisichoonekana kamwe: kama ni maandishi, siri, picha au faili; maandishi yenyewe; majina ya faili; ukubwa kamili.

## Vighairi

Vyote viwili ni chaguo lako:

- **Roku** iliyoongezwa kwa `cbb remote add -roku -consent` hupata maandishi yake kama HTTP wazi kwenye mtandao wako wa nyumbani ([kibodi na televisheni](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- **Kitovu kinachosoma nakala** ni msimamizi uliyemchagua, kwa hiyo nakala hufungwa kwa ajili yake kama kwa vifaa vyako vingine. Kompyuta inayowaka kila wakati ambayo funguo zake ziko kwenye faili tu, kama Raspberry Pi, ifanye badala yake **kitovu kinachopitisha nakala tu**: hakuna nakala inayofungwa kwa ajili yake, kwa hiyo haisomi yoyote ([ukiwa mbali na nyumbani](away-from-home.md)). Amri, kama kubandika kwa mbali au kitendo cha haraka, hufungwa kwa ajili ya kifaa kimoja zinachokiendea katika hali zote mbili ([kubandika kwa mbali](remote-paste.md)).
- **Apple Watch** au saa ya **Wear OS** hupata nakala kutoka kwa simu yake kupitia njia ambayo mfumo wenyewe husimba kati ya hivyo viwili, si zilizofungwa na Copy Beyond Borders.

## Kila mtu mwingine

| Nani | Anachoweza kuona | Jinsi ya kuepuka |
|---|---|---|
| Wengine kwenye mtandao wako wa nyumbani | kwamba vifaa vilivyopo vinaendesha Copy Beyond Borders, vitambulisho vyao vya kifaa vya nasibu na lebo ya kikundi chako katika mDNS, na ni vipi vinavyozungumza na kwa kiasi gani; kamwe si majina ya vifaa wala maudhui | hakuna cha kufanya; kompyuta huchapisha tu kwenye mitandao ya nyumbani inayoijua (mwanachama mwepesi kwenye kila mtandao) |
| Wengine kwenye mtandao ulio mbali na nyumbani (mkahawa, hoteli) | kwamba kifaa kinazungumza WireGuard, au kwa VLESS kwamba kinafungua muunganisho wa TLS kwenda kwenye kitovu au kisambazaji chako, lini na kwa kiasi gani | VPN ya mfumo huficha hata hilo |
| Kisambazaji (chako, au cha mradi kwenye `cbb.tools`) | anwani ambazo pakiti zilizosimbwa hutoka na zinazoelekea kwenye kitovu chako, lini na ukubwa wake; si kikundi au kifaa kipi zinakomilikiwa | endesha chako mwenyewe, au elekeza mlango kwenye kitovu chako na usitumie chochote |
| Relei pofu | ni vifaa vipi vya kikundi vilivyo mtandaoni sasa na vinavyozungumza, lini na kwa kiasi gani; haihifadhi chochote kati ya hayo | endesha yako mwenyewe, au tumia kitovu |
| Kampuni inayopangisha kisambazaji au relei | anwani zinazozungumza nacho, lini na kwa kiasi gani | VPN ya mfumo kwenye kifaa |
| GitHub, au `dl.cbb.tools` GitHub isipojibu | anwani yako na kwamba unatumia Copy Beyond Borders, kwa kila ukaguzi wa sasisho na upakuaji; hakuna kuhusu kikundi | `sudo cbb update -auto off`, au kioo chako mwenyewe (`-mirror`) |
| `cbb.tools` | anwani ya mzizi, mara moja kwa siku, anapopakua nakala iliyosainiwa ya orodha ya Google ya funguo za Android zilizofutwa (nakala hiyo itakapoanza, kwa funguo za kusaini za mradi) | hakuna kinachohitajika: ni faili ile ile kwa kila mtu |
| Apple, Intel au AMD | kwamba kifaa cha aina hiyo kiliwaomba kuthibitisha ufunguo wake, kutoka kwenye anwani yako | tu katika kiwango cha funguo cha **kali**; chaguo-msingi halimuulizi yeyote ([funguo](keys.md#the-three-levels)) |
| App Store, Google Play, F-Droid, Homebrew, winget | kwamba ulisakinisha programu, kama kwa programu yoyote | sakinisha faili iliyosainiwa ya toleo badala yake |

Hakuna kinachoripoti hitilafu au matumizi. Kumbukumbu hubaki kwenye kila kifaa; kukiwa na maelezo ya hitilafu yamewashwa (`CBB_DEBUG=1`), huwa na sababu zaidi, bado kwenye kifaa hicho tu.

## Tovuti

`cbb.tools` huhesabu ziara kwa GoatCounter yake yenyewe, bila vidakuzi na bila kutuma chochote kwa kampuni nyingine. Programu na huduma hazipakii kamwe chochote kutoka kwake isipokuwa faili zilizo hapo juu.

## Maelezo zaidi

- Kisambazaji na relei huweka nini, na mtoa huduma wao wa upangishaji anaona nini: [kuendesha seva zako mwenyewe](../admin/self-hosting.md#what-the-server-keeps).
- Kila seva hujifunza nini, sehemu kwa sehemu: [itifaki](../protocol.md), sehemu ya 13 na 14.
- Mashambulizi ambayo Copy Beyond Borders hujilinda dhidi yake, na yale isiyojilinda dhidi yake: [muundo wa vitisho](../threat-model.md).
