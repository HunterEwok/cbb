<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 753c15aad88e -->
# Faragha: nani anaona nini

Kwa yeyote anayetaka kujua nini kinatoka kwenye vifaa vyake. Copy Beyond Borders haina akaunti, wingu wala telemetria: unachonakili huenda kwenye vifaa vya kikundi chako tu, kimesimbwa mwisho hadi mwisho. Ukurasa huu unaorodhesha kila kitu kingine ambacho mtu aliye nje ya kikundi anaweza kuona, na jinsi ya kukizima.

## Unachonakili

Maandishi, picha na faili hupita tu kati ya vifaa vya kikundi chako, ndani ya TLS 1.3 yenye vyeti vya kikundi chenyewe. Ukiwa mbali na nyumbani pia hupita ndani ya WireGuard, kupitia kitovu chako, na labda kupitia kisambazaji au relei. Hakuna seva, mtandao wala mtoa huduma anayeweza kuvisoma, zikiwemo seva za mradi. Kifaa kilichoondolewa kwenye kikundi hakipati kitu zaidi.

Mambo mawili ni vighairi, na yote mawili ni chaguo lako:

- **Roku** iliyoongezwa kwa `cbb remote add -roku -consent` hupata maandishi yake kama HTTP wazi kwenye mtandao wako wa nyumbani ([kibodi na televisheni](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- **Kitovu** ni kimoja cha vifaa vyako mwenyewe, kwa hiyo husoma nakala kama mwanachama mwingine yeyote.

## Kila mtu mwingine

| Nani | Anachoweza kuona | Jinsi ya kuepuka |
|---|---|---|
| Wengine kwenye mtandao wako wa nyumbani | kwamba vifaa vilivyopo vinaendesha Copy Beyond Borders, vitambulisho vyao vya kifaa vya nasibu na lebo ya kikundi chako katika mDNS, na ni vipi vinavyozungumza na kwa kiasi gani; kamwe si majina ya vifaa wala maudhui | hakuna cha kufanya; kompyuta huchapisha tu kwenye mitandao ya nyumbani inayoijua (mwanachama mwepesi kwenye kila mtandao) |
| Wengine kwenye mtandao ulio mbali na nyumbani (mkahawa, hoteli) | kwamba kifaa kinazungumza WireGuard, au kwa VLESS kwamba kinafungua muunganisho wa TLS kwenda kwenye kitovu au kisambazaji chako, lini na kwa kiasi gani | VPN ya mfumo huficha hata hilo |
| Kisambazaji (chako, au cha mradi kwenye `cbb.tools`) | anwani ambazo pakiti zilizosimbwa hutoka na zinazoelekea kwenye kitovu chako; si kikundi au kifaa kipi zinakomilikiwa | endesha chako mwenyewe, au elekeza mlango kwenye kitovu chako na usitumie chochote |
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
