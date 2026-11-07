<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 1e2dc830708b -->
# Jinsi inavyofanya kazi

Ukurasa huu unaeleza Copy Beyond Borders kwa picha: nani yumo kwenye kikundi, jinsi vifaa vinavyopatana nyumbani, na kila njia ambayo vinaweza kuendelea kuwasiliana vikiwa mbali. Kanuni kamili ziko kwenye [muundo](../design.md); huzihitaji ili kuutumia.

## Kikundi

Vifaa vyako huunda **kikundi**. Ni vifaa unavyoviruhusu tu vinavyokuwa ndani yake, na huzungumza wao kwa wao tu, kila mara kwa usimbaji (TLS). Juu ya hilo kila nakala imesimbwa mwisho hadi mwisho: kifaa kinachonakili huifunga kwa ajili ya vifaa vya kikundi vinavyosoma nakala na kuitia sahihi, kwa hiyo kifaa kinachoipitisha tu hakiwezi kuisoma, kuibadilisha wala kuighushi. Kila kifaa kina jukumu:

| Jukumu | Nani | Kinafanya nini |
|---|---|---|
| **Mzizi** | simu iliyounda kikundi (au kompyuta, [bila programu](without-app.md)) | hushikilia ufunguo wa kikundi, huongeza na kuondoa vifaa, huteua wasimamizi |
| **Msimamizi** | simu ya pili, au kompyuta aliyoichagua mzizi | huongeza na kuondoa vifaa, kama mzizi |
| **Mwanachama** | kila kompyuta na kila simu | husawazisha ubao wa kunakili |
| **Mwanachama mwepesi** | kifaa kidogo cha Linux: kipanga njia, Raspberry Pi Zero | husawazisha, hakiongezi mtu yeyote ([mwanachama mwepesi](../../member/README.md)) |
| **Mwanachama bila root** | kompyuta ya Linux iliyosakinishwa bila `sudo` | husawazisha kama mwanachama, lakini kamwe si mzizi, msimamizi wala kitovu ([tazama hapa chini](#rootless-members)) |
| **Kitovu** | kompyuta nyumbani, au simu wakati programu yake imefunguliwa, ukipenda | huwezesha vifaa vyako kusawazisha vikiwa mbali na nyumbani; kinachopitisha nakala tu hakisomi yoyote |

Funguo za simu hutengenezwa ndani ya chipu yake ya usalama (Secure Enclave, Keystore ya Android) na hazitoki kamwe; kila sahihi kwa ufunguo wa mzizi wa kikundi au ufunguo wa msimamizi huomba uso wako, alama ya kidole au nambari ya siri, huku ufunguo ambao simu husawazisha nao ukifanya kazi bila kuuliza. Kompyuta huweka funguo zake kwenye faili ambazo Copy Beyond Borders pekee ndiyo huzisoma.

### Wanachama bila root

Kwa kawaida kisakinishi huhitaji `sudo` mara moja, ili Copy Beyond Borders ifanye kazi chini ya akaunti yake yenyewe: kivinjari chako, michezo yako na kila programu nyingine unayoendesha haziwezi kusoma funguo zake, na mfumo huweka huduma ndani ya mazingira finyu yaliyotengwa. Usakinishaji bila root huruka hilo, kwa kompyuta ambayo huna `sudo`, kazini kwa mfano. Husawazisha kama mwanachama yeyote, lakini programu yoyote yako inaweza kunakili ufunguo wake na kujifanya yeye, kwa hiyo kamwe hawezi kuwa mzizi, msimamizi wala kitovu, hata ukiomba. Orodha ya vifaa huuweka alama "rootless". Steam Deck haihitaji hili: inatumia usakinishaji wa kawaida ([kusakinisha](install.md#steamos-steam-deck)).

## Aina mbili za kikundi

Kikundi kinaweza kuwa na kompyuta moyoni mwake, au kuundwa na simu pekee. Zote mbili zinaungwa mkono kikamilifu, na unaweza kuhama kutoka moja hadi nyingine wakati wowote. Tunapendekeza kompyuta inayowashwa mara nyingi, kwa sababu iliyo chini ya jedwali.

| | Na kompyuta | Simu pekee |
|---|---|---|
| Nani anashikilia ufunguo wa kikundi | simu (ndani ya chipu yake ya usalama), au kompyuta [bila programu](without-app.md) | simu, ndani ya chipu yake ya usalama |
| Usawazishaji nyumbani | kila kifaa moja kwa moja | kila kifaa moja kwa moja |
| Usawazishaji mbali na nyumbani | kupitia kompyuta kama kitovu, wakati wowote | kupitia simu kama kitovu wakati programu yake imefunguliwa (kwenye Android pia chinichini), au relei pofu |
| Unachohitaji | kompyuta inayowashwa mara nyingi | hakuna kingine |

Kwa nini tunapendekeza kompyuta: huwa imewashwa mara nyingi zaidi kuliko programu inavyokuwa wazi kwenye simu, na iPhone huipa programu muda mfupi chinichini, kwa hiyo usawazishaji ukiwa mbali na nyumbani hufanya kazi tu. Kompyuta inayowaka kila wakati ikijiunga na kikundi cha simu, programu ya simu hutoa kuifanya kitovu.

## Nyumbani: kitovu hakihitajiki

Kwenye mtandao mmoja wa nyumbani vifaa hupatana vyenyewe (mDNS) na kuunganishwa moja kwa moja. Hakuna kinachotoka nje ya mtandao wako, na hakuna seva katikati: kifaa chochote kinaweza kuzimwa, na vingine vinaendelea kusawazisha.

![Nyumbani kila kifaa huzungumza moja kwa moja na kila kifaa kingine, bila seva](../images/at-home.svg)

**Mitandao miwili nyumbani**, kwa mfano mtandao tofauti wa vifaa mahiri: mDNS haivuki kipanga njia, kwa hiyo vifaa vilivyo kwenye mitandao tofauti havipatani vyenyewe. Programu za simu hukumbuka anwani za kila kompyuta kutoka kwenye msimbo wake wa QR na bado huifikia; mwanachama mwepesi anaweza kuambiwa anwani ya kompyuta ([`-peer`](../../member/README.md#install)); na kwa kila kitu kingine kitovu (hapa chini) huunganisha pande zote mbili.

## Mbali na nyumbani: kitovu

Laptopu au simu inapoondoka nyumbani, inahitaji njia ya kurudi. Kompyuta moja nyumbani huwa **kitovu** cha kikundi: vifaa vilivyo mbali huunganishwa nacho kupitia handaki la kikundi lenyewe lililosimbwa (WireGuard), nacho hupitisha ubao wa kunakili kwa wote walio nyumbani.

![Mbali na nyumbani, laptopu na simu hufikia kitovu cha nyumbani kupitia handaki la WireGuard la kikundi](../images/hub.svg)

- Kitovu ni kompyuta yako mwenyewe: Linux, Windows, Mac, FreeBSD au kipanga njia. Ni cha mojawapo ya aina mbili. **Kitovu kinachosoma nakala** ni msimamizi, kwa hiyo nakala hufungwa kwa ajili yake kama kwa vifaa vyako vingine. **Kitovu kinachopitisha nakala tu** kinaweza kuwa kompyuta yoyote ya kikundi, kwa mfano Raspberry Pi yenye funguo zake kwenye faili: nakala hufungwa mwisho hadi mwisho bila kukihusisha, kwa hiyo hakisomi yoyote, na funguo zake hazihitaji chipu ya usalama.
- Kipanga njia chako huelekeza mlango mmoja wa UDP (8764) kwenye kitovu, ili intaneti iweze kukifikia.
- Kitovu si lazima kibaki kimewashwa. Kikiwa kimezimwa, hakuna kinachosawazishwa ukiwa mbali na nyumbani, na vifaa vilivyo nyumbani bado husawazisha bila hicho.
- Vifaa hupata maelezo ya kitovu vikiwa nyumbani, kwa hiyo washa usawazishaji ukiwa mbali na nyumbani kabla ya kuondoka.

Kuuweka kumeelezwa katika [Mbali na nyumbani](away-from-home.md).

## Intaneti isipoweza kufikia kitovu chako: kisambazaji

Watoa huduma wengi wa intaneti huweka nyumba nyuma ya anwani moja ya pamoja (carrier-grade NAT), na hapo hakuna uelekezaji wa mlango unaosaidia. Badala yake kitovu kinaweza kujisajili kwa **kisambazaji**, seva iliyo kwenye intaneti inayopitisha pakiti zilizosimbwa za handaki kati ya vifaa vyako na kitovu chako. Kitovu hupiga simu nje kwa kisambazaji, kwa hiyo hakuna kinachohitaji kufunguliwa nyumbani.

![Kitovu kilicho nyuma ya NAT ya mtoa huduma hupiga nje kwa kisambazaji, kinachopitisha handaki kutoka kwa vifaa vilivyo mbali](../images/forwarder.svg)

Kisambazaji hakina funguo na hakiwezi kusoma chochote: huona tu pakiti zilizosimbwa zinazoelekea kwenye kitovu chako, zinakotoka, lini na ukubwa wake. Kuna aina mbili:

- **Chako mwenyewe**: `cbb forward` kwenye seva yoyote yenye anwani ya umma, seva pepe ya bei nafuu kwa mfano ([kuendesha seva zako mwenyewe](../admin/self-hosting.md)).
- **Kisambazaji cha Copy Beyond Borders** kwenye `cbb.tools`, kinachoendeshwa na mradi kwa kila mtu. Kinajaribiwa na bado hakijafunguliwa kwa wote; anwani na ufunguo wake vitakuwa kwenye ukurasa huu kikifunguliwa.

Vifaa hujaribu anwani ya kitovu chenyewe kwanza na kisambazaji mwisho.

## Mtandao unapozuia WireGuard

Baadhi ya mitandao (hoteli, ofisi, nchi fulani) huzuia trafiki ya VPN. Kitovu kinaweza kuficha handaki la kikundi:

- **Ufichaji** (`-obfuscate`): handaki huzungumza AmneziaWG, ambayo haifanani na WireGuard kwenye waya. Kompyuta na programu zote mbili za simu zinaiunga mkono.
- **VLESS na REALITY** (`-vless`, kupitia kisambazaji): vifaa hufikia kisambazaji ndani ya kinachoonekana kama muunganisho wa kawaida wa HTTPS kwenye tovuti maarufu. Kwa mitandao inayozuia yote mawili hapo juu. Kompyuta na programu zote mbili za simu zinaiunga mkono.

Mwanachama mwepesi huzungumza WireGuard ya kawaida tu, kwa hiyo kwa mojawapo ya hizi husawazisha nyumbani tu.

## Simu pekee: simu kama kitovu

Kikundi cha simu pekee, au simu na Mac, hakina kompyuta ya kuwa kitovu. Njia mbili hukiweka kikisawazisha ukiwa mbali na nyumbani:

- **Simu kama kitovu**, wakati programu yake imefunguliwa (Mipangilio, **This phone as the hub**; imewashwa tangu mwanzo kwenye kikundi kilichoundwa kwenye simu). Simu nyingine, televisheni na wanachama wepesi huunganishwa nayo nyumbani, na kwa kisambazaji huifikia kutoka mbali pia. Kwenye Android inaweza kuendelea kufanya kazi chinichini; iPhone hutoa huduma tu programu ikiwa wazi.
- **Relei pofu yako mwenyewe** (`cbb relay` kwenye seva yako). Inachukua nafasi ya kitovu kama mahali pa kukutana, lakini si mwanachama: usimbaji fiche wa vifaa hupita ndani yake mwisho hadi mwisho, kwa hiyo haiwezi kusoma ubao wa kunakili. Huona ni vifaa vipi vyako vinavyozungumza, na lini. Kompyuta na programu zote mbili za simu zinaweza kuitumia.

![Relei pofu huunganisha laptopu iliyo mbali na Mac iliyo nyumbani; usimbaji fiche hupita ndani yake mwisho hadi mwisho](../images/relay.svg)

Kikundi kinaweza kuwa na vitovu kadhaa: mzizi, kila msimamizi aliye na kitovu kilichowekwa, na vitovu vinavyopitisha nakala tu. Vifaa vilivyo mbali na nyumbani hutumia cha kwanza kinachojibu, simu kwanza, kwa hiyo kikundi cha simu na kompyuta huendelea kufanya kazi wakati programu ya simu imefungwa.

**Imepangwa:** relei pofu kwenye `cbb.tools` kwa kila mtu asiyetaka kuendesha kitovu au relei. Itaona ni vifaa vipi vinavyozungumza na lini, kamwe isione kinachonakiliwa, na wewe mwenyewe ndiye unayeiwasha.

## Kila seva inaweza kuona nini

| Seva | Inasoma ubao wa kunakili | Inajua ni vifaa vipi vyako vinavyozungumza, na lini | Ni ya nani |
|---|---|---|---|
| Kitovu kinachosoma nakala | ndiyo, ni kifaa chako na msimamizi | ndiyo | chako |
| Kitovu kinachopitisha nakala tu | hapana: nakala zimefungwa bila kukihusisha | ndiyo | chako |
| Kisambazaji | hapana | hapana: huona anwani ambazo pakiti zilizosimbwa hutoka na zinazoelekea kwenye kitovu chako, lini na ukubwa wake | chako, au cha mradi kwenye `cbb.tools` |
| Relei pofu | hapana | ndiyo | chako (moja kwenye `cbb.tools` imepangwa) |

Hakuna kingine kinachohusika: hakuna akaunti, hakuna wingu, hakuna telemetria. Kila mtu mwingine anayeweza kuona chochote, kuanzia Wi-Fi yako hadi ukaguzi wa masasisho, ameorodheshwa katika [faragha](privacy.md). Usawazishaji ukiwa mbali na nyumbani ukiwa umewashwa, huduma ya Copy Beyond Borders kwenye kompyuta inaweza kufikia mtandao wa nyumbani tu na kitovu, kisambazaji na relei vya kikundi chenyewe.
