<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0ee54fa655f3 -->
# Mbali na nyumbani

Nyumbani vifaa vyako husawazisha vyenyewe. Ili kuendelea kusawazisha laptopu au simu inapokuwa mahali pengine, kompyuta moja nyumbani huwa **kitovu** cha kikundi, na vifaa vinavyosafiri hukifikia kupitia handaki lililosimbwa la kikundi chenyewe. Picha za kila hali ziko katika [Jinsi inavyofanya kazi](how-it-works.md#away-from-home-the-hub).

> Kati ya kompyuta hili limejengwa na kujaribiwa katika CI, bado si kwenye vifaa halisi; iPhone imesawazisha kwa data ya simu kupitia kitovu kwenye Mac na kisambazaji cha mradi. [Jedwali la hali](../../README.md#status) katika README linaonyesha nini kimejaribiwa wapi.

Usawazishaji ukiwa mbali na nyumbani umezimwa hadi uuwashe, kwenye kitovu na kwenye kila kifaa kinachopaswa kuutumia. Uweke **vifaa vyote vikiwa nyumbani**: hapo ndipo vinapokabidhiana funguo za handaki.

## 1. Chagua kitovu

Kitovu ni kompyuta: Linux, Windows, Mac, FreeBSD au kipanga njia chenye OpenWrt au OPNsense. Kilicho bora huwaka kila wakati: seva ya nyumbani, NAS, Raspberry Pi. Kompyuta unayowasha tu unapoihitaji inafaa pia; wakati kitovu kimezimwa, hakuna kinachosawazishwa ukiwa mbali na nyumbani, na kila kitu nyumbani bado husawazishwa.

Kitovu ni cha mojawapo ya aina mbili, na unachagua aina unapokifanya kitovu:

- **Kitovu kinachosoma nakala** ni msimamizi wa kikundi, kwa hiyo nakala hufungwa kwa ajili yake kama kwa vifaa vyako vingine, na [kiwango cha funguo](keys.md#the-three-levels) cha kikundi kinatumika kwa funguo zake. Katika kikundi kilichoundwa kwenye simu, simu huifanya kompyuta kuwa msimamizi kwanza.
- **Kitovu kinachopitisha nakala tu** ni kompyuta nyingine yoyote ya kikundi. Nakala hufungwa mwisho hadi mwisho kwa ajili ya vifaa vyako vingine na kamwe si kwa ajili yake, kwa hiyo haisomi yoyote, na funguo zake hazihitaji chipu ya usalama: Raspberry Pi au NAS kwenye Docker yenye funguo zake kwenye faili ni chaguo zuri. Haitengenezi, haisomi wala haibandiki nakala zake yenyewe.

Kwenye simu, gusa kompyuta, kisha **Make it a hub** na aina; programu ya Mac na programu ya trei huuliza vivyo hivyo. Kutoka kwenye kompyuta ya msimamizi, `sudo cbb global hub -on DEVICE -forward-only` huifanya kompyuta nyingine kuwa kitovu kinachopitisha nakala tu. Usawazishaji ukiwa mbali na nyumbani lazima uwe umewashwa huko kwanza (hatua ya 2 hapa chini, kwa `sudo cbb global on`).

## 2. Kiwashe kwenye kitovu

Kwenye Linux, kwenye terminal ya kitovu (kwenye Windows, bila `sudo`, kwenye terminal ya msimamizi):

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

Kwenye programu ya Mac au programu ya trei, fungua ukurasa wa kompyuta yenyewe na uchague **Make it a hub**: inauliza mara moja na kuwasha pamoja nayo usawazishaji ukiwa mbali na nyumbani, kupitia kisambazaji cha mradi.

- **Anwani** ni anwani ya IP ya umma ya nyumbani kwako (IPv4 au IPv6), au jina linaloielekeza. Ukurasa wa hali wa kipanga njia chako huionyesha, au tovuti kama `ifconfig.me`.
- **Kipanga njia** lazima kielekeze mlango wa UDP 8764 kwenye kitovu. Tafuta "port forwarding" au "virtual server" kwenye mipangilio yake.
- **Ngome ya moto ya kitovu**: `cbb global hub` huorodhesha kanuni inayoihitaji na kuuliza kabla ya kuiongeza.

**Kipanga njia cha OpenWrt kama kitovu** hakihitaji kuelekeza milango: endesha amri zile zile kwenye kipanga njia, kama root bila `sudo`. Kwa Yes, kanuni ya mlango wa UDP wa kitovu kutoka `wan` huwa sehemu ya kanuni za ngome ya moto za huduma yenyewe, zinazokuja na kwenda na huduma; `/etc/config/firewall` hubaki kama ilivyokuwa. Kipanga njia kilicho nyuma ya kipanga njia kingine (double NAT) bado kinahitaji kuelekeza kwenye kipanga njia cha mbele, au kisambazaji.

Huna anwani ya umma kwa sababu mtoa huduma wako anakuweka nyuma ya carrier-grade NAT? Basi kipanga njia hakiwezi kusaidia; tumia kisambazaji badala yake (hatua ya 5).

## 3. Kiwashe kwenye vifaa vingine

Nyumbani, kitovu kikiwa kimewashwa:

- **Kompyuta**: `sudo cbb global on` (kwenye Windows, kwenye terminal ya msimamizi).
- **Simu**: kwenye programu, Mipangilio, **Sync away from home**. Kisha acha programu wazi kwa muda nyumbani, ili ikutane na kitovu. iPhone husawazisha ukiwa mbali na nyumbani programu ikiwa wazi; Android pia chinichini. Katika kikundi kilichoundwa kwenye simu, simu hiyo huanza ikiwa kitovu, na swichi huonekana inapoacha kuwa kitovu: chini ya **Move the hub to a computer** ifanye kompyuta kuwa kitovu (ukihifadhi kisambazaji kwenye simu kwanza), au zima **This phone as the hub**.
- **Mwanachama mwepesi**: `sudo cbb global on` kwenye kifaa ([mwanachama mwepesi](../../member/README.md#sync-away-from-home)).

## 4. Kikague

```sh
cbb global
```

Kwenye kila kompyuta huonyesha kama usawazishaji ukiwa mbali na nyumbani umewashwa, kifaa kipi ni kitovu, kama handaki liko juu, na kilichoharibika kama halipo. Kisha toa laptopu au simu kwenye Wi-Fi ya nyumbani (data ya simu inatosha) na unakili kitu.

Isipounganishwa, sababu za kawaida ni kwamba kipanga njia hakielekezi mlango, au anwani si ile inayoonwa na intaneti. [Utatuzi wa matatizo](troubleshooting.md#sync-away-from-home) una zaidi.

Anwani ya nyumbani kwako ikibadilika, kitovu huvijulisha vifaa wakati ujao vitakapokutana; kwenye kompyuta, `cbb global` kisha husema uendeshe `sudo cbb global allow`.

## 5. Intaneti isipoweza kufikia nyumbani kwako: kisambazaji

Nyuma ya carrier-grade NAT, kitovu hujisajili badala yake kwenye **kisambazaji** kilicho kwenye intaneti, kwa muunganisho wa kutoka nje, kwa hiyo hakuna kinachohitaji kufunguliwa nyumbani. Kisambazaji hupitisha tu pakiti zilizosimbwa na hakina funguo.

```sh
sudo cbb global hub
```

Bila anwani zake, kitovu hupitia kisambazaji cha mradi kwenye `cbb.tools`: cbb inajua anwani na ufunguo wake, na simu inayokuwa kitovu huitumia pia. `-forwarder default` huiongeza kwa kitovu chenye anwani zake pia. Kwa [kisambazaji chako mwenyewe](../admin/self-hosting.md#a-forwarder) kwenye seva yoyote ndogo, toa anwani na ufunguo wake badala yake: `sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>`; kwenye simu, chini ya **This phone as the hub**.

Kitovu kinaweza kuwa na anwani yake na kisambazaji kwa wakati mmoja: vifaa hujaribu kitovu kwanza na kisambazaji mwisho.

## 6. Mitandao inayozuia VPN

Hoteli, ofisi na baadhi ya nchi huzuia WireGuard. Kitovu kinaweza kuficha handaki kwa AmneziaWG au kulificha ndani ya VLESS: tazama [Mitandao inayozuia VPN](blocked-networks.md).

## Kompyuta isiyo nyumbani: mwaliko

Kompyuta iliyo mbali inaweza kujiunga na kikundi kwa mwaliko kutoka kwenye kitovu, mara usawazishaji ukiwa mbali na nyumbani unapofanya kazi:

```sh
sudo cbb invite        # on the hub: writes cbb.cbbinvite, valid for an hour
```

Tuma faili kwa kompyuta mpya kupitia njia unayoiamini, kama programu ya ujumbe unayotumia kujitumia mwenyewe; ni siri hadi itumike. Huko, endesha `sudo cbb pair -invite cbb.cbbinvite`. Kompyuta zote mbili huonyesha alama ya vidole ya ufunguo wa mpya; kwenye kitovu, andika `yes` tu kama zinalingana. Simu bado haziwezi kujiunga kwa mwaliko: ziongeze nyumbani.

Njia nyingine za kujiunga ukiwa mbali, kupitia SSH au VPN yako mwenyewe, ziko katika [Bila programu](without-app.md#joining-from-another-network).

## Hakuna kompyuta ya kuwa kitovu

Simu inaweza kuwa kitovu wakati programu yake imefunguliwa (Mipangilio, **This phone as the hub**). Au vifaa hukutana kwenye **relei pofu** kwenye seva yako mwenyewe badala ya kitovu: kompyuta kwa `cbb global relay`, simu chini ya **Blind relay** kwenye Mipangilio. Relei haiwezi kusoma ubao wa kunakili lakini huona ni vifaa vipi vinavyozungumza, lini na kwa kiasi gani. Tazama [kuendesha seva zako mwenyewe](../admin/self-hosting.md#a-blind-relay).

Swichi ya **This phone as the hub** iko kwenye Mipangilio tu, si kwenye ukurasa wa simu katika orodha ya vifaa kama ilivyo kwa kompyuta: simu huwa kitovu tu wakati programu yake imefunguliwa (simu ya Android pia chinichini, kwa gharama ya betri), kwa hiyo kompyuta inayowashwa kila wakati ni kitovu bora zaidi.

Baadaye: relei pofu kwenye `cbb.tools` ambayo kikundi chochote kitaweza kuitumia.

## Kuzima

Ili kompyuta iache kuwa kitovu lakini iendelee kusawazisha ukiwa mbali na nyumbani, endesha `sudo cbb global hub off` hapo, au uchague **Stop being the hub** kwenye ukurasa wake katika programu ya Mac au programu ya trei; msimamizi anaweza kufanya hivyo kwa kompyuta nyingine pia (`sudo cbb global hub off -on NAME`). Vifaa vilivyounganishwa nayo huhamia kwenye kitovu kinachofuata cha kikundi. Ikiwa hakuna kitovu kingine, inauliza kwanza, kwa sababu vifaa vilivyo mbali na nyumbani huacha kusawazisha hadi kifaa fulani kiwe kitovu tena.

```sh
sudo cbb global off
```

Husahau funguo za handaki kwenye kifaa hicho. Funguo mpya za `cbb global on` ya baadaye hufikia kitovu kwenye mtandao wa nyumbani tu, kwa hiyo kifaa kilicho mbali sasa husawazisha tena baada ya kufika nyumbani tu. Kwenye simu, zima swichi kwenye Mipangilio.
