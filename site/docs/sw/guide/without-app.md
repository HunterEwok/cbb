<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: a9d8b94a0114 -->
# Bila programu

Kikundi cha kompyuta hakihitaji programu ya simu: kompyuta inaweza kushikilia kikundi.

![Kompyuta ya Linux inashikilia kikundi na kuongeza Mac na Windows kwa msimbo wa tarakimu sita](../images/without-app.svg)

## 1. Tengeneza kikundi kwenye kompyuta

[Sakinisha](install.md) Copy Beyond Borders kwenye kompyuta inayowashwa mara nyingi: Linux, Windows, Mac au FreeBSD. Inashikilia kikundi. Kisha:

```sh
sudo cbb new
```

Kompyuta hii sasa ni **mzizi** wa kikundi: inashikilia ufunguo wa kikundi na kuongeza na kuondoa vifaa. Ufunguo wake uko kwenye TPM au Secure Enclave ya kompyuta ikiwa inayo, vinginevyo kwenye faili inayolindwa na mfumo.

`cbb new` pia huonyesha **karatasi ya urejeshaji** ya kikundi mara moja: mistari minne ya herufi na tarakimu na msimbo wa QR. Iandike au uchapishe skrini, na uiweke mbali na vifaa vyako. Kwa hiyo unarudisha kikundi kompyuta hii ikipotea (`cbb recovery`); hakuna kinachohifadhi nakala.

## 2. Ongeza kompyuta

Kwenye mzizi:

```sh
sudo cbb pair
```

Hufungua dirisha la kuoanisha, huonyesha msimbo wa tarakimu sita na kusubiri. Kwenye kompyuta mpya endesha `sudo cbb pair -code` na uandike msimbo huo: inapata dirisha kwenye mtandao wa nyumbani na kujiunga ndani ya sekunde chache. Msimbo usio sahihi hutumia mojawapo ya majaribio matatu; dirisha hufungwa baada ya la tatu, au kompyuta ikishajiunga.

Kisha kila kompyuta husawazisha, kama katika [mwanzo wa haraka](quickstart.md#4-copy-on-one-paste-on-another).

## 3. Usitegemee kompyuta moja

Fanya kompyuta ya pili kuwa msimamizi, ili iweze pia kuongeza na kuondoa vifaa:

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a computer without a TPM or a Secure Enclave
```

Kompyuta ya Linux au ya Windows yenye TPM huweka ufunguo wa msimamizi humo, na Mac kwenye Secure Enclave yake. Kompyuta isiyo na chochote kati ya hivyo huuweka kwenye faili, kwa hivyo `cbb admin` huomba kwanza `-allow-file-key`: yeyote anayenakili faili hiyo hutenda kama msimamizi hadi msimamizi mwingine aondoe kompyuta hiyo, kwa hivyo fanya msimamizi kompyuta unayoitunza salama tu.

Mzizi ukipotea au kuharibika, kompyuta nyingine inakuwa mzizi kwa karatasi ya urejeshaji ya kikundi, na kila kifaa kingine kinabaki:

```sh
sudo cbb recovery            # then type the recovery key from the sheet
```

Zaidi katika [kifaa kikipotea au kuibiwa](lost-device.md).

## Kujiunga kutoka mtandao mwingine

Kompyuta isiyo nyumbani hujiunga kwa mwaliko kutoka kitovu ([Nje ya nyumbani](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)), au kupitia muunganisho unaoudhibiti tayari:

- **SSH** kwenda kwenye mzizi au msimamizi: kwenye kompyuta mpya endesha `ssh -N -L 18764:localhost:8764 user@that-machine`, kisha `sudo cbb pair` pale (katika kikao kingine cha SSH) na `sudo cbb pair -code 127.0.0.1:18764` hapa.
- **VPN yako mwenyewe** inayozipa mashine zote mbili anwani za kibinafsi: `sudo cbb pair` kwenye mzizi au msimamizi, kisha `sudo cbb pair -code ITS-VPN-ADDRESS:8764` hapa. Kwenye Linux, endesha kisakinishi tena baada ya kuweka VPN, ili kanuni zake za ngome ya moto ziruhusu mtandao wa VPN.

Kwa njia zote mbili, andika mstari ambao `cbb pair` huchapisha chini ya msimbo (`cbb://pair?...`) badala ya tarakimu sita: tarakimu peke yake hazitaji dirisha lolote mahali ambapo mDNS haifiki, na mstari unalitaja, ukiwa na msimbo uleule ndani yake.

Misimbo haisafiri kamwe: kila kompyuta hukokotoa msimbo wake yenyewe kutokana na kuoanisha, ambako hufanyika ndani ya SSH au VPN yako, na ndani ya TLS. Kompyuta mpya husawazisha kupitia njia hiyo hadi huduma yake ianzishwe upya; ili kuendelea kusawazisha baadaye, washa [usawazishaji nje ya nyumbani](away-from-home.md) kwenye zote mbili kabla ya kufunga muunganisho.

## Kikundi cha kabla ya 0.6

0.6 inasoma rekodi za kikundi za toleo 2 pekee, na haina njia ya kurudi kwenye vikundi vya zamani. Kompyuta iliyosasishwa kutoka toleo la awali huacha kikundi chake cha zamani inapoanza kwa mara ya kwanza: huhamisha faili za kikundi hadi `before-0.6` kwenye saraka yake ya hali, huhifadhi mipangilio yake, na `cbb status` husema hivyo. Unda kikundi upya: `cbb new` kwenye kompyuta moja, kisha `cbb pair -code` kwenye nyingine.
