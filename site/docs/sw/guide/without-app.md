<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: f06d2929ba18 -->
# Bila programu

Kikundi hakihitaji programu ya simu. Kompyuta inaweza kushikilia kikundi, na iPhone isiyo na programu hujiunga kwa njia ya mkato. Hii pia ndiyo njia wakati programu ya iPhone inasubiri TestFlight.

![Kompyuta ya Linux inashikilia kikundi na kuongeza Mac na Windows kwa msimbo wa tarakimu sita, na iPhone kwa wasifu na njia ya mkato](../images/without-app.svg)

## 1. Tengeneza kikundi kwenye kompyuta

[Sakinisha](install.md) Copy Beyond Borders kwenye kompyuta inayowashwa mara nyingi: Linux, Windows, Mac au FreeBSD. Inashikilia kikundi na kutoa njia ya mkato ya iPhone. Kisha:

```sh
sudo cbb new
```

Kompyuta hii sasa ni **mzizi** wa kikundi: inashikilia ufunguo wa kikundi na kuongeza na kuondoa vifaa. Ufunguo wake ni faili kwenye kompyuta, inayolindwa na mfumo; programu ya simu huhifadhi ufunguo huohuo kwenye chipu ya usalama ya simu.

## 2. Ongeza kompyuta

Kwenye mzizi:

```sh
sudo cbb pair
```

Huonyesha msimbo wa tarakimu sita na kusubiri. Kwenye kompyuta mpya, endesha pia `sudo cbb pair`: kwanza huonyesha msimbo wa QR kwa programu ya simu, ambao unaweza kuupuuza, kisha huuliza msimbo; andika tarakimu hizo sita pale. Kompyuta mpya hujiunga ndani ya sekunde chache.

Kisha washa ushirikiano kwenye kila kompyuta, kama katika [mwanzo wa haraka](quickstart.md#4-share-the-computers-clipboard): `sudo cbb mode shared`.

## 3. Ongeza iPhone kwa njia ya mkato

Kwenye mzizi, au kwenye kompyuta ya msimamizi inayojibu `clipboardbridge.local` (`cbb status` inasema kama inajibu):

```sh
sudo cbb pair -phone
```

Huchapisha msimbo wa QR, mwanzo wa alama ya kidole na msimbo wa tarakimu sita.

1. Changanua msimbo wa QR kwa kamera ya iPhone na ufuate ukurasa: sakinisha wasifu.
2. Hakikisha alama ya kidole ya wasifu inaanza kama ile iliyochapishwa (Mipangilio, Jumla, VPN na Usimamizi wa Kifaa, "CBB", Maelezo Zaidi), kisha uwashe uaminifu kamili kwake (Mipangilio, Jumla, Kuhusu, Mipangilio ya Kuaminiwa kwa Cheti).
3. Ongeza njia ya mkato "clipboardbridge" kutoka ukurasa uleule na uiendeshe mara moja; inauliza msimbo wa tarakimu sita.
4. Weka njia ya mkato kwenye kitufe cha Kitendo, au kwenye Gusa Nyuma (Mipangilio, Ufikivu, Mguso, Gusa Nyuma, Gusa Mara Mbili).

Mbonyezo mmoja kisha huchagua mwelekeo wenyewe: kilichonakiliwa kwenye kompyuta muda mfupi uliopita huja kwenye iPhone; la sivyo nakala mpya kwenye iPhone huenda kwenye kompyuta.

## 4. Usitegemee kompyuta moja

Fanya kompyuta ya pili kuwa msimamizi, ili iweze pia kuongeza na kuondoa vifaa:

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a computer without a TPM or a Secure Enclave
```

Kompyuta ya Linux au ya Windows yenye TPM huweka ufunguo wa msimamizi humo, na Mac kwenye Secure Enclave yake. Kompyuta isiyo na chochote kati ya hivyo huuweka kwenye faili, kwa hivyo `cbb admin` huomba kwanza `-allow-file-key`: yeyote anayenakili faili hiyo hutenda kama msimamizi hadi msimamizi mwingine aondoe kompyuta hiyo, kwa hivyo fanya msimamizi kompyuta unayoitunza salama tu.

Mzizi ukipotea au kuharibika, msimamizi huchukua kikundi, na kila kifaa kingine kinabaki:

```sh
sudo cbb takeover NAME       # on the admin; NAME is the lost root
```

iPhone zenye njia ya mkato huoanishwa tena baada ya kuchukua. Zaidi katika [kifaa kikipotea au kuibiwa](lost-device.md).

## Kujiunga kutoka mtandao mwingine

Kompyuta isiyo nyumbani hujiunga kwa mwaliko kutoka kitovu ([Nje ya nyumbani](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)), au kupitia muunganisho unaoudhibiti tayari:

- **SSH** kwenda kwenye mzizi au msimamizi: kwenye kompyuta mpya endesha `ssh -N -L 18764:localhost:8764 user@that-machine`, kisha `sudo cbb pair` pale (katika kikao kingine cha SSH) na `sudo cbb pair -code 127.0.0.1:18764` hapa.
- **VPN yako mwenyewe** inayozipa mashine zote mbili anwani za kibinafsi: `sudo cbb pair` kwenye mzizi au msimamizi, kisha `sudo cbb pair -code ITS-VPN-ADDRESS:8764` hapa. Kwenye Linux, endesha kisakinishi tena baada ya kuweka VPN, ili kanuni zake za ngome ya moto ziruhusu mtandao wa VPN.

Msimbo haupiti wazi kamwe: uoanishaji hufanyika ndani ya SSH au VPN yako, na ndani ya TLS. Kompyuta mpya husawazisha kupitia njia hiyo hadi huduma yake ianzishwe upya; ili kuendelea kusawazisha baadaye, washa [usawazishaji nje ya nyumbani](away-from-home.md) kwenye zote mbili kabla ya kufunga muunganisho.

## Kikundi cha kabla ya 0.6

0.6 inasoma rekodi za kikundi za toleo 2 pekee, na haina njia ya kurudi kwenye vikundi vya zamani. Kompyuta iliyosasishwa kutoka toleo la awali huacha kikundi chake cha zamani inapoanza kwa mara ya kwanza: huhamisha faili za kikundi hadi `before-0.6` kwenye saraka yake ya hali, huhifadhi mipangilio yake, na `cbb status` husema hivyo. Unda kikundi upya: `cbb new` kwenye kompyuta moja, kisha `cbb pair` kwenye nyingine.
