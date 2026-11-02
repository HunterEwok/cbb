<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d9f2991969be -->
# Kuanza haraka

Clipboard Bridge huipa simu yako na kompyuta zako ubao mmoja wa kunakili: unanakili kwenye kimoja na kubandika kwenye kingine. Vifaa huunda **kikundi** kwenye mtandao wako wa nyumbani. Simu hushikilia ufunguo wa kikundi na kuruhusu kila kifaa kipya kuingia, kwa hiyo hakuna anayeweza kujiunga bila wewe.

![Simu huongeza kila kompyuta kwa msimbo wake wa QR; kisha vifaa vinatumia ubao mmoja wa kunakili](../images/group.svg)

Ni hatua nne: sakinisha programu, sakinisha Clipboard Bridge kwenye kompyuta, changanua msimbo wa QR wa kompyuta, kisha washa ushiriki kwenye kompyuta hiyo.

Kikundi kinaweza kuwa na kompyuta moyoni mwake au kuundwa na simu pekee: njia zote mbili zinafanya kazi, na tunapendekeza kompyuta inayowashwa mara nyingi, kwa sababu inaweka usawazishaji ukiwa mbali na nyumbani ukiendelea wakati wowote ([aina mbili za kikundi](how-it-works.md#two-kinds-of-group)). Ukiwa na simu pekee, ruka hatua 2 hadi 4: kwenye kila simu nyingine gusa **I already use Clipboard Bridge on another phone**, kisha changanua msimbo unaoonyesha kwa **Connect a new device** kwenye simu ya kwanza (**+** ikishakuwa na vifaa).

## 1. Sakinisha programu kwenye simu yako

- **Android** 10 au mpya zaidi: pakua `clipboardbridge-X.Y.Z.apk` kutoka [toleo la hivi karibuni](https://github.com/HunterEwok/clipboardbridge/releases/latest) kwenye simu yenyewe na uifungue; ruhusu kivinjari kusakinisha programu Android inapouliza.
- **iPhone**: programu itakuja kupitia TestFlight, ambayo bado haijafunguliwa. Hadi hapo, iPhone hutumia njia ya mkato, na kompyuta hushikilia kikundi: tazama [Bila programu](without-app.md).

Fungua programu. Utaongeza kompyuta ya kwanza katika hatua ya 3.

## 2. Sakinisha Clipboard Bridge kwenye kompyuta

Chagua kompyuta yoyote kwenye mtandao wako wa nyumbani: laptopu, kompyuta ya mezani, Raspberry Pi.

Kwenye **Linux** au **Mac**, kwenye terminal:

```sh
curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh
```

Kwenye **Windows** 10 au 11, kwenye PowerShell iliyofunguliwa kwa "Run as administrator":

```powershell
irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
```

Kisakinishi huangalia faili ulizopakua, huanzisha Clipboard Bridge na kuuliza maswali mawili: kama kifungue ngome ya moto kwa ajili yake (jibu `y`) na kama kijisasishe chenyewe kiotomatiki (`y` pia ni jibu zuri). Kisha toka na uingie tena mara moja, au fungua terminal mpya kwenye Windows. Homebrew, winget, Docker na maelezo yote yako katika [Kusakinisha](install.md).

## 3. Ongeza kompyuta

Kwenye kompyuta:

```sh
sudo cbb pair
```

Kwenye Windows, endesha `cbb pair` kwenye terminal ya msimamizi. Huonyesha msimbo wa QR.

Kwenye programu, gusa **Connect a new device** na uchanganue msimbo. Programu huunda ufunguo wa kikundi (huomba alama ya kidole, uso au nambari ya siri) na kuongeza kompyuta. Hicho ndicho kikundi.

Ongeza kompyuta nyingine zote vivyo hivyo: sakinisha, `sudo cbb pair`, na **+** kwenye programu.

## 4. Shiriki ubao wa kunakili wa kompyuta

Kompyuta mpya huuweka ubao wake wa kunakili kwake yenyewe hadi useme vinginevyo. Ili unachonakili juu yake kifike kwenye kikundi, na kile ambacho kikundi kinanakili kifike juu yake:

```sh
sudo cbb mode shared
```

Kwenye Windows, endesha `cbb mode shared` kwenye terminal ya msimamizi.

Sasa nakili kwenye kompyuta na ubandike kwenye simu, au kinyume chake:

- **Android** hupokea nakala za kompyuta zenyewe. Ili kutuma nakala za simu, gusa kitufe kikubwa kwenye Mwanzo wa programu, kigae cha **Send clipboard** kwenye Mipangilio ya Haraka, au Send kwenye arifa; au washa **Send my copies by themselves** kwenye programu ili ifanyike yenyewe.
- **Kati ya kompyuta** katika hali ya ushiriki: nakili kwenye moja na ubandike kwenye nyingine. Hakuna cha kubonyeza.

Hali nyingine (kupokea tu, kutuma tu) ziko katika [amri](../reference/cli.md#cbb) (`cbb mode`), na mengine ambayo programu zinafanya yako katika [Programu](apps.md).

## 5. Inapendekezwa: acha kompyuta inayowaka kila wakati isaidie simu

Kikundi hufanya kazi na simu pekee, lakini mambo mawili ni bora kwenye kompyuta inayobaki imewashwa, kama seva ya nyumbani, Raspberry Pi au kompyuta ya mezani:

- **Ifanye msimamizi.** Kwenye simu, gusa kompyuta kwenye Mwanzo kisha **Make it an admin**. Kompyuta isiyo na TPM wala Secure Enclave huweka funguo zake kwenye faili, na programu hukuonya kwanza ([funguo](keys.md#the-three-levels)). Baada ya hapo inaweza pia kuongeza na kuondoa vifaa (`sudo cbb pair`, `sudo cbb revoke NAME`), kwa hiyo huhitaji simu mkononi kila mara. Simu inabaki mzizi wa kikundi, kifaa chake kinachoaminika zaidi: ufunguo wa mzizi haondoki kamwe kwenye chipu ya usalama ya simu.
- **Ifanye kitovu**, ili vifaa vyako viendelee kusawazisha vikiwa mbali na nyumbani. Tazama [Mbali na nyumbani](away-from-home.md).

Ongeza pia simu ya pili, ili kupoteza simu moja kusipoteze chochote: kwenye simu ya pili gusa **I already use Clipboard Bridge on another phone** na uchanganue msimbo wake kwa **+** kwenye ya kwanza. Simu ya kwanza huifanya msimamizi.

## Hatua zinazofuata

- [Jinsi inavyofanya kazi](how-it-works.md): kikundi, majukumu, na picha za kila njia ambayo vifaa huunganishwa, nyumbani na mbali.
- [Mbali na nyumbani](away-from-home.md): sawazisha kutoka popote kupitia kitovu.
- [Bila programu](without-app.md): kikundi kinachoshikiliwa na kompyuta, na njia ya mkato ya iPhone.
- [Utatuzi wa matatizo](troubleshooting.md), kitu kisipofanya kazi.
