<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 9b05c71a6bfc -->
# Kibodi na televisheni

Kwa yeyote anayetaka kuandika nenosiri refu, kiungo au utafutaji kwenye televisheni, kompyuta kibao, kiweko cha michezo au kompyuta ambayo haina chochote cha Copy Beyond Borders. Kifaa kimoja cha kikundi chako huandika maandishi hayo pale kama kibodi au kama rimoti ya televisheni, unapogusa wewe au msimamizi anapotuma ubandikaji wa mbali.

## Chagua njia

| Njia | Huandika kwenye | Inahitaji |
|---|---|---|
| [Simu ya Android kama kibodi ya Bluetooth](#an-android-phone-as-a-bluetooth-keyboard) | kila kinachopokea kibodi ya Bluetooth: televisheni, kompyuta kibao, simu, kompyuta, Steam Deck, PlayStation 5 | Android 10 au mpya zaidi yenye wasifu wa kibodi ya Bluetooth |
| [Kompyuta ya Linux kama kibodi ya Bluetooth](#a-linux-computer-as-a-bluetooth-keyboard) | kila kinachopokea kibodi ya Bluetooth LE | BlueZ 5.50 au mpya zaidi na adapta yenye Bluetooth 4.0 au mpya zaidi |
| [Nano ESP32 kama kibodi ya USB au ya Bluetooth](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | kupitia USB pia BIOS, ombi la usimbaji fiche wa diski, Xbox na Nintendo Switch | Arduino Nano ESP32 katika kikundi chako |
| [Kompyuta kama rimoti ya televisheni](#a-computer-as-the-tvs-remote) | Android TV, Google TV au Roku kwenye mtandao wako wa nyumbani | kompyuta ya Linux, macOS, Windows au FreeBSD nyumbani |

Xbox na Nintendo Switch hupokea kibodi za USB tu, kwa hivyo kwazo tumia Nano ESP32. macOS, Windows na iPhone haziruhusu programu yoyote kufanya kazi kama kibodi ya Bluetooth.

## Mpangilio wa kibodi lazima ulingane

Kibodi hutuma vitufe, si herufi: kifaa kinachoandikiwa hugeuza kila kitufe kuwa herufi kwa mpangilio wake chenyewe. Kwa hivyo ambia kibodi ni mpangilio gani unaotumika pale, Kiingereza (US) au Kirusi. Maandishi yenye herufi ambayo mpangilio huo hauna kitufe chake hayaandikwi kabisa, na unaambiwa ni herufi gani; hakuna kitu kingine kinachoandikwa badala yake. Mstari mpya hubonyeza Enter na kichupo hubonyeza Tab.

Uandishi ni wa polepole kwa makusudi, herufi 20 kwa sekunde kwa chaguo-msingi: baadhi ya televisheni hupoteza vitufe vinavyofika kwa kasi zaidi. Ipunguze ikiwa herufi zinapotea.

## Simu ya Android kama kibodi ya Bluetooth

1. Kwenye programu, fungua Mipangilio, Kibodi ya Bluetooth, na uwashe **Act as a Bluetooth keyboard**. Ruhusu Bluetooth ("Vifaa vya karibu") ukiulizwa. Programu ikisema simu haiwezi kufanya kazi kama kibodi, mtengenezaji wake aliacha wasifu huo (kwa mfano Fairphone 6 na baadhi ya simu za Huawei, Honor na Xiaomi za zamani); tumia njia nyingine. Ikisema programu nyingine inaweza kuwa kibodi ya simu, zima kibodi ya programu hiyo: programu moja tu kwa wakati mmoja inaweza kuwa kibodi hiyo.
2. Gusa **Make this phone visible**. Ndani ya dakika mbili, ongeza simu kwenye kifaa, katika mipangilio yake ya Bluetooth, kama ungeongeza kibodi.
3. Chini ya **Type into**, chagua kifaa. Programu inasema "Connected to …".
4. Weka **The device's keyboard layout** na, ikihitajika, **Speed** (herufi 10, 20 au 40 kwa sekunde).
5. Gusa **Type the clipboard**. Maandishi yanaonekana pale ambapo kifaa kina mwelekeo, kwa hivyo fungua kwanza sehemu ya maandishi kwenye kifaa hicho.

Ili ubandikaji wa mbali wa msimamizi uandikwe pale badala ya kwenye simu, washa ubandikaji wa mbali kwenye programu kisha **Type remote pastes there**. Maandishi yenye mstari mpya yanahitaji Enter iruhusiwe kwa ubandikaji wa mbali.

## Kompyuta ya Linux kama kibodi ya Bluetooth

```sh
sudo cbb keyboard on -layout us    # registers the keyboard with BlueZ
sudo cbb keyboard pair             # discoverable for two minutes
# add "CBB <this computer's name>" on the device, in its Bluetooth settings
cbb keyboard                       # shows whether it is connected
echo 'the text' | sudo cbb keyboard type
```

`on` pia inakubali `-rate N`, kasi, herufi 5 hadi 60 kwa sekunde, na `-pastes`, ambayo hutuma ubandikaji wa mbali wa kikundi kwa kifaa badala ya skrini ya kompyuta hii: `sudo cbb keyboard on -layout us -rate 10 -pastes`. `sudo cbb keyboard off` huisimamisha. Kibodi na panya za Bluetooth za kompyuta yenyewe zinaendelea kufanya kazi.

## Nano ESP32 kama kibodi ya USB au ya Bluetooth

Bodi hii ni mwanachama mwepesi wa kikundi chako. Kwenye kiweko chake:

- `usb keyboard` hufanya mlango wake wa USB kuwa kibodi, na kiweko kama mlango wa pili wa serial kando yake; ichomeke kwenye kifaa. Hufanya kazi kabla mfumo wowote haujaanza: kwenye BIOS, mipangilio ya UEFI au ombi la usimbaji fiche wa diski.
- `ble on`, kisha `ble pair`, huifanya kibodi ya Bluetooth LE; ongeza "CBB Nano ESP32" kwenye kifaa ndani ya dakika mbili. Hukumbuka hadi vifaa vinne; `ble forget` huvisahau.
- `layout ru` au `layout us` na `rate N` huweka mpangilio na kasi.
- `type TEXT` huandika kwenye kifaa cha Bluetooth kilichounganishwa, au la sivyo kwenye cha USB.

Ubandikaji wa mbali wa kikundi kwenda kwenye bodi huandikwa vivyo hivyo. Mwongozo wa bodi yenyewe uko katika [esp32/](../../esp32/README.md).

## Kompyuta kama rimoti ya televisheni

Kompyuta ya nyumbani inaweza kuandika kwenye televisheni kupitia mtandao, kama rimoti yake inavyofanya. Hakuna kinachosakinishwa kwenye televisheni, na televisheni haiungani kamwe na kikundi.

Android TV au Google TV huoanishwa mara moja:

```sh
sudo cbb remote add -name living-room-tv living-room-tv.lan   # the TV shows a six-digit code
sudo cbb remote code 123456              # within two minutes
```

Apple TV huoanishwa vivyo hivyo, kwa PIN ya tarakimu nne inayoonyesha. Kwanza kwenye Apple TV, weka Settings, AirPlay and HomeKit, Allow Access kuwa "Everyone on the Same Network": ikiwa "Only People Sharing This Home" inakataa kila uoanishaji.

```sh
sudo cbb remote add -appletv -name lounge 192.168.1.30   # the Apple TV shows a four-digit PIN
sudo cbb remote code 1234                # within two minutes
```

Roku haina uoanishaji wala usimbaji fiche: maandishi hupita kwenye mtandao wako wa nyumbani kama HTTP wazi, kwa hivyo huongezwa tu unaposema hivyo kwa `-consent`. Kwenye Roku, kwanza weka Mipangilio, Mfumo, Mipangilio ya hali ya juu ya mfumo, Udhibiti kwa programu za simu kuwa Imewezeshwa au Ruhusu.

```sh
sudo cbb remote add -roku -consent 192.168.1.40
```

Kisha fungua sehemu ya utafutaji au ya maandishi kwenye televisheni kwa rimoti yake yenyewe, na uandike:

```sh
echo 'the film' | sudo cbb remote type
sudo cbb remote pastes living-room-tv on   # an admin's remote pastes go to that TV
```

`cbb remote` huorodhesha televisheni, `-tv NAME` huchagua moja zikiwa nyingi, na `sudo cbb remote remove NAME` husahau moja. Android TV au Apple TV iliyowekwa upya, au iliyosahau kompyuta hii, lazima ioanishwe tena.

## Usalama

- Kibodi ya Bluetooth huandika popote kifaa kinapokuwa na mwelekeo, kana kwamba uko kwenye kibodi yake. Ioanishe tu na vifaa unavyokusudia kuandikia, na uisahau pande zote mbili unapoacha kuitumia.
- Ubandikaji wa mbali ukitumwa kwa kibodi au televisheni, msimamizi yeyote wa kikundi chako anaweza kuandika pale. Uwashe tu pale unapouhitaji; huzimika pamoja na ubandikaji wa mbali.
- Televisheni hufikiwa tu kwenye mtandao wa nyumbani: anwani ya nje yake hukataliwa, jina lijiotatue baadaye kuwa lolote.
- Maandishi ya Roku hayajasimbwa fiche kwenye mtandao wa nyumbani. Usitume manenosiri kwa Roku.

## Mipaka

- Kwenye televisheni halisi imejaribiwa tu na Apple TV 4K, kuandika kupitia `cbb remote`; mengine hujaribiwa dhidi ya BlueZ, Android TV, Apple TV na Roku bandia.
- Programu za simu bado haziwezi kuwa rimoti ya televisheni; televisheni za Samsung na LG zitafuata ([ramani ya njia](../roadmap.md), kipengele cha 25).
- Kibodi huandika herufi 4,096 kwa kila mara kwa upeo.

Kila chaguo liko katika [amri](../reference/cli.md); milango ya televisheni iko katika [vifaa, milango na faili](../reference/devices.md#ports); jinsi inavyofanya kazi ndani iko katika [maelezo ya programu](../apps.md#android-the-bluetooth-keyboard).
