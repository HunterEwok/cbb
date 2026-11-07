<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 18b8e122d883 -->
# Wakati kitu hakifanyi kazi

Anza na `cbb status` kwenye kifaa chenye tatizo: kinasema kama huduma inaendesha, kiko kwenye kikundi gani, ni wanachama gani wameunganishwa na hali ya usawazishaji nje ya nyumbani. Kila ujumbe ni mfupi; `CBB_DEBUG=1 cbb status` (kwenye Windows kwanza `$env:CBB_DEBUG = "1"`) huonyesha kosa la msingi chini yake. Kumbukumbu ya huduma daima ina maelezo: kwenye Linux `journalctl -u cbb`, na ya kiunganishi cha eneo-kazi iko kwenye jarida la kikao, `journalctl --user`; mifumo mingine iko katika [faili na kumbukumbu](../reference/devices.md#files-and-logs). Swichi ya maelezo ya kila sehemu, ikiwemo programu na visakinishi, iko katika [ujumbe wa makosa na maelezo](../reference/errors.md).

## Amri

**"the CBB service is not running"**: ianzishe (`sudo systemctl start cbb` kwenye Linux; `sudo launchctl kickstart -k system/tools.cbb` kwenye Mac; `Start-Service cbb` kwenye Windows) na uangalie kumbukumbu yake.

**"permission denied" kwenye soketi ya udhibiti, mara baada ya kusakinisha**: kisakinishi kilikuongeza kwenye kikundi `cbb`, na kikundi huhesabiwa tu kuanzia kuingia kunakofuata. Toka kisha uingie tena (kwenye Windows, fungua terminali mpya); hadi hapo, `sudo cbb ...` inafanya kazi.

## Vifaa havionani

- **Ngome ya moto.** Wanachama wanahitaji TCP 8764 (au mlango wako) na UDP 5353 (mDNS) kutoka mtandao wa nyumbani. Visakinishi huviongeza unapojibu Ndiyo; ngome zipi za moto wanazozijua, na amri za zingine, ziko katika [ngome ya moto](install.md#the-firewall). Ngome ya moto ikiwashwa baadaye, endesha kisakinishi tena. Ikiwa `cbb status` inaonya kwamba wengine hawawezi kuunganishwa na kompyuta hii, ngome yake ya moto inazuia mlango wa wanachama.
- **Mtandao mdogo mwingine au VLAN.** mDNS haivuki rauta, kwa hivyo vifaa vilivyo kwenye, kwa mfano, 192.168.0.x na 192.168.20.x havipatani. Washa [usawazishaji nje ya nyumbani](away-from-home.md) ukiwa na kitovu upande mmoja, au, kwa mwanachama mwepesi, taja kompyuta kwa `-peer` kwenye huduma yake ([mwanachama mwepesi](../../member/README.md#install)).
- **Wi-Fi ya wageni au utengaji wa wateja** kwenye rauta huvizuia vifaa kuzungumza kabisa; viweke kwenye mtandao mkuu.
- **Kikundi tofauti.** `cbb status` huonyesha kikundi; vifaa vya vikundi viwili havisawazishi kamwe. Ili kuhamisha kompyuta kwenye kikundi sahihi, endesha `sudo cbb leave` juu yake, kisha uioanishe na kikundi sahihi, na uiondoe kwenye kikundi kisicho sahihi kupitia kifaa cha kikundi hicho.
- **Imeondolewa kwenye kikundi.** `cbb status` husema hivyo, na wanachama wa kikundi huikataa. Endesha `sudo cbb leave` juu yake (kwenye programu: Ondoka kwenye kikundi), kisha uioanishe tena.

## Uoanishaji unashindwa

- **"wrong code"**: kila dirisha la uoanishaji huruhusu majaribio matatu; endesha `cbb pair` tena upate msimbo mpya.
- **Simu haifikii kompyuta baada ya kuchanganua msimbo wake wa QR**: simu na kompyuta lazima ziwe kwenye mtandao mmoja, na mlango wa kompyuta lazima uwe wazi (juu). Kwenye iOS, ruhusu Mtandao wa Ndani kwa programu (Mipangilio, Faragha na Usalama, Mtandao wa Ndani).

## Usawazishaji nje ya nyumbani

`cbb global` kwenye kifaa na kwenye kitovu inasema nini kimekosewa. Sababu za kawaida: rauta haipitishi mlango wa UDP wa kitovu kwenda kwenye kitovu, ngome ya moto ya kitovu inaudondosha, au anwani iliyopewa `cbb global hub` si ile ambayo intaneti inaifikia. Kifaa ambacho hakijakutana na kitovu nyumbani tangu usawazishaji nje ya nyumbani uwashwe, au tangu kitovu kibadilishe mipangilio yake (`-obfuscate`, `-vless`), hakijui jinsi ya kukifikia: kilete nyumbani mara moja. Mtandao unaozuia VPN unahitaji [AmneziaWG au VLESS](blocked-networks.md). Kwa `CBB_DEBUG=1` kwenye mazingira ya huduma, kumbukumbu pia huonyesha mikono-ya-salamu ya WireGuard. Kwenye Linux:

```sh
sudo systemctl edit cbb     # add the two lines below, save
# [Service]
# Environment=CBB_DEBUG=1
sudo systemctl restart cbb
```

## Android

- **Huduma ya ufikivu haiwezi kuwashwa** ("mpangilio uliowekewa vikwazo"): kwenye Android 13 na mpya zaidi, fungua Maelezo ya programu, ⋮, "Ruhusu mipangilio iliyowekewa vikwazo", kisha uiwashe.
- **Nakala kutoka kwenye kompyuta zinaacha kufika**: huduma ya mbele inaweza kuwa imesimamishwa na kiokoa betri; acha programu iendeshe bila vikwazo katika mipangilio yake ya betri.

## Bado umekwama

Fungua [suala](https://github.com/HunterEwok/cbb/issues) lenye matokeo ya `CBB_DEBUG=1 cbb status`, sehemu husika ya kumbukumbu na mifumo inayohusika. Ondoa chochote ulichonakili ambacho ni cha faragha. Matatizo ya usalama yanakwenda kwenye [SECURITY.md](../../SECURITY.md) badala yake.
