<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 503bd28272de -->
# Kubandika kwa mbali

Kwa yeyote anayetaka kuweka maandishi kwenye programu ya kifaa kingine: nenosiri kwenye fomu ya kuingia ya televisheni, amri kwenye terminal ya seva, anwani kwenye kompyuta iliyo upande wa pili wa chumba. Msimamizi wa kikundi hutuma maandishi, nayo hutua mahali ambapo mwelekeo wa kifaa hicho upo, yakibandikwa au kuandikwa herufi kwa herufi.

Kubandika kwa mbali kumezimwa kwenye kila kifaa hadi mtumiaji wake mwenyewe akiwashe hapo. Hakuna anayeweza kuwasha ukiwa mbali.

## Kiwashe mahali maandishi yanapopaswa kutua

| Kifaa | Jinsi | Kinabandika wapi |
|---|---|---|
| Linux | `sudo cbb paste-receive on` | programu yenye mwelekeo ya eneo-kazi (X11, Wayland, GNOME na KDE), kidirisha amilifu cha tmux; kwa `-console`, pia kiweko cha maandishi |
| FreeBSD | `sudo cbb paste-receive on` | programu yenye mwelekeo kwenye X11 na maeneo-kazi ya wlroots (sway, Hyprland); si GNOME, kwa kuwa huko hakuna kinachoonyesha kama skrini yake imefungwa |
| Windows | `cbb paste-receive on` kwenye terminal iliyofunguliwa kama msimamizi | dirisha lenye mwelekeo |
| Mac | `sudo cbb paste-receive on`, na programu ya Mac ikiwa wazi, imeruhusiwa katika Mipangilio ya Mfumo, Faragha na Usalama, Ufikivu | programu yenye mwelekeo |
| Simu au televisheni ya Android | Mipangilio, "Let the group's admins paste here", na huduma ya ufikivu ya programu ikiwa imewashwa | uga wa maandishi wenye mwelekeo katika programu nyingine |
| Mwanachama mwepesi | `sudo cbb paste-receive on`; kwa `-console`, pia kiweko cha maandishi | kidirisha cha tmux kinachotumika |

`-enter` (kwenye simu, "Let a paste press Enter") huruhusu kubandika kubonyeza Enter baada ya maandishi. Bila hiyo maandishi yenye kikatizo cha mstari hukataliwa, kwa sababu kikatizo cha mstari kinaweza kutekeleza kama amri kilichotangulia popote ambapo terminal haipokei kubandika kama kipande kimoja.

Kwenye GNOME na KDE kubandika kwa mara ya kwanza hufungua kisanduku cha mazungumzo cha mfumo cha udhibiti wa mbali wa skrini; kiruhusu mara moja na hukumbukwa. Ili kuruka kisanduku hicho, sakinisha msaidizi wa uinput: sakinisha tena kwa `--uinput` (`curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh -s -- --uinput`), ambayo huongeza kibodi pepe inayobonyeza Shift+Insert na Enter tu kwa niaba ya mtumiaji aliye mbele ya skrini.

Bila eneo-kazi, tmux na kiweko cha maandishi vinahitaji wasaidizi wao. Kila usakinishaji huongeza sehemu ya Clipboard Bridge ya `/etc/tmux.conf`, inayoanzisha msaidizi wa tmux pamoja na tmux; `install.sh --console` huongeza huduma ya msaidizi wa kiweko.

## Bandika kutoka kwa msimamizi

Kwenye kompyuta ya msimamizi:

```sh
echo 'the text' | cbb paste -on DEVICE          # pastes it
cbb paste -on DEVICE                            # pastes this computer's clipboard text
cbb paste -on DEVICE -type < note.txt           # types it key by key, up to 4 KiB
cbb paste -on DEVICE -enter -secret < pass.txt  # presses Enter after it; kept as a secret
```

`DEVICE` ni jina la kifaa au kitambulisho chake kutoka `cbb status`. Amri husema maandishi yanapofika, au kwa nini kifaa kiliyakataa.

Kwenye simu ya msimamizi, fungua ukurasa wa kifaa na uchague "Paste on it…": andika maandishi, au acha sehemu tupu ili kutuma kilicho kwenye ubao wa kunakili, chagua kubandika au kuandika, na uthibitishe kwa Face ID au alama ya kidole. iPhone huuliza kila mara kama programu inaweza kusoma ubao wa kunakili, hadi kwenye Mipangilio, Programu, CBB, "Bandika kutoka Programu Nyingine" uweke Ruhusu.

Kuandika hufanya kazi katika mpangilio wowote wa kibodi kwenye X11, vikusanyaji vya Wayland vyenye kibodi pepe, Windows na Mac. Kwenye GNOME na KDE kupitia kisanduku cha mazungumzo, kubandika hufanya kazi lakini kuandika hakufanyi, kwa kuwa vitufe vingefuata mpangilio wa mtumiaji.

## Inapokataliwa

Kifaa hakibandiki kamwe:

- skrini yake ikiwa imefungwa, kiokoa skrini au skrini ya kuingia ikiwa imewashwa;
- kwenye dirisha linaloendeshwa kama msimamizi kwenye Windows, au chini ya kidokezo cha msimamizi;
- kwenye Mac wakati uga wa nenosiri au Secure Keyboard Entry unashikilia kibodi;
- wakati hakuna aliyeunganishwa kwenye tmux au aliyeingia kwenye kiweko;
- zaidi ya mara moja kwa sekunde, au zaidi ya mara 30 kwa dakika, kutoka kwa mtumaji mmoja.

Jibu kwa mtumaji husema ni lipi kati ya hayo.

## Usalama

- Yeyote aliye msimamizi wa kikundi chako anaweza kuandika kwenye kifaa chako kubandika kwa mbali kukiwa kumewashwa, kana kwamba yuko kwenye kibodi yako. Kiwashe pale unapokihitaji tu, na ufanye orodha ya wasimamizi iwe fupi.
- Kila kifaa huweka kumbukumbu ya mabandiko yake 100 ya mwisho: nani aliyatuma na lini, kamwe si maandishi. Android pia humtaja mtumaji kwenye arifa.
- Msimamizi yeyote anaweza kuzima kubandika kwa mbali kwenye kifaa kingine au kwenye vyote, kwa mfano simu inapopotea: `cbb paste-receive off -on DEVICE` au `-all`. Ni mtumiaji wa kifaa chenyewe pekee anayekiwasha tena.

Vikomo viko katika [vikomo na muda wa kuishi](../reference/limits.md#remote-paste-and-quick-actions); jinsi inavyofanya kazi ndani iko katika [muundo](../design.md#remote-paste).
