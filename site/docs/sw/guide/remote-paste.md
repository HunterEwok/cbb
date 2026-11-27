<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 92bb7661d223 -->
# Kubandika kwa mbali

Kwa yeyote anayetaka kubandika maandishi, picha, au faili kutoka kwenye simu au kompyuta ya msimamizi moja kwa moja kwenye programu iliyolengwa kwenye kompyuta nyingine — kwa mfano, nywila kwenye sehemu ya kuingia, amri kwenye terminal, au picha ya skrini kwenye gumzo.

Msimamizi hutia sahihi ombi la kubandika, na kompyuta lengwa huweka maudhui mahali ambapo lengo la kibodi yake lilipo kwa kubandika au kuandika kitufe kwa kitufe. Kubandika kwa mbali kumezimwa kwenye kila kompyuta hadi mtumiaji wa kompyuta hiyo mwenyewe akiwashe hapo; hakuna anayeweza kukiwasha kwa mbali. Simu hutuma ubandikaji wa mbali kwa kompyuta na hazipokei ubandikaji wa mbali.

## 1. Washa kubandika kwa mbali kwenye kompyuta lengwa

Endesha hatua za usanidi za mfumo wa uendeshaji wa kompyuta lengwa:

| Mfumo lengwa | Hatua za usanidi | Mahali ubandikaji unapotua |
|---|---|---|
| **Linux** | Endesha `sudo cbb paste-receive on` | Programu yenye lengo ya eneo-kazi (X11, Wayland, GNOME, KDE), kidirisha amilifu cha `tmux`, na (kwa `-console`) kiweko cha maandishi cha Linux |
| **FreeBSD** | Endesha `sudo cbb paste-receive on` | Programu yenye lengo kwenye X11 na vikusanyaji vya Wayland vya wlroots (kama sway na Hyprland); GNOME kwenye FreeBSD haitumiki kwa sababu hali ya skrini iliyofungwa haipatikani |
| **Windows** | Fungua terminal kama msimamizi wa mfumo na uendeshe `cbb paste-receive on` | Dirisha lenye lengo |
| **macOS** | Endesha `sudo cbb paste-receive on`, acha programu ya upau wa menyu ya **CBB** ikiwa wazi, na uiruhusu katika **Mipangilio ya Mfumo > Faragha na Usalama > Ufikivu** | Programu yenye lengo |
| **Kifaa kidogo cha Linux kisicho na eneo-kazi** | Endesha `sudo cbb paste-receive on` (ongeza `-console` kwa kiweko cha maandishi cha Linux) | Kidirisha amilifu cha `tmux` au kiweko cha maandishi |

Bendera za hiari za `cbb paste-receive on`:

- `-enter`: Huruhusu ubandikaji wa mbali kubonyeza Enter baada ya maudhui. Bila `-enter`, maandishi yoyote yenye kikatizo cha mstari hukataliwa ili ubandikaji usiweze kuendesha amri kwa bahati mbaya kwenye terminal.
- `-console`: Huruhusu kubandika kwa mbali kwenye kiweko cha maandishi cha Linux na vipindi vya `tmux` vya `root` (haipatikani kwenye usakinishaji wa bila root).
- `-no-lock-check`: Kwenye Linux na FreeBSD bila `logind`, huruhusu kubandika kwa mbali wakati mfumo hauwezi kuripoti hali ya kufungwa kwa kipindi (kifunga skrini kinachoendeshwa bado huzuia ubandikaji).

**Matokeo:** Endesha `cbb paste-receive` bila hoja zozote ili kuthibitisha kuwa kubandika kwa mbali kumewashwa na kuona ni chaguo zipi zinazotumika.

### Wasaidizi wa ziada kwenye Linux

- **Visanduku vya mazungumzo vya eneo-kazi la GNOME na KDE:** Ubandikaji wa kwanza wa mbali hufungua kisanduku cha uthibitisho cha udhibiti wa mbali cha eneo-kazi lako; kiruhusu mara moja ili eneo-kazi likikumbuke. Ili kuruka kisanduku hicho (na kuruhusu kubonyeza vitufe kwenye maeneo-kazi yasiyo na njia nyingine ya uingizaji), sakinisha upya kwa `--uinput`:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --uinput
  ```

  Hii huongeza `cbb-uinput.service`, kibodi pepe inayobonyeza Shift+Insert na Enter pekee kwa niaba ya mtumiaji aliyeingia.
- **`tmux` isiyo na skrini na viweko vya maandishi:** Kila usakinishaji wa Linux huongeza kiungo cha Connect Beyond Borders kwenye `/etc/tmux.conf` ili `tmux` ianzishe msaidizi wake wa kubandika kiotomatiki. Kwa kiweko cha maandishi cha Linux, sakinisha kwa `--console` (tazama [Kusakinisha kwenye Linux](install.md#linux)).

## 2. Tuma ubandikaji wa mbali kutoka kwa msimamizi

### Kutoka kwenye kompyuta ya msimamizi

Endesha `cbb paste -on DEVICE` kwenye terminal (`DEVICE` ni jina la kifaa lengwa au kitambulisho chake kutoka `cbb status`):

```sh
echo 'the text' | cbb paste -on DEVICE              # paste text from standard input
cbb paste -on DEVICE                                # paste this computer's clipboard text
cbb paste -on DEVICE -type < note.txt               # type text key by key (up to 4 KiB)
cbb paste -on DEVICE -enter -secret < pass.txt      # paste as a secret and press Enter
cbb paste -on DEVICE photo.jpg notes/               # paste files into the focused app
cbb paste -on DEVICE -image screenshot.png          # paste a PNG or JPEG as an image
cbb paste -on DEVICE -copy                          # paste the group's current image or files
```

**Matokeo:** Amri huchapisha `Pasted on DEVICE.` wakati kifaa lengwa kinapokubali na kuwasilisha ubandikaji, au huripoti sababu kamili ambayo kifaa lengwa kilikataa.

### Kutoka kwenye simu ya msimamizi

1. Fungua **CBB**, gusa kompyuta lengwa kwenye **Mwanzo**, kisha uguse **Bandika kwake…**.
2. Chagua cha kutuma:
   - **Maandishi:** Andika maandishi (au acha sehemu ya maandishi tupu ili kutuma ubao wa kunakili wa simu yako), kwa hiari chagua kuandika kitufe kwa kitufe, **Siri**, au **Bonyeza Enter baada yake**, kisha uguse **Bandika**.
   - **Picha au faili:** Gusa **Bandika picha au faili…** (kwenye iPhone, **Bandika picha…** au **Bandika faili…**) na uchague vipengee.
3. Thibitisha kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi.

Kwenye iPhone, weka **Mipangilio > Programu > CBB > Bandika kutoka Programu Nyingine** kuwa **Ruhusu** ili iOS isiulize kila wakati programu inaposoma ubao wako wa kunakili.

**Matokeo:** Kompyuta lengwa hubandika au kuandika maudhui kwenye dirisha lake lenye lengo na programu huonyesha **Imebandikwa.**

### Kubandika dhidi ya kuandika

- **Kubandika** hufanya kazi katika programu nyingi za eneo-kazi na hutumia maandishi (hadi MiB 1), picha, na faili.
- **Kuandika** (`-type`) hutuma mibonyezo ya vitufe mmoja mmoja (maandishi pekee, hadi KiB 4) kwa programu zinazozuia kubandika kutoka ubao wa kunakili. Kuandika hufanya kazi katika mipangilio mbalimbali ya kibodi kwenye X11, vikusanyaji vya Wayland vyenye itifaki ya kibodi pepe, Windows, na macOS. Kwenye GNOME na KDE kupitia kisanduku cha mfumo cha udhibiti wa mbali, kubandika hufanya kazi ilhali kuandika hakupatikani.

## Kifaa lengwa kinapokataa kubandika

Kompyuta lengwa hukataa ubandikaji wa mbali wakati:

- Skrini yake imefungwa, kiokoa skrini kinatumika, au skrini ya kuingia inaonyeshwa.
- Kwenye Windows, dirisha lenye lengo linaendeshwa kama msimamizi wa mfumo au ombi la kupandisha haki za msimamizi liko wazi.
- Kwenye macOS, sehemu ya nywila au Secure Keyboard Entry inashikilia lengo la kibodi.
- Hakuna mtu aliyeunganishwa kwenye `tmux` au aliyeingia kwenye kiweko cha maandishi (kwenye vifaa lengwa visivyo na skrini).
- Maandishi yana kikatizo cha mstari na `-enter` haijawashwa kwenye kifaa lengwa.
- Mtumaji mmoja anazidi mpaka wa kiwango wa **ubandikaji 1 kwa sekunde** au **mabandiko 30 kwa dakika**.

Hitilafu inayorudishwa kwa mtumaji hutaja sababu.

## Usalama na kuzima kubandika kwa mbali

- **Weka kikomo kwa wasimamizi wako:** Msimamizi yeyote katika kikundi chako anaweza kuandika kwenye kompyuta wakati kubandika kwa mbali kumewashwa. Washa kubandika kwa mbali kwenye kompyuta unazohitaji pekee, na fanya orodha yako ya wasimamizi iwe fupi.
- **Kumbukumbu ya ukaguzi wa kubandika:** Kila kifaa lengwa hurekodi maombi yake 100 ya mwisho ya kubandika (mtumaji, muhuri wa muda, urefu, njia, na matokeo — kamwe si maandishi yaliyobandikwa). Siri haziachi alama yoyote kwenye ubao wa kunakili wa kifaa lengwa baada ya kubandikwa.
- **Zima moja kwa moja:** Endesha `sudo cbb paste-receive off` kwenye kompyuta lengwa (kukizima pia hurejesha `-enter`, `-console`, na `-no-lock-check` katika hali ya awali).
- **Zima kwa mbali kutoka kwa msimamizi yeyote:** Endesha `sudo cbb paste-receive off -on DEVICE` (au `-all` ili kuzima kubandika kwa mbali kwenye kila kompyuta katika kikundi). Ni mtumiaji wa kila kompyuta pekee anayeweza kukiwasha tena.

Kwa mipaka kamili ya ukubwa na kiwango, tazama [Mipaka na muda](../reference/limits.md#remote-paste-and-quick-actions). Kwa jinsi kubandika kwa mbali kunavyofanya kazi ndani, tazama [Muundo: kubandika kwa mbali](../design.md#remote-paste).
