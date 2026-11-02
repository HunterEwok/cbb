<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ce6e8f0e4357 -->
# Vitendo vya haraka

Kwa yeyote anayetaka kufunga, kulaza au kuwasha upya kompyuta kutoka kwenye simu au kompyuta nyingine ya kikundi. Msimamizi huendesha kitendo kwa mguso mmoja au amri moja; kifaa hukiendesha tu ikiwa mtumiaji wake mwenyewe aliwasha kitendo hicho hapo.

## Vitendo

| Kitendo | Kinafanya nini | Wapi |
|---|---|---|
| `lock` | hufunga skrini | kompyuta |
| `sleep` | hulaza kompyuta | kompyuta |
| `reboot` | huwasha upya kompyuta dakika moja baadaye | kompyuta, mwanachama mwepesi |
| `shutdown` | huzima kompyuta dakika moja baadaye | kompyuta |
| `cancel-shutdown` | hughairi kuwasha upya au kuzima kunakosubiri | kompyuta, mwanachama mwepesi |
| `restart` | huwasha upya huduma ya Clipboard Bridge | kompyuta, mwanachama mwepesi |
| `keyboard-layout` | hubadilisha mpangilio ambao [kibodi yake ya Bluetooth](keyboards-and-tvs.md) huandika nao hadi unaofuata, baada ya kubadilisha ule wa kifaa chenyewe | kompyuta za Linux zenye kibodi imewashwa |
| chako mwenyewe | huendesha programu uliyoichagua, kama mtumiaji aliyeingia | kompyuta |

Onyo la dakika moja kabla ya kuwasha upya au kuzima humpa yeyote aliye kwenye kompyuta muda wa kuhifadhi kazi yake au kuendesha `cancel-shutdown`. Windows pia huwaonya watumiaji walioingia.

## Washa kitendo

Kwenye kifaa, kama msimamizi (`sudo` kwenye Linux, macOS na FreeBSD):

```sh
cbb action                     # lists the actions and who may run each
sudo cbb action enable lock    # says what it allows and asks you to type yes
sudo cbb action enable reboot -by root,phone
sudo cbb action disable lock
```

`-by` huweka kikomo cha nani anayeweza kukiendesha: `root`, `phone` (simu za wasimamizi), `computer` (kompyuta za wasimamizi), `watch` (saa yenye ufunguo wa msimamizi). Bila hiyo kila msimamizi anaweza. `reboot` na `shutdown` huwakubali tu wasimamizi ambao funguo zao ziko kwenye maunzi, simu au kompyuta yenye TPM, isipokuwa uongeze `-any-key`.

Kwenye Linux, kuwasha huandika kanuni ya polkit inayoipa huduma haki zinazohitajika hasa na vitendo vilivyowashwa, na kuzima huzirudisha.

## Kitendo chako mwenyewe

```sh
sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
sudo cbb action remove backup
```

Wakala wa mtumiaji aliyeingia huendesha programu kwa njia yake kamili, kwa hoja hizi hasa na bila shell. Mtumaji hupata hali yake ya kutoka tu. Lazima iishe ndani ya sekunde 15; kitu chochote kinachochukua muda mrefu zaidi kianzishe chinichini.

## Endesha kitendo

Kwenye kompyuta ya msimamizi: `cbb action -on DEVICE NAME`, ambayo husema kama kiliendeshwa au kwa nini la.

Kwenye simu ya msimamizi, fungua ukurasa wa kifaa kikiwa mtandaoni na ugonge kitendo chini ya "Quick actions"; Face ID au alama ya kidole huthibitisha, na kuwasha upya na kuzima huuliza mara moja zaidi. Saa ya msimamizi inaweza kuendesha vitendo vinavyoruhusiwa kwa `watch`.

## Vizime vyote

`sudo cbb action off` kwenye kifaa huzima kila kitendo hapo. Kutoka kwa msimamizi, `cbb action off -on DEVICE` au `-all` hufanya hivyo kwenye kifaa kingine au kwenye kila kimoja, na "Turn all off" kwenye simu hufanya vivyo hivyo; ni mtumiaji wa kila kifaa pekee anayevirudisha.

Kila kifaa huweka kumbukumbu ya vitendo 100 vya mwisho kilivyoombwa kuviendesha, pamoja na nani aliyeomba na lini.
