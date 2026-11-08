<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f28736f9b01 -->
# Picha, faili na maandishi yenye muundo

Kwa mtu yeyote anayenakili zaidi ya maandishi matupu. Picha, faili kutoka kwenye kidhibiti faili au maandishi yenye muundo wake, vilivyonakiliwa kwenye kifaa kimoja, vinaweza kubandikwa kwenye vingine kama vilivyo.

## Nini kinakwenda wapi

| Kilichonakiliwa | Kompyuta zenye eneo-kazi | Simu | Kompyuta isiyo na eneo-kazi | Mwanachama mwepesi |
|---|---|---|---|---|
| Maandishi yenye muundo wake (kivinjari, programu ya ofisi) | hubandikwa na muundo wake | hubandikwa kama maandishi matupu | maandishi matupu | maandishi matupu |
| Picha (PNG, JPEG; TIFF kwenye Mac na HEIC kwenye simu hubadilishwa) | hubandikwa kama picha | kitufe cha programu hukibandika; pia huja chenyewe, kwenye iPhone programu ikiendeshwa | maandishi yake tu; `cbb paste -o DIR` huhifadhi picha | maandishi yake tu; hupitisha picha |
| Faili na folda | hubandikwa kama faili zilizonakiliwa | programu huzihifadhi: Vipakuliwa kwenye Android, folda ya programu katika Files kwenye iPhone | `cbb paste -o DIR` huzihifadhi | huzipitisha, haihifadhi yoyote |

Nakala yenye maandishi na picha hutumwa kama maandishi. Kukata kwenye kidhibiti faili huchukuliwa kama kunakili: hakuna kinachofutwa popote.

## Jinsi kinavyosafiri

Nakala yenyewe hubaki kwenye kifaa ilipofanywa. Vingine hujua kwamba kuna nakala mpya, pamoja na ukubwa wake, na vile vilivyowasha usawazishaji huileta mara moja kutoka kwenye kifaa hicho, au kutoka kwa kingine kilicho nayo, kupitia miunganisho ile ile iliyosimbwa kama maandishi.

Ukiwa mbali na nyumbani, kitovu huleta kila nakala na kuipitisha kupitia handaki la kikundi, hadi kikomo chake chenyewe.

## Ukubwa

| Wapi | Chaguo-msingi | Libadilishe kwenye kila kifaa |
|---|---|---|
| Nyumbani | MiB 100 kwa kila nakala | `cbb config max-copy SIZE`, MiB 1 hadi GiB 1 |
| Kupitia handaki la kikundi | MiB 25 kwa kila nakala | `cbb config max-copy-away SIZE`, isizidi `max-copy` |
| Kutoka menyu ya kushiriki ya simu | MiB 100 kwenye Android, MB 50 kutoka iPhone | hapana |

Nakala inayozidi kikomo cha kifaa hailetwi hapo, na `cbb status` husema hivyo. `max-copy-away` ya kitovu huweka kikomo kwa kila kifaa kinachokifikia kutoka mbali. Vikomo vyote viko katika [vikomo na muda wa kuishi](../reference/limits.md#copies).

## Kutoka kwenye mstari wa amri

```sh
cbb copy photo.jpg notes/              # sends files and folders as one copy
cbb copy -type png screenshot.png      # sends one image as an image
cbb paste -o ~/Downloads               # saves the clipboard's images or files there
cbb status                             # shows a copy that is still arriving
```

`cbb paste -o` husubiri nakala inapoendelea kufika, haibadilishi faili kamwe na haifanyi chochote kitekelezeke.

## Usalama

- Faili zilizopokelewa huhifadhiwa katika folda yake yenyewe ndani ya akiba ya mtumiaji wako, inayosomeka na wewe tu, na kuondolewa dakika 10 baada ya nakala mpya zaidi. Mac huziwekea alama kuwa zimepakuliwa (karantini) na Windows kwa Mark of the Web, kwa hiyo mfumo hukuonya kabla ya kufungua programu miongoni mwazo. Hakuna kinachofanywa kitekelezeke.
- Majina hufanywa salama kwa kila mfumo, na viungo na faili maalum ndani ya folda huachwa.
- Muundo wa siri haujasomwa kamwe; siri hutumwa kama maandishi matupu tu.
- Huduma huweka nakala ya sasa na zile za zamani kwa dakika 10 katika saraka yake ya hali, na hakuna kitu baada ya kuwashwa upya.
