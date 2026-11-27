<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f215e8c49c0 -->
# Maabara

Kwa yeyote anayetaka kujua kuhusu vipengele vya majaribio vya Connect Beyond Borders zaidi ya usawazishaji wa kila siku wa ubao wa kunakili.

Connect Beyond Borders inalenga ahadi moja kuu: ubao mmoja wa kunakili uliosimbwa unaoshirikiwa kati ya simu na kompyuta zako. Maabara ni mahali ambapo njia za ziada za kutumia kikundi chako hujaribiwa. Kila jaribio hapa chini hujengwa na kufaulu majaribio ya kiotomatiki katika CI, lakini vipengele hivi ni vya majaribio: vinaweza kubadilika au kuondolewa, na vingi vina majaribio machache kwenye maunzi halisi. Tazama [Usawa wa majukwaa](../parity.md#on-real-devices) kwa hali ya sasa kwenye maunzi halisi.

## Majaribio

| Jaribio | Linafanya nini | Mwongozo |
|---|---|---|
| **Kibodi za Bluetooth na USB** | Simu ya Android, Aurora OS, au HarmonyOS, kompyuta ya Linux, au Arduino Nano ESP32 huandika maandishi kwenye TV, kompyuta kibao, konsoli ya michezo, au kompyuta ambayo haiendeshi Connect Beyond Borders | [Kibodi na televisheni](keyboards-and-tvs.md) |
| **Rimoti za TV** | Kompyuta kwenye mtandao wako wa nyumbani huandika moja kwa moja kwenye Android TV, Google TV, Apple TV, au Roku kupitia mtandao wa ndani kama rimoti yake | [Kibodi na televisheni](keyboards-and-tvs.md#a-computer-as-the-tvs-remote) |
| **Arduino Nano ESP32** | Programu dhibiti ya kidhibiti kidogo cha gharama nafuu inayoendesha Wi-Fi, jaribio binafsi la itifaki ya TLS 1.3, na kibodi ya USB na Bluetooth LE (kujiunga na kikundi na usawazishaji wa ubao wa kunakili viko kwenye [ramani ya njia](../roadmap.md)) | [Programu dhibiti ya ESP32](../../esp32/README.md) |
| **ZX Spectrum Next** | Hunakili maandishi na siri, hubandika maandishi, huonyesha picha za kikundi kwenye Layer 2, na hupokea kubandika kwa mbali kupitia Raspberry Pi iliyo ndani ya Accelerated Next | [`.cbb` kwa Next](../../apps/zxnext/README.md) |

## Mahali pa kupata vipengele vya maabara

- **Programu za simu (Android, Aurora OS, na HarmonyOS):** Fungua **Mipangilio**, washa **Mipangilio ya kina**, na usogeze hadi **Maabara** (ina vidhibiti vya **Kibodi ya Bluetooth**).
- **Kompyuta:** Tumia `cbb keyboard` (Linux) na `cbb remote` (Linux, macOS, Windows, na FreeBSD) kwenye terminal; tazama [Amri](../reference/cli.md).
- **ESP32 na ZX Spectrum Next:** Fuata maelekezo ya usanidi ya kila kifaa yaliyounganishwa kwenye jedwali hapo juu.

## Shiriki maoni

Ukijaribu jaribio kwenye maunzi halisi, ripoti jinsi linavyofanya kazi katika [suala kwenye GitHub](https://github.com/HunterEwok/cbb/issues). Majaribio yanayojithibitisha kuwa ya kuaminika kwenye vifaa halisi yanaweza kutoka maabara na kuwa vipengele vinavyoungwa mkono.
