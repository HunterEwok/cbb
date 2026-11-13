<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 5a06c8a1fa53 -->
# Mitandao inayozuia VPN

Ukiwa mbali na nyumbani, vifaa vyako hufikia kitovu kupitia handaki la WireGuard la kikundi chenyewe. Baadhi ya mitandao huzuia WireGuard: Wi-Fi ya hoteli na ofisi, baadhi ya waendeshaji wa simu, na nchi nzima zinazochuja VPN. Copy Beyond Borders ina njia mbili za kukwepa hilo, na kitovu hutumia zote mbili usipozizima; vifaa hupokea badiliko wakati ujao vitakapokutana na kitovu nyumbani.

| Njia | Kinachoonwa na mtandao | Unachohitaji | Inafanya kazi kwenye |
|---|---|---|---|
| **AmneziaWG** (imewashwa kwa chaguo-msingi; `-no-obfuscate` pamoja na `-no-vless` huizima) | pakiti za UDP zisizofanana na kitu chochote hasa | kitovu au kisambazaji | kompyuta, simu |
| **VLESS** (imewashwa kwa chaguo-msingi kwenye kisambazaji; `-no-vless` huizima) | muunganisho wa HTTPS kwenye tovuti | kisambazaji chenye VLESS imewashwa (cha mradi kinayo) | kompyuta, simu |
| WireGuard ya kawaida (`-no-obfuscate -no-vless`) | pakiti za WireGuard | kitovu au kisambazaji | kompyuta, simu, vifaa vidogo |

Chochote utakachochagua, ubao wa kunakili hubaki ndani ya handaki la kikundi na TLS ya vifaa vyenyewe, kwa hiyo hakuna kitu kati ya vifaa vyako kinachoweza kuusoma. Ufichaji hubadilisha tu jinsi pakiti zinavyoonekana kwenye waya.

## Jinsi vifaa vinavyochagua

Vifaa hujaribu **AmneziaWG** kupitia UDP kwanza, ambayo ni ya haraka zaidi pale mtandao unapoiruhusu: vichujio vingi vinavyotafuta WireGuard havilitambui. Pale hata hilo linapozuiwa, kama ilivyo katika nchi zinazozuia kila aina isiyojulikana ya trafiki, hufikia kisambazaji kupitia **VLESS**, inayohitaji kisambazaji kinachopokea VLESS kwenye mlango wa TCP 443: cha mradi kwenye cbb.tools kinafanya hivyo, au chako mwenyewe. Kitovu kisicho na kisambazaji hutoa AmneziaWG peke yake.

Hakuna kinachosaidia kwenye mtandao unaoruhusu tu orodha ya anwani zilizoidhinishwa.

## AmneziaWG

Kitovu huzungumza AmneziaWG mara tu kinapokuwa kitovu:

```sh
sudo cbb global hub 203.0.113.7:8764
```

Hutengeneza mipangilio ya kikundi kwa nasibu na kuibadilisha takriban mara moja kwa mwezi, likiviambia vifaa mipangilio inayofuata mapema. Kwenye mtandao ambapo hakuna kinachozuiwa, WireGuard ya kawaida ni ya haraka kidogo:

```sh
sudo cbb global hub -no-obfuscate -no-vless 203.0.113.7:8764
```

Baada ya badiliko, walete laptopu na simu zote nyumbani mara moja, au acha programu wazi nyumbani, ili zichukue mipangilio mipya.

## VLESS

VLESS hufanya kazi kati ya vifaa vyako na kisambazaji, ndani ya kile ambacho kwa mtandao kinaonekana kama muunganisho wa kawaida wa HTTPS kwenye tovuti.

1. **Kisambazaji.** Kisambazaji cha mradi kwenye cbb.tools kina VLESS imewashwa: kwa mtandao, vifaa vyako vinatembelea `cbb.tools`. Kisambazaji chako mwenyewe huiendesha nyuma ya seva ya wavuti ya tovuti yako:

   ```sh
   cbb forward -vless-xhttp vpn.example.org
   ```

   Seva ya wavuti, iliyo na cheti cha tovuti yako, hukipitishia njia ambayo kisambazaji huchapisha; mwingine yeyote hupata kurasa za tovuti yako yenyewe. Fungua TCP 443 kwenye ngome ya moto ya seva, kando ya UDP na TCP 8764. Kuandaa seva kumeelezwa katika [kuendesha seva zako mwenyewe](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Kwenye kitovu**: hakuna cha kufanya. Kitovu kilicho kwenye kisambazaji huomba VLESS:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   (`-forwarder 198.51.100.9:8764 -forwarder-key <key>` kwa chako mwenyewe.) Kisambazaji huambia kitovu tovuti yake na njia yake; kisicho na VLESS husajili kitovu kwa UDP peke yake. VLESS huja pamoja na AmneziaWG: ndani ya VLESS huficha ukubwa wa pakiti za WireGuard, ambao vinginevyo ungeonekana kupitia HTTPS. `-no-vless` huzima VLESS.

3. **Kwenye vifaa**: kutana na kitovu nyumbani mara moja, kama baada ya mabadiliko yoyote. Kuanzia hapo hujaribu AmneziaWG kupitia UDP kwanza, ambayo ni ya haraka zaidi pale mtandao unapoiruhusu, na VLESS usipoiruhusu, na hushikilia njia iliyofanya kazi. Kamwe havijaribu WireGuard ya kawaida, kwa hiyo mtandao unaotaka kuficha handaki kutoka kwake haulioni kamwe.

## Vidokezo kwa nchi zinazochuja

- **Weka kila kitu nyumbani, kabla ya kusafiri.** Vifaa huchukua mipangilio ya kitovu kwenye mtandao wa nyumbani tu.
- Chagua kisambazaji nje ya nchi inayochuja, kwa mtoa huduma wa upangishaji asiyezuiwa huko.
- Tovuti ya kisambazaji huonekana kwenye pakiti ya kwanza ya kila muunganisho: mtandao unaozuia tovuti hiyo huzuia njia pia. Hapo jibu ni kisambazaji chako mwenyewe, kwenye tovuti nyingine.
- VPN ya simu yenyewe inaendelea kufanya kazi: handaki la programu ni trafiki ya kawaida ya programu na halichukui nafasi ya VPN ya simu.
- Handaki likiacha kufanya kazi safarini, `cbb global` kwenye laptopu husema kinachoshindwa, na `CBB_DEBUG=1` huonyesha maelezo ([utatuzi wa matatizo](troubleshooting.md#sync-away-from-home)).
