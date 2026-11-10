<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6e12f051d6a2 -->
# Mitandao inayozuia VPN

Ukiwa mbali na nyumbani, vifaa vyako hufikia kitovu kupitia handaki la WireGuard la kikundi chenyewe. Baadhi ya mitandao huzuia WireGuard: Wi-Fi ya hoteli na ofisi, baadhi ya waendeshaji wa simu, na nchi nzima zinazochuja VPN. Copy Beyond Borders ina njia mbili za kukwepa hilo. Zote mbili huwashwa kwenye kitovu, na vifaa huzipokea wakati ujao vitakapokutana na kitovu nyumbani.

| Njia | Kinachoonwa na mtandao | Unachohitaji | Inafanya kazi kwenye |
|---|---|---|---|
| WireGuard ya kawaida (chaguo-msingi) | pakiti za WireGuard | kitovu au kisambazaji | kompyuta, simu, mwanachama mwepesi |
| **AmneziaWG** (`-obfuscate`) | pakiti za UDP zisizofanana na kitu chochote hasa | kitovu au kisambazaji | kompyuta, simu |
| **VLESS** (`-vless`) | muunganisho wa HTTPS kwenye tovuti | kisambazaji chenye VLESS imewashwa (cha mradi kinayo) | kompyuta, simu |

Chochote utakachochagua, ubao wa kunakili hubaki ndani ya handaki la kikundi na TLS ya vifaa vyenyewe, kwa hiyo hakuna kitu kati ya vifaa vyako kinachoweza kuusoma. Ufichaji hubadilisha tu jinsi pakiti zinavyoonekana kwenye waya.

## Ipi ya kutumia

1. Jaribu **WireGuard ya kawaida** kwanza. Ni ya haraka zaidi na hufanya kazi kwenye mitandao mingi.
2. Handaki likishindwa kusimama kwenye mtandao fulani, au likikatwa baada ya muda, washa **AmneziaWG**. Vichujio vingi vinavyotafuta WireGuard havilitambui tena.
3. Hata hilo likizuiwa, kama ilivyo katika nchi zinazozuia kila aina isiyojulikana ya trafiki, tumia **VLESS**. Inahitaji kisambazaji kinachopokea VLESS kwenye mlango wa TCP 443: cha mradi kwenye cbb.tools kinafanya hivyo, au chako mwenyewe.

Hakuna kinachosaidia kwenye mtandao unaoruhusu orodha tu ya anwani zilizoidhinishwa.

## AmneziaWG

Kwenye kitovu:

```sh
sudo cbb global hub -obfuscate 203.0.113.7:8764
```

Ukiwa na kisambazaji, ongeza `-obfuscate` vivyo hivyo:

```sh
sudo cbb global hub -obfuscate -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

Kitovu hutengeneza mipangilio ya kikundi mara moja, kwa nasibu, na kuihifadhi maadamu `-obfuscate` ipo. Walete laptopu na simu zote nyumbani mara moja baadaye, au acha programu wazi nyumbani, ili zichukue mipangilio mipya. Mwanachama mwepesi huzungumza WireGuard ya kawaida tu: katika kikundi chenye ufichaji husawazisha nyumbani tu.

## VLESS

VLESS hufanya kazi kati ya vifaa vyako na kisambazaji, ndani ya kile ambacho kwa mtandao kinaonekana kama muunganisho wa kawaida wa HTTPS kwenye tovuti.

1. **Kisambazaji.** Kisambazaji cha mradi kwenye cbb.tools kina VLESS imewashwa: kwa mtandao, vifaa vyako vinatembelea `cbb.tools`. Kisambazaji chako mwenyewe huiendesha nyuma ya seva ya wavuti ya tovuti yako:

   ```sh
   cbb forward -vless-xhttp vpn.example.org
   ```

   Seva ya wavuti, iliyo na cheti cha tovuti yako, hukipitishia njia ambayo kisambazaji huchapisha; mwingine yeyote hupata kurasa za tovuti yako yenyewe. Fungua TCP 443 kwenye ngome ya moto ya seva, kando ya UDP na TCP 8764. Kuandaa seva kumeelezwa katika [kuendesha seva zako mwenyewe](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Kwenye kitovu**: washa VLESS kwenye programu (handaki la kitovu: VLESS), au:

   ```sh
   sudo cbb global hub -forwarder default -vless
   ```

   (`-forwarder 198.51.100.9:8764 -forwarder-key <key>` kwa chako mwenyewe.) Kisambazaji huambia kitovu tovuti yake na njia yake. Ongeza pia `-obfuscate` ukipenda; kisha zote mbili hutumika.

3. **Kwenye vifaa**: kutana na kitovu nyumbani mara moja, kama baada ya mabadiliko yoyote. Kuanzia hapo hufikia kisambazaji kupitia VLESS tu, kamwe si kwa WireGuard ya kawaida kwanza, kwa hiyo mtandao unaotaka kuficha handaki kutoka kwake haulioni kamwe.

## Vidokezo kwa nchi zinazochuja

- **Weka kila kitu nyumbani, kabla ya kusafiri.** Vifaa huchukua mipangilio ya kitovu kwenye mtandao wa nyumbani tu.
- Chagua kisambazaji nje ya nchi inayochuja, kwa mtoa huduma wa upangishaji asiyezuiwa huko.
- VPN ya simu yenyewe inaendelea kufanya kazi: handaki la programu ni trafiki ya kawaida ya programu na halichukui nafasi ya VPN ya simu.
- Handaki likiacha kufanya kazi safarini, `cbb global` kwenye laptopu husema kinachoshindwa, na `CBB_DEBUG=1` huonyesha maelezo ([utatuzi wa matatizo](troubleshooting.md#sync-away-from-home)).
