<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 90564bcf632e -->
# Mitandao inayozuia VPN

Ukiwa mbali na nyumbani, vifaa vyako hufikia kitovu kupitia handaki la WireGuard la kikundi chenyewe. Baadhi ya mitandao huzuia WireGuard: Wi-Fi ya hoteli na ofisi, baadhi ya waendeshaji wa simu, na nchi nzima zinazochuja VPN. Copy Beyond Borders ina njia mbili za kukwepa hilo. Zote mbili huwashwa kwenye kitovu, na vifaa huzipokea wakati ujao vitakapokutana na kitovu nyumbani.

| Njia | Kinachoonwa na mtandao | Unachohitaji | Inafanya kazi kwenye |
|---|---|---|---|
| WireGuard ya kawaida (chaguo-msingi) | pakiti za WireGuard | kitovu au kisambazaji | kompyuta, simu, mwanachama mwepesi |
| **AmneziaWG** (`-obfuscate`) | pakiti za UDP zisizofanana na kitu chochote hasa | kitovu au kisambazaji | kompyuta, simu |
| **VLESS na REALITY** (`-vless`) | muunganisho wa HTTPS kwenye tovuti maarufu | kisambazaji chenye VLESS imewashwa | kompyuta, simu |

Chochote utakachochagua, ubao wa kunakili hubaki ndani ya handaki la kikundi na TLS ya vifaa vyenyewe, kwa hiyo hakuna kitu kati ya vifaa vyako kinachoweza kuusoma. Ufichaji hubadilisha tu jinsi pakiti zinavyoonekana kwenye waya.

## Ipi ya kutumia

1. Jaribu **WireGuard ya kawaida** kwanza. Ni ya haraka zaidi na hufanya kazi kwenye mitandao mingi.
2. Handaki likishindwa kusimama kwenye mtandao fulani, au likikatwa baada ya muda, washa **AmneziaWG**. Vichujio vingi vinavyotafuta WireGuard havilitambui tena.
3. Hata hilo likizuiwa, kama ilivyo katika nchi zinazozuia kila aina isiyojulikana ya trafiki, tumia **VLESS na REALITY**. Inahitaji kisambazaji (chako mwenyewe au, baadaye, cha mradi) kinachosikiliza mlango wa TCP 443.

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

## VLESS na REALITY

VLESS hufanya kazi kati ya vifaa vyako na kisambazaji. REALITY hufanya kisambazaji kijibu kama tovuti halisi, maarufu: mtu yeyote anayeunganishwa nacho bila funguo za kikundi, mdhibiti anayekijaribu kwa mfano, hupata kurasa za tovuti hiyo yenyewe. Kwa hiyo kisambazaji lazima kiwekwe kwanza, kisha kitovu.

1. **Kwenye kisambazaji**, chagua tovuti kubwa ya HTTPS isiyozuiwa katika nchi unayosafiria na inayounga mkono TLS 1.3, na uanzishe kisambazaji nayo:

   ```sh
   cbb forward -vless-site www.example.com
   ```

   Kisambazaji sasa husikiliza pia kwenye TCP 443 (`-vless-listen` kwa mlango mwingine). Fungua mlango huo kwenye ngome ya moto ya seva, kando ya UDP na TCP 8764. Kuiandaa seva kumeelezwa katika [kuendesha seva zako mwenyewe](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Kwenye kitovu**:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key> -vless
   ```

   Ongeza `-obfuscate` pia ukipenda; zote mbili basi zinatumika.

3. **Kwenye vifaa**: kutana na kitovu nyumbani mara moja, kama baada ya mabadiliko yoyote. Kuanzia hapo hufikia kisambazaji kupitia VLESS tu, kamwe si kwa WireGuard ya kawaida kwanza, kwa hiyo mtandao unaotaka kuficha handaki kutoka kwake haulioni kamwe.

## Vidokezo kwa nchi zinazochuja

- **Weka kila kitu nyumbani, kabla ya kusafiri.** Vifaa huchukua mipangilio ya kitovu kwenye mtandao wa nyumbani tu.
- Chagua kisambazaji nje ya nchi inayochuja, kwa mtoa huduma wa upangishaji asiyezuiwa huko.
- Kwa VLESS, chagua tovuti ambayo watu wa nchi hiyo huitumia kila siku, ili kuizuia kuwaumize; na inayohudumiwa na mtoa huduma tofauti na wa kisambazaji chako.
- VPN ya simu yenyewe inaendelea kufanya kazi: handaki la programu ni trafiki ya kawaida ya programu na halichukui nafasi ya VPN ya simu.
- Handaki likiacha kufanya kazi safarini, `cbb global` kwenye laptopu husema kinachoshindwa, na `CBB_DEBUG=1` huonyesha maelezo ([utatuzi wa matatizo](troubleshooting.md#sync-away-from-home)).
