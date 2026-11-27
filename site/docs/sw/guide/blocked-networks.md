<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6e944da2c5ca -->
# Mitandao inayozuia VPN

Kwa yeyote anayesawazisha akiwa mbali na nyumbani kwenye mitandao inayochuja au kuzuia WireGuard, kama vile Wi-Fi ya hoteli, mitandao ya ofisi, waendeshaji wa simu, au nchi zenye uchujaji mkali wa trafiki. Kwenye ukurasa huu, unahakiki au kubadilisha jinsi kitovu chako kinavyoficha handaki lake.

Ukiwa mbali na nyumbani, vifaa vyako hufikia kitovu chako kupitia handaki la WireGuard la kikundi chako. Kwa chaguo-msingi, kitovu hutumia **AmneziaWG** na (kinapooanishwa na kisambazaji chenye uwezo wa VLESS) **VLESS** pia ili handaki lako lipite kwenye mitandao inayochuja. Bila kujali ufichaji unaotumika, nakala zako hubaki ndani ya WireGuard, TLS 1.3 ya pande zote mbili, na usimbaji wa mwisho hadi mwisho; tazama [Jinsi inavyofanya kazi](how-it-works.md#networks-that-block-vpns).

| Njia ya usafirishaji | Kinachoonwa na mtandao | Mahitaji | Vifaa vinavyotumika |
|---|---|---|---|
| **AmneziaWG** (imewashwa kwa chaguo-msingi) | Pakiti za UDP zenye vichwa na ujazaji wa nasibu | Kitovu au kisambazaji | Kompyuta, vifaa vidogo (isipokuwa vipanga njia vya MIPS), simu |
| **VLESS** (imewashwa kwa chaguo-msingi na kisambazaji cha VLESS) | Muunganisho wa HTTPS kwenda tovuti ya kisambazaji | Kisambazaji chenye VLESS imewashwa (kisambazaji cha mradi kwenye `cbb.tools` kinayo) | Kompyuta, vifaa vidogo (isipokuwa vipanga njia vya MIPS), simu |
| **WireGuard ya kawaida** (`-no-obfuscate -no-vless`) | Pakiti za kawaida za UDP za WireGuard | Kitovu au kisambazaji | Kompyuta, vifaa vidogo (isipokuwa vipanga njia vya MIPS), simu |

## Jinsi vifaa vinavyochagua

Wakati kitovu kinatumia kisambazaji chenye uwezo wa VLESS, vifaa vilivyo mbali hujaribu **AmneziaWG** kupitia UDP kwanza kwa sababu UDP ina kasi zaidi pale mtandao unapoiruhusu. Ikiwa UDP imezuiwa — kama kwenye mitandao inayoruhusu trafiki ya wavuti pekee — hubadilika moja kwa moja kwenda **VLESS** kupitia HTTPS (mlango wa TCP 443) kwenda kwa kisambazaji na kubaki kwenye njia iliyofaulu.

VLESS ikiwa imewashwa, vifaa kamwe havirudi kwenye WireGuard ya kawaida, kwa hiyo mitandao inayochuja haioni trafiki ya VPN isiyofichwa. Kitovu kisicho na kisambazaji hutoa AmneziaWG pekee.

Hakuna ufichaji wa handaki unaosaidia kwenye mtandao unaoruhusu miunganisho kwenda tu kwenye orodha maalum ya anwani za IP au vikoa vilivyoidhinishwa.

## Sanidi ufichaji wa handaki katika programu ya kompyuta

Kwenye kitovu kinachoendesha programu ya Mac au programu ya trei ya Linux na Windows:

1. Fungua **CBB** na uchague ukurasa wa kifaa wa kompyuta hii.
2. Chini ya **Mitandao mikali**, washa au zima:
   - **Mitandao inayozuia VPN (AmneziaWG)** ili kuwasha au kuzima AmneziaWG.
   - **Mitandao inayoruhusu wavuti pekee (VLESS)** ili kuwasha au kuzima VLESS (inahitaji kisambazaji kinachotumia VLESS).
3. Thibitisha kwa nywila yako ya msimamizi wa mfumo, Touch ID, Windows Hello, au ombi la polkit.
4. Unganisha kila kompyuta mpakato na simu kwenye mtandao wako wa nyumbani mara moja ili ipokee mipangilio mipya ya handaki ya kitovu.

**Matokeo:** Kitovu huhifadhi mipangilio iliyosasishwa na kuishiriki na vifaa vyako wakati ujao vitakapokutana nyumbani.

## AmneziaWG

Kila kitovu huwasha AmneziaWG kwa chaguo-msingi mara tu unapokiweka:

```sh
sudo cbb global hub 203.0.113.7:8764
```

Kitovu hutengeneza vigezo vya nasibu vya AmneziaWG kwa kikundi chako na kuvibadilisha kiotomatiki katika kila kipindi cha vitambulisho vya seva (takriban mara moja kwa mwezi), kikishiriki seti inayofuata mapema.

Ili kubadilisha kwenda WireGuard ya kawaida kwenye mitandao ambapo hakuna kinachozuia VPN (jambo linalopunguza mzigo wa ziada kwenye pakiti):

1. Endesha kwenye kitovu (tumia `-keep` ili kuhifadhi anwani na kisambazaji kilichopo cha kitovu):

   ```sh
   sudo cbb global hub -keep -no-obfuscate -no-vless
   ```

2. Unganisha kila kompyuta mpakato na simu iliyo mbali kwenye mtandao wako wa nyumbani mara moja (acha programu ya simu wazi kwa muda mfupi) ili ipokee mipangilio mipya.

**Matokeo:** Vifaa vyako hutumia WireGuard ya kawaida mara tu vinapochukua toleo jipya la mipangilio nyumbani.

## VLESS

VLESS hubeba handaki lako lililofichwa kwa AmneziaWG ndani ya kile kinachoonekana kwa mtandao kama muunganisho wa kawaida wa HTTPS kwenda tovuti ya kisambazaji. Kuweka AmneziaWG ndani ya VLESS huficha ukubwa wa pakiti za WireGuard ambao vinginevyo ungeonekana wazi ndani ya HTTPS.

1. **Chagua kisambazaji chenye VLESS:**
   - **Kisambazaji cha mradi kwenye `cbb.tools`** tayari kina VLESS imewashwa; kwa mtandao, vifaa vyako vinaonekana kutembelea `cbb.tools`.
   - **Kisambazaji chako mwenyewe:** Endesha `cbb forward` nyuma ya seva ya wavuti yenye cheti cha TLS cha tovuti yako:

     ```sh
     cbb forward -vless-xhttp vpn.example.org
     ```

     Sanidi seva yako ya wavuti kuelekeza njia ambayo `cbb forward` huchapisha kwenda kwa msikilizaji wa ndani wa kisambazaji (`127.0.0.1:3276` kwa chaguo-msingi) huku ikihudumia kurasa zako za wavuti kwa mtu mwingine yeyote. Fungua **mlango wa TCP 443** kwenye ngome ya seva kando ya mlango wa UDP na TCP 8764. Tazama [Kuendesha seva zako mwenyewe: VLESS kwenye kisambazaji](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Elekeza kitovu chako kwa kisambazaji:** Kwenye kitovu, sajili na kisambazaji cha mradi au chako mwenyewe:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   Kwa kisambazaji chako mwenyewe, weka anwani na ufunguo wake badala yake:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
   ```

   **Matokeo:** Kitovu huomba VLESS kiotomatiki. Ikiwa kisambazaji kinatumia VLESS, hukitumia kitovu jina la tovuti yake na njia; vinginevyo kitovu hujisajili kwa UDP pekee. Ili kuzima VLESS huku ukiendelea kutumia AmneziaWG, ongeza `-no-vless` (kwa mfano, `sudo cbb global hub -keep -no-vless`).

3. **Sawazisha mara moja nyumbani:** Leta kila kompyuta mpakato na simu kwenye mtandao wako wa nyumbani (na fungua programu ya simu kwa muda mfupi) baada ya kubadilisha mipangilio ya kitovu.

   **Matokeo:** Vifaa vyako hupokea toleo la VLESS la kitovu na kulitumia kiotomatiki kila wakati UDP inapozuiwa.

## Vidokezo kwa nchi zinazochuja trafiki

- **Weka na ujaribu nyumbani kabla ya kusafiri.** Vifaa hupokea mipangilio ya handaki ya kitovu kwenye mtandao wako wa nyumbani pekee.
- **Panga kisambazaji chako nje ya nchi inayochuja** kwa mtoa huduma ambaye anwani zake za IP hazizuiwi huko.
- **Tarajia uzuiaji wa vikoa:** Jina la kikoa cha kisambazaji huonekana katika salamu ya TLS (SNI). Ikiwa mtandao unazuia `cbb.tools`, endesha kisambazaji chako mwenyewe nyuma ya jina tofauti la kikoa.
- **Endelea kutumia VPN ya mfumo wako:** Handaki la Connect Beyond Borders huendeshwa ndani ya programu kama trafiki ya kawaida na halichukui nafasi ya VPN ya simu yako, kwa hiyo VPN yako mwenyewe inaendelea kufanya kazi pamoja nayo.
- **Sasisha milango ya kuingilia iliyozuiwa:** Ikiwa milango ya kuingilia ya kisambazaji cha mradi inabadilika na kifaa hakiwezi kuifikia, hamisha milango ya kuingilia iliyotiwa sahihi kutoka kompyuta iliyounganishwa kwa `cbb global entries export` (au `-qr`) na uiingize kwenye kompyuta iliyoathirika kwa `sudo cbb global entries import STRING`.
- **Chunguza matatizo:** Endesha `cbb global` kwenye kompyuta mpakato ili kuona sababu ya handaki kushindwa, na washa `CBB_DEBUG=1` kwenye huduma ili kuona kumbukumbu za salamu ya WireGuard ([Utatuzi wa matatizo: usawazishaji ukiwa mbali na nyumbani](troubleshooting.md#sync-away-from-home)).
