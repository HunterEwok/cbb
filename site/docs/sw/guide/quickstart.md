<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e51f90fef61a -->
# Kuanza haraka

Kwa yeyote anayeweka Connect Beyond Borders kwa mara ya kwanza akiwa na simu na kompyuta kwenye mtandao wa nyumbani. Katika hatua nne, unasakinisha programu ya simu, unaunda kikundi, unaongeza kompyuta yako ya kwanza, na unashiriki ubao wako wa kunakili kati yao.

Connect Beyond Borders hushiriki ubao mmoja wa kunakili uliosimbwa kati ya vifaa vyako mwenyewe bila wingu wala akaunti. Vifaa vyako huunda **kikundi**: seti ya vifaa vinavyoaminiana kupitia rekodi zilizotiwa sahihi badala ya seva kuu. Simu inayounda kikundi ndiyo **kifaa kikuu** chake (kinachoitwa *root* katika zana za mstari wa amri na michoro): hushikilia ufunguo mkuu wa kikundi na hukubali vifaa vipya.

![Simu inayoshikilia ufunguo wa kikundi huunganishwa na kompyuta za Linux, Mac, na Windows ili kila kifaa kishiriki ubao mmoja wa kunakili moja kwa moja kwenye mtandao wako wa nyumbani](../images/group.svg)

Ikiwa unataka kuanzisha kikundi bila programu ya simu (kwa kutumia kompyuta pekee), fuata [Bila programu](without-app.md). Ikiwa una simu pekee, ruka hatua ya 2 na 3, gusa **+** kwenye simu ya kwanza, kisha uguse **Jiunge na kikundi** kwenye kila simu nyingine ili kuchanganua msimbo wake wa QR (tazama [aina mbili za kikundi](how-it-works.md#two-kinds-of-group)).

## 1. Sakinisha programu na uunde kikundi kwenye simu yako

Mwongozo huu unatumia simu ya Android (Android 10 au mpya zaidi). Kwa programu nyingine za simu (iPhone, Aurora OS, na HarmonyOS), tazama [Programu](apps.md).

1. Kwenye simu yako ya Android, pakua `cbb-X.Y.Z.apk` kutoka [toleo la karibuni la GitHub](https://github.com/HunterEwok/cbb/releases/latest).
2. Fungua faili ulilopakua ili kusakinisha Connect Beyond Borders. Android inapouliza, ruhusu kivinjari chako au kidhibiti faili kusakinisha programu.
3. Fungua **CBB** na uguse **Unda kikundi**.
4. Thibitisha kwa alama ya kidole, uso, au kufuli ya skrini unapoulizwa. Programu inaunda ufunguo mkuu wa kikundi ndani ya maunzi ya usalama ya simu yako.
5. Hifadhi **ufunguo wa urejeshaji** wa kikundi, ambao programu inauonyesha mara moja tu. Chagua **Andika kwenye karatasi** ili kuuchapisha au kuuhifadhi, **Andika kwenye YubiKey** ili kuuhifadhi kwenye YubiKey, au vyote viwili. Hifadhi ufunguo wa urejeshaji mahali tofauti na vifaa vyako: ndiyo njia pekee ya kuhamishia kikundi kwenye kifaa kingine kikuu ukipoteza simu hii ([Funguo na uthibitisho](keys.md)).

**Unachoona:** Baada ya kufunga skrini ya ufunguo wa urejeshaji, programu inafungua **Ongeza kifaa** ikiwa na msimbo wa QR na msimbo wa kuoanisha wa tarakimu sita. Ukifunga skrini hiyo, programu inaonyesha **Mwanzo** ambapo simu yako imeorodheshwa kuwa mtandaoni.

## 2. Sakinisha Connect Beyond Borders kwenye kompyuta

Chagua kompyuta iliyo kwenye mtandao mmoja wa nyumbani na simu yako, kama kompyuta mpakato, kompyuta ya mezani, au Raspberry Pi.

- Kwenye **Linux** au **macOS**, fungua terminal na uendeshe:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

  Kwenye macOS 14 au mpya zaidi, unaweza pia kupakua na kufungua `cbb-X.Y.Z.pkg` kutoka [toleo la karibuni la GitHub](https://github.com/HunterEwok/cbb/releases/latest) ili kusakinisha huduma ya chinichini na programu ya upau wa menyu zote mbili.

- Kwenye **Windows** 10 (1809 au mpya zaidi) au 11, fungua PowerShell kwa **Run as administrator** na uendeshe:

  ```powershell
  irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
  ```

Wakati wa usanidi, kisakinishi hukagua sahihi ya upakuaji, husakinisha huduma ya chinichini (`cbb`), na kuuliza hadi maswali mawili:

1. **Kanuni za ngome** (zinaonyeshwa ngome ikiwa inafanya kazi): jibu `y` ili kuruhusu Connect Beyond Borders kuwasiliana kwenye mtandao wako wa nyumbani.
2. **Masasisho ya kiotomatiki**: jibu `y` ili kuruhusu Connect Beyond Borders kukagua kila siku masasisho yaliyotiwa sahihi na kuyasakinisha kiotomatiki.

Kwenye Linux, toka na uingie tena mara moja ili akaunti yako iweze kuendesha `cbb` bila `sudo`. Kwenye Windows, fungua dirisha jipya la terminal.

**Unachoona:** Kisakinishi kinaripoti kuwa Connect Beyond Borders inaendeshwa kwenye mlango wa TCP 8764 na kinachapisha amri inayofuata ya kujiunga na kikundi. Kwa Homebrew, Docker, vipanga njia, na chaguo nyingine, tazama [Kusakinisha](install.md).

## 3. Ongeza kompyuta kwenye kikundi chako

1. Kwenye simu yako, hakikisha **Ongeza kifaa** iko wazi. Ikiwa uko kwenye **Mwanzo**, gusa **+** na uchague **Ongeza kifaa**. Skrini inaonyesha msimbo wa QR na tarakimu sita, na inasubiri kwa dakika tano.
2. Kwenye kompyuta yako, jiunge kwa kutumia terminal au programu ya kompyuta:
   - **Kwenye terminal (Linux na macOS):** endesha `sudo cbb pair -code`, kisha andika tarakimu sita zinazoonyeshwa kwenye simu yako.
   - **Kwenye terminal (Windows):** fungua terminal kama msimamizi wa mfumo, endesha `cbb pair -code`, kisha andika tarakimu sita.
   - **Kwenye programu ya kompyuta (programu ya trei ya Linux, programu ya trei ya Windows, au programu ya upau wa menyu ya macOS):** fungua **CBB**, chagua **Jiunge na kikundi**, andika tarakimu sita, na uthibitishe kwa nywila yako ya msimamizi wa mfumo unapoulizwa.

**Unachoona:** Kompyuta yako inathibitisha kuwa imejiunga na kikundi, na skrini ya **Ongeza kifaa** kwenye simu yako inafungwa. Kwenye skrini ya **Mwanzo** ya simu yako, kompyuta inaonekana katika orodha yako ya vifaa na inaonyesha kuwa iko mtandaoni.

Ongeza kompyuta nyingine zozote kwa njia ileile: sakinisha Connect Beyond Borders, fungua **Ongeza kifaa** kwenye simu yako, na uendeshe `cbb pair -code` (au tumia **Jiunge na kikundi** katika programu ya kompyuta).

## 4. Nakili kwenye kimoja, bandika kwenye kingine

Jaribu kunakili mstari wa maandishi kwenye kompyuta yako, kisha uubandike kwenye simu yako. Kisha nakili maandishi kwenye simu yako na uyatume kwenye kompyuta yako.

- **Kati ya kompyuta:** Nakili kwenye kompyuta moja na ubandike kwenye nyingine kiotomatiki.
- **Kutoka kompyuta hadi Android:** Nakala kutoka kwenye kompyuta zako hufika kwenye ubao wa kunakili wa simu yako kiotomatiki chinichini.
- **Kutoka Android hadi kompyuta:** Fungua **CBB** ili kutuma ulichonakili kiotomatiki (kutuma kukishindwa, kitufe cha **Tuma nilichonakili** kinaonekana kwenye **Mwanzo**). Bila kufungua programu, unaweza kugusa **Tuma** kwenye arifa ya CBB, kugusa wijeti ya skrini ya mwanzo ya **Tuma ubao wa kunakili**, kushiriki maandishi au faili kwa **Connect Beyond Borders**, au kuwasha **Usawazishaji wa ubao wa kunakili** katika **Mipangilio** ya programu ili kutuma nakala kiotomatiki.

Ili kusitisha usawazishaji kwenye kifaa ili ubao wake wa kunakili ubaki wa faragha:

- Kwenye simu yako, gusa kitufe cha **Sawazisha** (ikoni ya nyumba) kwenye **Mwanzo**—au ukishikilie ili kusitisha kwa dakika 15, saa 1, saa 8, au hadi ukiwashe tena—au gusa kigae cha **Sawazisha** katika Mipangilio ya Haraka ya Android.
- Kwenye kompyuta, endesha `cbb sync off` (na `cbb sync on` ili kuendelea), au tumia swichi ya **Sawazisha** katika programu ya kompyuta.

Kwa vipengele na ishara zote za programu katika majukwaa mbalimbali, tazama [Programu](apps.md).

## Hatua zinazofuata zinazopendekezwa

Mara simu yako ya kwanza na kompyuta vinaposawazisha, fikiria nyongeza hizi mbili:

- **Pandisha cheo kompyuta inayowashwa kila wakati iwe msimamizi na kitovu:** Ikiwa una kompyuta inayobaki imewashwa (kama kompyuta ya mezani, seva ya nyumbani, au Raspberry Pi), ifungue kwenye **Mwanzo** kwenye simu yako kuu na uguse **Kifanye msimamizi**. Kompyuta ya msimamizi inaweza kuongeza na kuondoa vifaa (`sudo cbb pair` na `sudo cbb remove NAME`) simu yako isipokuwa karibu. Ikiwa kompyuta haina chipu ya usalama ya maunzi (TPM au Secure Enclave), funguo zake hukaa kwenye faili na programu inakuonya kabla ya kuthibitisha ([Funguo na uthibitisho](keys.md#the-three-levels)). Unaweza pia kuifanya kompyuta inayowashwa kila wakati kuwa **kitovu** cha kikundi chako ili vifaa vyako viendelee kusawazisha vikiwa mbali na nyumbani; tazama [Mbali na nyumbani](away-from-home.md).
- **Ongeza simu ya pili:** Gusa **+** kwenye simu yako kuu, kisha uguse **Jiunge na kikundi** kwenye simu ya pili na uchanganue msimbo wa QR. Simu ya pili inajiunga kama mwanachama. Ili kuiruhusu isimamie vifaa pia, ifungue kwenye **Mwanzo** kwenye simu yako kuu na uguse **Kifanye msimamizi**. Weka ufunguo wako wa urejeshaji salama endapo utawahi kuhitaji kuhamishia kikundi kwenye kifaa kingine kikuu ([Kifaa kikipotea](lost-device.md)).

## Kinachofuata

- [Jinsi inavyofanya kazi](how-it-works.md): Elewa majukumu ya kikundi, usimbaji, na jinsi vifaa vinavyounganishwa nyumbani na mbali.
- [Programu](apps.md): Gundua kile programu za simu, saa, TV, na kompyuta zinaonyesha na kufanya.
- [Mbali na nyumbani](away-from-home.md): Sawazisha ubao wako wa kunakili nje ya mtandao wako wa nyumbani kupitia kitovu au relei pofu.
- [Utatuzi wa matatizo](troubleshooting.md): Tambua matatizo ya muunganisho, ngome, na kuoanisha.
