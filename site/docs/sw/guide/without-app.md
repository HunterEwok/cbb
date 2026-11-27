<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: f59470cc5a63 -->
# Bila programu

Kwa yeyote anayetaka kuunda na kusimamia kikundi cha Connect Beyond Borders kwa kutumia kompyuta pekee, bila programu ya simu. Kwenye ukurasa huu, unaunda kikundi kwenye kompyuta moja, unaongeza kompyuta zaidi kwenye mtandao wako wa nyumbani, unaweka msimamizi wa pili, na unaongeza kompyuta kutoka mtandao mwingine kupitia SSH au VPN.

![Kompyuta ya Linux inashikilia kikundi na kuongeza Mac na Windows kwa msimbo wa tarakimu sita](../images/without-app.svg)

Kompyuta inayounda kikundi inakuwa **kifaa kikuu** chake (kinachoitwa *root* katika zana za mstari wa amri na michoro). [Usakinishaji wa Linux bila root](install.md#without-sudo-rootless) hauwezi kamwe kuwa kifaa kikuu wala msimamizi, na kontena ya Docker inahitaji `CBB_KEYS_IN_FILE=yes` katika mazingira yake kabla ya kushikilia funguo za kikundi.

## 1. Unda kikundi kwenye kompyuta

Chagua kompyuta inayowashwa mara kwa mara (Linux, macOS, Windows, au FreeBSD) na [usakinishe Connect Beyond Borders](install.md).

1. Endesha kwenye kompyuta hiyo (acha `sudo` kwenye terminal ya msimamizi wa mfumo kwenye Windows, au bofya **Unda kikundi** katika programu ya Mac au programu ya trei):

   ```sh
   sudo cbb new
   ```

2. Hifadhi **karatasi ya urejeshaji** inayoonyeshwa kwenye skrini—mistari minne ya herufi na tarakimu pamoja na msimbo wa QR. Ichapishe au uiandike na uihifadhi mahali tofauti na vifaa vyako.

**Matokeo:** Kompyuta hii inakuwa kifaa kikuu cha kikundi. Kwenye Mac yenye Apple silicon au chipu ya T2, au kompyuta ya Linux au Windows yenye TPM 2.0, funguo zake hukaa kwenye maunzi ya usalama; vinginevyo hukaa kwenye faili zilizolindwa (`cbb keys` huanza kwenye `files`; tazama [Funguo na uthibitisho](keys.md)). Hakuna kinachohifadhi nakala ya karatasi ya urejeshaji—ndiyo njia pekee ya kuhamisha kikundi ikiwa kompyuta hii itapotea.

## 2. Ongeza kompyuta kwenye mtandao wako wa nyumbani

Sakinisha Connect Beyond Borders kwenye kila kompyuta ya ziada kwenye mtandao mmoja wa nyumbani, kisha ioanishe:

1. Kwenye kifaa kikuu (au kompyuta yoyote ya msimamizi), fungua dirisha la kuoanisha:

   ```sh
   sudo cbb pair
   ```

   **Matokeo:** Terminal inaonyesha msimbo wa kuoanisha wa tarakimu 6 na msimbo wa QR, na inasubiri kwa dakika 5. Unaweza pia kufungua dirisha la kuoanisha kutoka kitufe cha **+** katika programu ya Mac au programu ya trei.

2. Kwenye kompyuta mpya, jiunge na kikundi:
   - **Terminal:** Endesha `sudo cbb pair -code` (acha `sudo` kwenye terminal ya msimamizi wa mfumo kwenye Windows) na uandike tarakimu 6 unapoulizwa.
   - **Programu ya kompyuta:** Fungua **CBB**, chagua **Jiunge na kikundi**, na uandike tarakimu 6.

   Kila msimbo usio sahihi hutumia mojawapo ya majaribio 3; dirisha hufungwa baada ya majaribio 3 yasiyofanikiwa au mara tu kifaa kinapojiunga.

**Matokeo:** Kompyuta zote mbili zinathibitisha kujiunga, na mbao zako za kunakili husawazisha kiotomatiki. Nakili maandishi kwenye kompyuta moja na uyabandike kwenye nyingine ili kuhakikisha (tazama [Kuanza haraka: nakili kwenye kimoja, bandika kwenye kingine](quickstart.md#4-copy-on-one-paste-on-another)).

## 3. Ongeza msimamizi wa pili na uhifadhi karatasi yako ya urejeshaji salama

Pandisha cheo kompyuta ya pili kuwa **msimamizi** ili bado uweze kuongeza na kuondoa vifaa wakati kifaa kikuu kiko nje ya mtandao. Kumbuka kwamba kompyuta inaweza kupandishwa cheo kuwa msimamizi ikiwa tu ilioanishwa moja kwa moja na kifaa kikuu.

1. Tafuta jina la kompyuta au kitambulisho cha kifaa kwa `cbb status`.
2. Kwenye kifaa kikuu, pandisha cheo kompyuta hiyo:
   - **Kompyuta yenye TPM 2.0 au Secure Enclave:**

     ```sh
     sudo cbb admin NAME
     ```

   - **Kompyuta ambayo funguo zake hukaa kwenye faili** (inahitaji kiwango cha funguo `files`, kinachowekwa kwa `sudo cbb keys files`):

     ```sh
     sudo cbb admin -allow-file-key NAME
     ```

     Yeyote anayenakili faili za funguo za msimamizi mwenye funguo za faili anaweza kutenda kama msimamizi hadi msimamizi mwingine aiondoe kompyuta hiyo, kwa hiyo pandisha cheo kompyuta unazozilinda kimwili na zenye diski iliyosimbwa pekee.

**Matokeo:** `cbb status` inaorodhesha kompyuta ya pili kama msimamizi, nayo inaweza kuendesha `sudo cbb pair` na `sudo cbb remove NAME` kwa wanachama wa kawaida.

Ikiwa kifaa kikuu kitawahi kupotea au kuharibika, hamishia kikundi kwenye kompyuta nyingine ya kikundi kwa kutumia karatasi yako ya urejeshaji:

```sh
sudo cbb recovery -leave LOST-DEVICE
```

Kisha andika ufunguo wa urejeshaji kutoka kwenye karatasi unapoulizwa (au pitisha `-yubikey` ikiwa uliufunga kwenye YubiKey). Tazama [Kifaa kikipotea au kuibiwa](lost-device.md) kwa utaratibu kamili.

## Kujiunga kutoka mtandao mwingine

Ili kuongeza kompyuta ambayo haiko kwenye mtandao wako wa nyumbani, unaweza kutuma [mwaliko kupitia kitovu](away-from-home.md#a-computer-that-is-not-at-home-an-invitation), au kuoanisha kupitia handaki la SSH au VPN yako mwenyewe.

### Kupitia SSH

1. Kwenye kompyuta mpya, elekeza mlango wa ndani kwenda kwenye mlango wa mwanachama wa kifaa kikuu au msimamizi (8764 kwa chaguo-msingi):

   ```sh
   ssh -N -L 18764:localhost:8764 user@admin-machine
   ```

2. Katika kipindi kingine cha SSH kwenye kifaa kikuu au kompyuta ya msimamizi, fungua dirisha la kuoanisha:

   ```sh
   sudo cbb pair
   ```

   Nakili mstari mzima wa `cbb://pair?...` uliochapishwa chini ya tarakimu 6. (Bila ugunduzi wa mtandao wa ndani, tarakimu 6 peke yake haziwezi kutambua dirisha; mstari wa `cbb://pair?...` hubeba maelezo ya dirisha na msimbo vyote viwili.)

3. Kwenye kompyuta mpya, jiunge kupitia mlango ulioelekezwa na ubandike mstari wa `cbb://pair?...` unapoulizwa:

   ```sh
   sudo cbb pair -code 127.0.0.1:18764
   ```

**Matokeo:** Kompyuta mpya inajiunga na kikundi kupitia handaki la SSH ndani ya TLS 1.3.

### Kupitia VPN yako mwenyewe

1. Kwenye Linux, ikiwa uliweka VPN baada ya kusakinisha Connect Beyond Borders, endesha kisakinishi tena ili kanuni za ngome ziruhusu subnet yako ya VPN.
2. Kwenye kifaa kikuu au kompyuta ya msimamizi, endesha `sudo cbb pair` na unakili mstari wa `cbb://pair?...` uliochapishwa chini ya tarakimu 6.
3. Kwenye kompyuta mpya, jiunge kwa kutumia anwani ya VPN na mlango wa kompyuta ya msimamizi, na ubandike mstari wa `cbb://pair?...` unapoulizwa:

   ```sh
   sudo cbb pair -code ADMIN-VPN-ADDRESS:8764
   ```

**Matokeo:** Kompyuta mpya inajiunga na kikundi chako kupitia VPN ndani ya TLS 1.3.

Siri ya kuoanisha haisafiri kamwe bila usimbaji: kompyuta zote mbili hutengeneza uthibitisho wa kipindi ndani ya TLS 1.3. Kompyuta mpya huendelea kusawazisha kupitia njia hiyo ya muda ya kuoanisha hadi huduma yake ianzishwe upya; ili kuendelea kusawazisha kwa kudumu baada ya kufunga SSH au VPN yako, sanidi [kusawazisha ukiwa mbali na nyumbani](away-from-home.md) kwenye vifaa vyote viwili kwanza.
