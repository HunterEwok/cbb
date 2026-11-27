<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 3475f09f1379 -->
# Kifaa kikipotea au kuibwa

Kwa yeyote ambaye simu, kompyuta, au kifaa kingine cha kikundi chake kimepotea au kuibwa. Kwenye ukurasa huu, unaondoa kifaa kilichopotea, unagandisha kompyuta ya msimamizi iliyoibwa, unahamishia kikundi kwenye kifaa kikuu kipya ikiwa kifaa chako kikuu kimepotea, na unazima vipengele vya mbali kwenye vifaa vyako vilivyobaki.

Ondoa kifaa kilichopotea mara tu unapogundua hakipo. Vifaa vyako vilivyobaki hukaa kwenye kikundi na kuendelea kusawazisha bila kuhitaji kuoanishwa tena.

## 1. Ondoa kifaa kilichopotea

Kuondoa kifaa husambaza rekodi ya uondoaji iliyotiwa sahihi ili kila kifaa kingine kikatae miunganisho kutoka kwake na kiache kufunga nakala kwa ajili yake. Ni **kifaa kikuu** (kinachoitwa *root* kwenye zana za mstari wa amri) au **simu ya msimamizi** pekee vinavyoweza kuondoa msimamizi mwingine; kompyuta ya msimamizi huondoa wanachama wa kawaida pekee.

- **Kwenye kifaa kikuu au simu ya msimamizi:**
  1. Fungua **CBB** na uguse kifaa kilichopotea kwenye **Mwanzo**.
  2. Gusa **Ondoa** na uthibitishe kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi.
- **Kwenye kifaa kikuu au kompyuta ya msimamizi (terminal):**

  ```sh
  sudo cbb remove NAME
  ```

  Badilisha `NAME` kwa jina la kifaa au kitambulisho cha kifaa kutoka `cbb status` (acha `sudo` kwenye terminal ya msimamizi wa mfumo kwenye Windows).
- **Kwenye programu ya Mac au programu ya trei (kifaa kikuu au msimamizi):** Fungua paneli ya maelezo ya kifaa kilichopotea, bofya **Ondoa**, na uthibitishe.

**Matokeo:** Kila kifaa kilichounganishwa hukikataa kifaa kilichoondolewa mara moja, na vifaa vilivyo nje ya mtandao hukikataa mara tu vinapounganishwa tena. Kifaa kilichoondolewa kinaweza kujiunga tena kwa kuoanishwa upya kama kifaa kipya pekee.

## 2. Kama kilikuwa kompyuta ya msimamizi: kigandishe kwanza

Kompyuta ya msimamizi inaweza kutia sahihi mabadiliko ya kikundi na kutuma amri. Ikiwa kompyuta ya msimamizi huenda iko mikononi mwa mtu mwingine na huna kifaa kikuu au simu ya msimamizi karibu ili kuiondoa, igandishe kwanza kutoka kifaa chochote cha msimamizi.

1. Endesha kwenye kifaa chochote cha msimamizi:
   - **Terminal:** `sudo cbb freeze NAME`
   - **Programu ya simu au kompyuta:** Fungua kompyuta ya msimamizi kwenye **Mwanzo**, chagua **Gandisha**, na uthibitishe.

   **Matokeo:** Hakuna chochote ambacho msimamizi aliyegandishwa anatia sahihi kinachohesabika kuanzia wakati huo, na kila kifaa kingine hukataa miunganisho yake. Msimamizi aliyegandishwa hawezi kugandisha kifaa kikuu wala simu ya msimamizi.

2. Mara tu unapokuwa na kifaa kikuu au simu ya msimamizi, ondoa kompyuta iliyogandishwa (hatua ya 1).

Ikiwa kompyuta mbili za msimamizi zinagandishana kabla ya kujua kuhusu kugandishwa kwa nyingine, zote mbili hubaki zimegandishwa hadi kifaa kikuu kiamue: endesha `sudo cbb unfreeze NAME` au `sudo cbb remove NAME` kwenye kompyuta kuu, au chagua **Yeyusha** au **Ondoa** kwenye simu kuu.

## 3. Kama kilikuwa kifaa kikuu: hamisha kikundi

**Kifaa kikuu** hushikilia ufunguo mkuu wa kikundi. Ikiwa kifaa kikuu kimepotea au kimeharibika, hamisha kikundi kwenda kifaa kingine ambacho tayari kiko kwenye kikundi kwa kutumia **ufunguo wa urejeshaji** wa kikundi chako — karatasi ya urejeshaji iliyochapishwa au YubiKey uliyohifadhi ulipounda kikundi.

Hakuna anayeweza kuhamisha kikundi bila ufunguo wa urejeshaji, hata msimamizi. Ikiwa huna ufunguo wa urejeshaji, huwezi kuhamisha kikundi: ondoka kwenye kikundi cha zamani kwenye kila kifaa kilichobaki (`sudo cbb leave` au **Ondoka kwenye kikundi** kwenye programu), unda kikundi kipya, na uoanishe vifaa vyako tena.

### Hamishia kikundi kwenye simu iliyo kwenye kikundi

1. Kwenye simu nyingine ambayo tayari iko kwenye kikundi chako, fungua **CBB** na uende **Mipangilio > Hamishia kikundi kwenye simu hii**.
2. Toa ufunguo wa urejeshaji:
   - **Karatasi ya urejeshaji:** Changanua msimbo wa QR ulio kwenye karatasi au andika maandishi yake.
   - **YubiKey:** Shikilia YubiKey kwenye simu (NFC) au ichomeke kwenye mlango wa USB-C (kwenye Aurora OS, USB-C pekee), weka PIN yake, na uguse YubiKey unapoombwa.
3. Kagua orodha ya vifaa vilivyo kwenye kikundi na uondoe alama kwenye kifaa kikuu kilichopotea (na kifaa kingine chochote unachotaka kukitoa).
4. Gusa **Fanya simu hii kuwa kifaa kikuu** na uthibitishe kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi.

**Matokeo:** Simu hii inakuwa kifaa kikuu cha kikundi mara moja ikiwa na ufunguo mkuu mpya. Kila kifaa chenye alama kinabaki kwenye kikundi na kufuata kifaa kikuu kipya mara tu kinapounganishwa; kila kifaa kisicho na alama kinatolewa na kukataliwa na kikundi.

### Hamishia kikundi kwenye kompyuta iliyo kwenye kikundi

1. Kwenye kompyuta nyingine iliyo kwenye kikundi chako, fungua terminal (kama msimamizi wa mfumo kwenye Windows) na uendeshe:
   - **Kwa karatasi ya urejeshaji:**

     ```sh
     sudo cbb recovery -leave LOST-DEVICE
     ```

   - **Kwa YubiKey** (inahitaji `pcscd` kwenye Linux na FreeBSD):

     ```sh
     sudo cbb recovery -yubikey -leave LOST-DEVICE
     ```

   Rudia `-leave NAME` kwa kila kifaa unachotaka kukitoa. Unaweza pia kuanza hatua hii kwenye programu ya Mac au programu ya trei kwa **Hamishia kikundi kwenye Mac hii** / **Hamishia kikundi kwenye kompyuta hii**.
2. Kagua nani anabaki na nani anaondoka, thibitisha, kisha uandike ufunguo wa urejeshaji kutoka kwenye karatasi kwenye uingizaji wa kawaida (au weka PIN ya YubiKey na uiguse inapomweka).

**Matokeo:** Huduma ya kompyuta huanza upya kama kifaa kikuu kipya cha kikundi, huweka kila kifaa kilichoorodheshwa, na kukataa kila kifaa kilichotolewa. Kompyuta hutupa ufunguo wa urejeshaji baada ya badiliko.

## 4. Zima vipengele vya mbali ikihitajika

Kuondoa kifaa kilichopotea hukizuia kutenda katika kikundi chako. Ikiwa huwezi kukiondoa mara moja, au unataka kufunga vifaa vyako vilivyobaki mara moja, msimamizi yeyote anaweza kuzima vipengele hivi kutoka kifaa kingine:

| Kipengele | Amri kwenye kompyuta ya msimamizi | Kwenye programu ya simu ya msimamizi |
|---|---|---|
| [Kubandika kwa mbali](remote-paste.md) | `sudo cbb paste-receive off -on DEVICE` (au `-all`) | Fungua ukurasa wa kifaa na uzime kubandika kwa mbali |
| [Vitendo vya haraka](quick-actions.md) | `sudo cbb action off -on DEVICE` (au `-all`) | Fungua ukurasa wa kifaa na uguse **Zima vyote** |
| [Sawazisha ukiwa mbali na nyumbani](away-from-home.md) | `sudo cbb global off -on DEVICE` | Fungua ukurasa wa kifaa na uzime kusawazisha ukiwa mbali na nyumbani |

**Matokeo:** Vifaa vilivyoathirika huzima vipengele hivyo mara moja. Ni mtumiaji wa kila kifaa pekee anayeweza kuviwasha tena kwenye kifaa chenyewe.

## Mwizi anaweza kufikia nini

Kile ambacho mtu aliyeiba kifaa chako anaweza kupata kinategemea mahali kifaa hicho kinahifadhi funguo zake (tazama [Funguo na uthibitisho](keys.md)):

- **Funguo kwenye maunzi** (simu zenye chipu ya usalama, Mac zenye Apple silicon au chipu ya T2, na kompyuta za Linux au Windows zenye TPM 2.0): Funguo haziwezi kunakiliwa kutoka kwenye kifaa. Kwenye simu, funguo za kifaa kikuu na za msimamizi hutia sahihi baada ya uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi pekee.
- **Funguo kwenye faili** (Mac za Intel bila chipu ya T2, kompyuta za Linux na Windows bila TPM, FreeBSD, vifaa vidogo, simu za Aurora OS 4 na Sailfish OS, na usakinishaji wa Linux bila root): Yeyote anayeweza kusoma diski anaweza kunakili faili za funguo na kujifanya kifaa hicho hadi utakapokiondoa. Acha usimbaji kamili wa diski ukiwa umewashwa (FileVault, BitLocker, au LUKS).

Connect Beyond Borders haihifadhi historia ya ubao wa kunakili. Nakala za kawaida huisha muda wake baada ya muda wa nakala wa kikundi (dakika 5 kwa chaguo-msingi), na siri hubaki kwenye kumbukumbu pekee na kuisha muda baada ya sekunde 60 kwa chaguo-msingi.
