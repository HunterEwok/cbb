<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 2424dc0d0064 -->
# Vitendo vya haraka

Kwa yeyote anayetaka kufunga, kulaza, kuwasha upya, kuzima, au kuendesha programu maalum kwenye kompyuta kutoka kwenye simu ya msimamizi au kompyuta nyingine ya msimamizi katika kikundi.

**Msimamizi** huendesha kitendo cha haraka kwa mguso mmoja au amri moja, na kompyuta lengwa hukiendesha tu ikiwa mtumiaji wa kompyuta hiyo mwenyewe aliwasha kitendo hicho hapo. Kila kitendo cha haraka huanza kikiwa kimezimwa kwa chaguo-msingi, na hakuna anayeweza kuwasha kitendo ukiwa mbali.

## Vitendo vilivyojengwa ndani

| Kitendo | Kinafanya nini | Vifaa vinavyotumika |
|---|---|---|
| `lock` | Hufunga skrini | Kompyuta, vifaa vidogo |
| `sleep` | Hulaza kompyuta | Kompyuta, vifaa vidogo |
| `reboot` | Huwasha upya kompyuta baada ya onyo la dakika 1 | Kompyuta, vifaa vidogo |
| `shutdown` | Huzima kompyuta baada ya onyo la dakika 1 | Kompyuta, vifaa vidogo |
| `cancel-shutdown` | Hughairi kuwasha upya au kuzima kunakosubiri | Kompyuta, vifaa vidogo |
| `restart` | Huwasha upya huduma ya Connect Beyond Borders | Kompyuta, vifaa vidogo |
| `keyboard-layout` | Hubadilisha mpangilio unaotumika wa [kibodi ya Bluetooth](keyboards-and-tvs.md) ya kompyuta kwenda mpangilio unaofuata | Kompyuta za Linux zenye kibodi ya Bluetooth imewashwa |

Kuchelewa kwa dakika 1 kabla ya `reboot` au `shutdown` humpa yeyote aliye kwenye kompyuta muda wa kuhifadhi kazi au kuendesha `cancel-shutdown`. Kwenye Windows, watumiaji walioingia pia huona onyo la mfumo.

Kwenye macOS na Windows, vitendo vya kipindi (`lock`, `sleep`, na vitendo maalum) huendeshwa kupitia wakala wa ubao wa kunakili wa mtumiaji aliyeingia, kwa hiyo lazima mtu awe ameingia. Kwenye macOS, `lock` inahitaji **Mipangilio ya Mfumo > Skrini ya Kufunga > Hitaji nywila baada ya kiokoa skrini kuanza au onyesho kuzimwa** iwekwe kuwa **Mara moja**.

## 1. Washa kitendo kilichojengwa ndani

Endesha amri hizi kwenye kompyuta lengwa (tumia `sudo` kwenye Linux, macOS, na FreeBSD; tumia terminal ya msimamizi wa mfumo bila `sudo` kwenye Windows):

1. Orodhesha vitendo vyote na uone ni nani anayeruhusiwa kuendesha kila kimoja:

   ```sh
   cbb action
   ```

2. Washa kitendo:

   ```sh
   sudo cbb action enable lock
   ```

   Soma kile ambacho kitendo kinaruhusu na uandike `yes` (au weka `-yes` kwenye hati za amri).

   **Matokeo:** Kitendo huwashwa kwa kila msimamizi katika kikundi chako. Kwenye Linux, Connect Beyond Borders huandika `/etc/polkit-1/rules.d/60-cbb.rules` ikiipa huduma haki za polkit zinazohitajika kwa vitendo vilivyowashwa pekee.

3. Kwa hiari, weka kikomo cha wasimamizi gani wanaweza kuendesha kitendo:
   - Weka kikomo kwa aina ya mtia sahihi kwa `-by` (`root` kwa kifaa kikuu, `phone` kwa simu za wasimamizi, `computer` kwa kompyuta za wasimamizi, `watch` kwa saa yenye ufunguo wa msimamizi):

     ```sh
     sudo cbb action enable reboot -by root,phone
     ```

   - Kwa chaguo-msingi, `reboot` na `shutdown` huwakubali tu wasimamizi ambao funguo zao ziko kwenye maunzi (simu, Mac yenye Secure Enclave, au kompyuta yenye TPM 2.0). Ili kuwaruhusu wasimamizi wenye funguo kwenye faili pia, ongeza `-any-key`:

     ```sh
     sudo cbb action enable reboot -any-key
     ```

Ili kuzima kitendo kimoja tena:

```sh
sudo cbb action disable lock
```

**Matokeo:** Kitendo huzimwa mara moja. Kwenye Linux, kukizima husasisha au kuondoa kanuni ya polkit ili haki zisizotumika zibatilishwe.

## 2. Ongeza kitendo chako mwenyewe

Unaweza kufafanua hadi vitendo maalum 32 kwa kila kompyuta (majina lazima yawe herufi ndogo 1 hadi 32, tarakimu, au vistari vifupi, yakianza na herufi).

1. Sajili amri kwenye kompyuta lengwa, ukitoa programu kwa njia yake kamili baada ya `--`:

   ```sh
   sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
   ```

2. Soma muhtasari wa kile ambacho kitendo kinaruhusu na uandike `yes`.

**Matokeo:** Connect Beyond Borders huhifadhi amri katika mipangilio ya mtumiaji wako (`own-actions.json`) ili wakala wa mtumiaji aliyeingia pekee aweze kuendesha faili hilo halisi na orodha hiyo ya hoja bila shell. Mtumaji hupokea hali ya kutoka pekee. Amri lazima zikamilike ndani ya sekunde 15; anzisha kazi ndefu zaidi chinichini.

Ili kuondoa kitendo maalum:

```sh
sudo cbb action remove backup
```

## 3. Endesha kitendo kutoka kwa msimamizi

- **Kutoka kwenye kompyuta ya msimamizi (terminal):**

  ```sh
  cbb action -on DEVICE NAME
  ```

  Badilisha `DEVICE` kwa jina la kifaa lengwa au kitambulisho chake kutoka `cbb status`, na `NAME` kwa jina la kitendo.

  **Matokeo:** `cbb` huchapisha kama kitendo kiliendeshwa au kwa nini kifaa lengwa kilikikataa.

- **Kutoka kwenye simu ya msimamizi:**
  1. Fungua **CBB** na uguse kompyuta lengwa iliyo mtandaoni kwenye **Mwanzo**.
  2. Chini ya **Vitendo vya haraka**, gusa kitendo unachotaka kuendesha.
  3. Thibitisha kwa uso wako, alama ya kidole, nambari ya siri, au (kwenye Aurora OS) PIN yako ya msimamizi. `reboot` na `shutdown` huomba uthibitisho wa pili.

  **Matokeo:** Kifaa lengwa huendesha kitendo na simu huonyesha **Imekamilika.**

## 4. Zima vitendo vyote

- **Moja kwa moja kwenye kompyuta lengwa:**

  ```sh
  sudo cbb action off
  ```

- **Kwa mbali kutoka kompyuta yoyote ya msimamizi:**

  ```sh
  sudo cbb action off -on DEVICE     # one computer
  sudo cbb action off -all           # every computer in the group
  ```

- **Kwa mbali kutoka kwenye simu ya msimamizi:** Fungua ukurasa wa kifaa kwenye **Mwanzo** na uguse **Zima vyote**.

**Matokeo:** Kila kitendo cha haraka kwenye kompyuta zilizoathirika huzimwa mara moja. Ni mtumiaji wa kila kompyuta pekee anayeweza kuviwasha tena kwenye kompyuta yenyewe.

Kila kompyuta lengwa huhifadhi kumbukumbu ya ukaguzi (`actions-log.json`) ya maombi 100 ya mwisho ya vitendo, ikirekodi nani aliomba kila kitendo na lini. Kwa mipaka kamili, tazama [Mipaka na muda](../reference/limits.md#remote-paste-and-quick-actions).
