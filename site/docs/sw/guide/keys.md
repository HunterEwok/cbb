<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 09c16892691e -->
# Funguo na uthibitisho

Kwa yeyote anayetaka kuelewa kila kifaa kinahifadhi wapi funguo zake za kriptografia, jinsi vifaa vinavyothibitisha kuwa funguo zao ziko kwenye maunzi ya usalama, na **kiwango gani cha funguo** cha kuchagua kwa kikundi chake. Kwa vipimo kamili vya mtandao, tazama [Itifaki](../protocol.md), sehemu ya 17, na [Kriptografia](../cryptography.md).

Kila kifaa katika kikundi hushikilia **ufunguo wa mwanachama** unaothibitisha utambulisho wake kwa vifaa vyako vingine. **Kifaa kikuu** (kinachoitwa *root* kwenye zana za mstari wa amri) hushikilia ufunguo mkuu wa kikundi, na kila **msimamizi** hushikilia ufunguo wa msimamizi unaotia sahihi mabadiliko ya kikundi na amri. Mahali kifaa kinapohifadhi funguo hizo huamua mshambuliaji anaweza kutoa nini ikiwa kifaa kitaibwa.

## Kila kifaa kinahifadhi funguo zake wapi

Orodha ya vifaa kwenye programu na safu ya `KEYS` ya `cbb status` huonyesha ngazi ya hifadhi ya funguo ya kila kifaa: **iliyothibitishwa** (`proven hardware`), **maunzi** (`hardware`), **faili** (`in a file`), au **bila root** (`in a file, rootless`).

| Kifaa | Mahali funguo za mwanachama, msimamizi, na kifaa kikuu zinapokaa | Uthibitisho kabla ya kutia sahihi kama kifaa kikuu/msimamizi | Ngazi ya hifadhi inayoonyeshwa | Mwizi anaweza kuchukua nini |
|---|---|---|---|---|
| **iPhone na iPad** | Secure Enclave (maunzi) | Face ID, Touch ID, au nambari ya siri | `hardware` | Hakuna cha kunakili; funguo hutia sahihi kwenye kifaa hicho pekee baada ya kufunguliwa |
| **Simu au kompyuta kibao ya Android** (bootloader iliyofungwa, mfumo uliothibitishwa) | Android Keystore (StrongBox au TEE, maunzi) | Alama ya kidole, uso, au kufuli ya skrini (inasimamiwa na Keystore) | `proven hardware` | Hakuna cha kunakili; kikundi pia huhakiki uthibitisho wa maunzi nje ya mtandao |
| **Simu au kompyuta kibao ya Android** (bootloader iliyofunguliwa au mfumo uliotiwa sahihi maalum kama GrapheneOS) | Android Keystore (StrongBox au TEE, maunzi) | Alama ya kidole, uso, au kufuli ya skrini | `hardware` | Hakuna cha kunakili; uthibitisho wa mfumo hauwezi kudhaminiwa na vyeti vikuu vya Google |
| **Simu ya Aurora OS 5** | Kipengele salama cha OP-TEE (maunzi) | PIN ya msimamizi ya programu yenyewe (angalau tarakimu 6 inapoundwa; majaribio 7 yasiyo sahihi hufunga ufunguo wa msimamizi kabisa) | `hardware` | Hakuna cha kunakili; ufunguo wa mwanachama husawazisha bila PIN, ufunguo wa msimamizi/kifaa kikuu unahitaji PIN |
| **Simu ya Aurora OS 4 na Sailfish OS** | Faili la programu kwenye simu | Hakuna kutoka maunzi | `in a file` | Nakala ya faili la ufunguo, inayoweza kutumika popote hadi iondolewe |
| **Simu au kompyuta kibao ya HarmonyOS 5+** | HUKS (TEE, maunzi) | Uso, alama ya kidole, au PIN (User Authentication Kit) | `hardware` | Hakuna cha kunakili; funguo hutia sahihi kwenye kifaa hicho pekee baada ya uthibitishaji |
| **Mac yenye Apple silicon au chipu ya T2** | Secure Enclave (maunzi); siri za ndani na za handaki zimefungwa na Secure Enclave | Touch ID ya macOS au nywila ya msimamizi wa mfumo kupitia ombi la mfumo | `hardware` | Hakuna cha kunakili; funguo hutia sahihi kwenye Mac hiyo pekee |
| **Mac ya Intel bila chipu ya T2** | Faili za hali ya huduma (`/Library/Application Support/cbb/state`) | Nywila ya msimamizi wa mfumo wa macOS | `in a file` | Nakala ya faili za funguo ikiwa diski inasomeka; simba kwa FileVault |
| **Kompyuta ya Linux au Windows yenye TPM 2.0 na `cbb-helper`** | TPM 2.0 (maunzi); siri za ndani na za handaki zimefungwa na TPM | polkit ya Linux au Windows Hello / ombi la msimamizi wa mfumo | `proven hardware` (yenye cheti cha EK ndani ya chipu) au `hardware` | Hakuna cha kunakili; funguo hutia sahihi kwenye kompyuta hiyo pekee |
| **Kompyuta ya Linux au Windows bila TPM, FreeBSD, OpenWrt, OPNsense, vifaa vidogo bila `cbb-helper`, Docker** | Faili za hali ya huduma (zinasomeka na akaunti ya huduma pekee) | Haki za msimamizi wa mfumo (`sudo` au terminal ya msimamizi) | `in a file` | Nakala ya faili za funguo ikiwa diski au juzuu inasomeka; simba diski (LUKS, BitLocker) |
| **Usakinishaji wa Linux bila root (`--rootless`)** | Faili za mtumiaji katika `~/.local/state/cbb` | Hakuna (programu yoyote ya mtumiaji wako inaweza kuzisoma) | `in a file, rootless` | Programu yoyote inayoendeshwa chini ya akaunti yako inaweza kunakili faili za funguo; kamwe si kifaa kikuu, msimamizi, wala kitovu |

Kuweka `CBB_TPM=off` kwenye kompyuta huweka funguo mpya zinazotengenezwa kwenye faili badala ya maunzi. Kontena la Docker hukataa kushikilia funguo za kifaa kikuu au za msimamizi isipokuwa uweke `CBB_KEYS_IN_FILE=yes` katika mazingira yake.

### Ufunguo wa urejeshaji

Unapounda kikundi, Connect Beyond Borders hutoa **ufunguo wa urejeshaji** wa kikundi (ufunguo wa ECDSA P-256 uliounganishwa na ufunguo wa SLH-DSA-SHA2-128s ulio sugu kwa kompyuta za kwantamu) kutoka kwa siri moja ya nasibu ya baiti 32. Siri hiyo huonyeshwa mara moja na haihifadhiwi kamwe kwenye kifaa chochote katika kikundi. Unaihifadhi kwenye karatasi (karatasi ya urejeshaji), ikiwa imefungwa kwenye nafasi ya PIV iliyostaafu isiyotumika (nafasi 95 kushuka hadi 82) kwenye YubiKey (programu dhibiti 5.3 au mpya zaidi), au vyote viwili.

## Ufunguo unathibitishwaje

Kifaa chochote kinaweza kuripoti kuwa ufunguo wake uko kwenye maunzi, na programu iliyorekebishwa inaweza kuripoti hivyo kwa uongo. **Uthibitisho wa maunzi** huwezesha chipu ya usalama kutia sahihi uthibitisho wa kriptografia kuwa ufunguo ulitengenezwa ndani ya chipu na hauwezi kuondoka humo.

- **Uthibitisho wa Ufunguo wa Android (Android Key Attestation):** Programu ya Android inapounda ufunguo wake, Android Keystore hutia sahihi mnyororo wa vyeti unaoeleza ufunguo huo (StrongBox au TEE, bootloader iliyofungwa, hali ya kuwasha iliyothibitishwa) unaoanzia kwenye vyeti vikuu vya uthibitisho vya Google. Kifaa kikuu huhakiki mnyororo huu nje ya mtandao na kurekodi simu kuwa **iliyothibitishwa**. Hakuna kinachotumwa kwa Google.
- **Bootloader zilizofunguliwa na mifumo maalum:** Simu zinazoendesha bootloader iliyofunguliwa au mfumo wa uendeshaji uliotiwa sahihi binafsi (kama GrapheneOS) bado huhifadhi funguo ndani ya StrongBox au TEE, kwa hiyo ufunguo hauwezi kutolewa. Kwa sababu mnyororo haudhamini mfumo uliothibitishwa na kiwanda, kikundi hurekodi simu kuwa **maunzi** badala ya **iliyothibitishwa**.
- **Funguo za uthibitisho za Android zilizobatilishwa:** Google huchapisha orodha ya vifaa ambavyo funguo zao za uthibitisho wa maunzi ziliathiriwa. Seva ya mradi kwenye `cbb.tools` huleta orodha hiyo mara moja kwa siku na kutoa nakala iliyotiwa sahihi (`https://cbb.tools/attest/`). Kifaa kikuu huleta nakala iliyotiwa sahihi kutoka `cbb.tools`, kwa hiyo vifaa vyako haviwasiliani na Google kamwe. Simu yoyote ambayo nambari ya mfululizo ya cheti chake inaonekana kwenye orodha hushuka kutoka **iliyothibitishwa** hadi **maunzi**.
- **Uthibitisho wa TPM 2.0 kwenye kompyuta:** Kompyuta ya Linux au Windows yenye TPM 2.0 na `cbb-helper` huhifadhi funguo zake kwenye TPM. Wakati TPM ina cheti cha Endorsement Key (EK) ndani ya chipu kutoka kwa mtengenezaji wake (jambo la kawaida kwenye chipu tofauti za TPM za Infineon, ST, na Nuvoton, kama bodi za TPM za Raspberry Pi), kifaa kikuu huhakiki uwashaji wa kitambulisho cha TPM nje ya mtandao bila kuwasiliana na seva yoyote ya nje na hurekodi kompyuta kuwa **iliyothibitishwa**. TPM za programu dhibiti (zinazopatikana sana kwenye CPU za Intel na AMD) mara nyingi huacha cheti cha EK ndani ya chipu na kwa hiyo hubaki **maunzi**.

## Viwango vitatu

**Kiwango cha funguo** cha kikundi chako huweka ngazi ya chini zaidi ya hifadhi ya funguo inayohitajika ili kifaa kitende kama **kifaa kikuu**, **msimamizi**, au **kitovu kinachosoma nakala**.

**Kitovu kinachopitisha nakala tu** hakihitaji kiwango cha funguo kwa sababu kila nakala imefungwa mwisho hadi mwisho ikikipita: mshambuliaji anayenakili funguo zake anaweza kuchelewesha trafiki na kuona metadata (tazama [Faragha: vifaa vilivyo katikati vinaona nini](privacy.md#what-the-devices-in-between-see)), lakini hawezi kusoma wala kughushi nakala. **Mwanachama wa bila root** hawezi kamwe kuwa kifaa kikuu, msimamizi, wala kitovu katika kiwango chochote cha funguo.

1. **Maunzi yaliyothibitishwa pekee (`proven`):** Ni vifaa tu ambavyo funguo zao zimethibitishwa kwa uthibitisho wa maunzi (`proven`) vinavyoweza kuwa kifaa kikuu, msimamizi, au kitovu kinachosoma nakala. Kwenye Android, uhakiki mkali unahitaji minyororo iliyotolewa kupitia Remote Key Provisioning (RKP) ya Google. Kifaa kikuu ambacho ufunguo wake wenyewe si `proven` hakiwezi kuweka kikundi katika kiwango hiki.
2. **Funguo kwenye maunzi (`hardware`, chaguo-msingi na kinachopendekezwa):** Kifaa chochote ambacho funguo zake ziko kwenye maunzi ya usalama (`hardware` au `proven`) kinaweza kuwa kifaa kikuu, msimamizi, au kitovu kinachosoma nakala. Uthibitisho wa nje ya mtandao (Android Key Attestation na TPM zenye vyeti vya EK ndani ya chipu) bado unahakikiwa na kuonyeshwa, na hakuna taarifa ya kifaa inayoondoka kwenye mtandao wako wa nyumbani zaidi ya kuleta orodha ya pamoja ya ubatilishaji kutoka `cbb.tools`.
3. **Funguo pia kwenye faili (`files`):** Huruhusu pia vifaa ambavyo funguo zao ziko kwenye faili (`file`) kuwa kifaa kikuu, msimamizi, au kitovu kinachosoma nakala, baada ya onyo wazi kila mara (`cbb admin -allow-file-key` kwenye terminal, au kisanduku cha onyo kwenye programu). Kikundi kilichoundwa kwenye kompyuta isiyo na TPM au Secure Enclave huanza kwenye `files`.

### Tazama au badilisha kiwango cha funguo

Ni **kifaa kikuu** cha kikundi pekee kinachoweza kubadilisha kiwango cha funguo:

- **Kwenye programu ya simu au kompyuta:** Fungua **Mipangilio**, washa **Mipangilio ya kina**, kisha nenda **Kikundi > Funguo za msimamizi**.
- **Kwenye terminal kwenye kompyuta kuu:** Endesha `cbb keys` ili kutazama kiwango cha sasa, au kiweke kwa:

  ```sh
  sudo cbb keys proven
  sudo cbb keys hardware
  sudo cbb keys files
  ```

Wasimamizi na vitovu ambavyo tayari viko kwenye kikundi vikiwa na funguo dhaifu zaidi huendelea kufanya kazi hadi uviondoe, na Connect Beyond Borders hukuonya ni vifaa vipi vinavyoshuka chini ya kiwango kipya.

## Kifaa kikipotea

Ondoa kifaa kilichopotea kwenye kikundi chako haraka iwezekanavyo; tazama [Kifaa kikipotea au kuibwa](lost-device.md). Ufunguo uliohifadhiwa kwenye maunzi hauwezi kutolewa wala kutumika nje ya kifaa hicho; ufunguo uliohifadhiwa kwenye faili unaweza kunakiliwa na kutumika hadi uondoe kifaa hicho.
