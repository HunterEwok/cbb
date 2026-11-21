<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: fc79c2973911 -->
# Funguo na uthibitisho

Kila kifaa katika kikundi kina funguo: kimoja huthibitisha kwa vingine kifaa ni nani, na funguo za mzizi na wasimamizi huongeza na kuondoa vifaa. Mahali kifaa kinapoweka funguo zake huamua mwizi anapata nini pamoja na kifaa. Ukurasa huu unasema kila aina ya kifaa huziweka wapi, kikundi kinawezaje kukagua, na kiwango gani cha ukali cha kuchagua. Kanuni kamili ziko katika [itifaki](../protocol.md), sehemu ya 17.

> Imejengwa na kujaribiwa katika CI dhidi ya TPM ya programu; kwenye vifaa halisi hadi sasa ni Secure Enclave ya iPhone tu na Windows katika mashine pepe. [Jedwali la hali](../../README.md#status) katika README linaonyesha nini kimejaribiwa wapi.

## Funguo ziko wapi

| Wapi | Vifaa | Mwizi anapata nini |
|---|---|---|
| **Kwenye faili** | Mac za Intel bila chipu ya T2, na Windows PC na kompyuta za Linux bila TPM, vifaa vidogo | nakala ya faili, inayofanya kazi popote hadi msimamizi aondoe kifaa |
| **Kwenye maunzi** | iPhone (Secure Enclave), simu za Android (Keystore: StrongBox au TEE), Mac zenye Apple silicon au chipu ya T2 (Secure Enclave), kompyuta za Linux na Windows PC zenye TPM | hakuna cha kunakili: ufunguo husaini kwenye kifaa hicho tu, na kwenye simu funguo za mzizi na wasimamizi husaini tu baada ya uso wako, alama ya kidole au nambari ya siri |
| **Maunzi yaliyothibitishwa** | simu ya Android ambayo mzizi wa kikundi ulikagua ufunguo wake | sawa na maunzi, na kikundi kinajua ni kweli, si tu kwamba kifaa kinasema hivyo |

Orodha ya vifaa katika programu na `cbb status` (safu ya KEYS) huonyesha kila kifaa kina kipi.

## Ufunguo unathibitishwaje

Kifaa kinaweza kusema ufunguo wake uko kwenye maunzi, lakini programu iliyorekebishwa nayo ingeweza kusema hivyo. Baadhi ya maunzi yanaweza kuthibitisha:

- **Android.** Programu inapounda ufunguo wake, Keystore ya simu husaini cheti kinachoeleza ufunguo: ndani ya StrongBox au TEE, kwenye simu yenye bootloader iliyofungwa na mfumo uliothibitishwa. Cheti kinaongoza hadi mzizi wa uthibitisho wa Google. Programu hukituma kwa mzizi wa kikundi, ambao hukikagua na kurekodi simu kuwa **imethibitishwa**. Hakuna kinachotumwa kwa Google kwa ajili ya hili.
- **Simu yenye bootloader iliyofunguliwa, au mfumo uliosainiwa kwa ufunguo wake mwenyewe** (GrapheneOS na kadhalika) huweka ufunguo wake kwenye maunzi, lakini ukaguzi hauwezi kudhamini mfumo unaouzunguka. Huhesabiwa kama maunzi, si imethibitishwa.
- **Simu zilizofutwa.** Google huchapisha orodha ya simu ambazo funguo zao za uthibitisho zilivuja. Seva ya mradi, `cbb.tools`, huinakili mara moja kwa siku na kusaini nakala. Mzizi wa kikundi hupakua nakala hiyo, kwa hiyo vifaa vyako havimuulizi Google kamwe. Simu iliyo kwenye orodha hushuka kutoka imethibitishwa hadi maunzi.
- **Kompyuta za Linux zenye TPM** huweka ndani yake funguo za mwanachama na msimamizi, kwa hiyo funguo huhesabiwa kama maunzi. TPM ambayo mtengenezaji wake aliandika cheti chake ndani ya chipu (chipu za Infineon, ST na Nuvoton, kama bodi za TPM za Raspberry Pi) huthibitisha hilo kwa mzizi wa kikundi, ambao kisha hurekodi kompyuta kuwa **imethibitishwa**; mtengenezaji haulizwi chochote. TPM za firmware za Intel na AMD mara nyingi huweka cheti chao kwenye seva ya mtengenezaji, kwa hiyo hubaki maunzi. **Vifaa vya Apple** (App Attest) bado havithibitishi funguo zao.

## Viwango vitatu

Kikundi chako kina kiwango, kinachoamua kikundi kinapaswa kuwa na uhakika kiasi gani kabla kifaa hakijaweza kutenda kama mzizi au msimamizi. Kitovu kinachosoma nakala ni msimamizi, kwa hiyo kiwango kinakihusu pia. Kitovu kinachopitisha nakala tu hakihitaji kiwango: nakala hufungwa mwisho hadi mwisho kwa ajili ya vifaa vingine na kamwe si kwa ajili yake, kwa hiyo anayenakili funguo zake anaweza kuchelewesha nakala na kuona kile ambacho kifaa chochote kilicho katikati kinaona ([faragha](privacy.md#what-the-devices-in-between-see)), na hasomi yoyote.

1. **Kali.** Ni maunzi yaliyothibitishwa tu yanayoweza kuwa mzizi au msimamizi. Ili kuthibitisha vifaa zaidi, kiwango hiki pia huuliza huduma zilizo nje ya nyumba yako: Apple kwa App Attest, na Intel au AMD kwa baadhi ya vyeti vya TPM. Huduma hizo hujua kwamba kifaa cha aina hiyo kiliuliza, kutoka kwa anwani yako. Minyororo ya Android huhesabiwa tu ikiwa ilikuja kupitia Remote Key Provisioning ya Google.
2. **Maunzi (chaguo-msingi, linalopendekezwa).** Funguo zilizo kwenye maunzi zinaweza kuwa mzizi au msimamizi, zimethibitishwa au la. Uthibitisho usiohitaji huduma ya nje (Android, TPM zenye cheti chake kwenye chipu) bado hukaguliwa na kuonyeshwa. Hakuna kitu kuhusu vifaa vyako kinachotoka nyumbani kwako, isipokuwa kuleta nakala ya ubatilishaji kutoka `cbb.tools`, ambayo ni faili ileile kwa kila mtu.
3. **Faili zinaruhusiwa (si salama zaidi).** Kifaa chenye funguo kwenye faili pia kinaweza kuwa msimamizi, baada ya onyo: yeyote anayenakili faili hutenda kama msimamizi hadi msimamizi mwingine aondoe kifaa. Kompyuta ambayo funguo zake haziko kwenye TPM au Secure Enclave huwa msimamizi kwa njia hii tu (`cbb admin -allow-file-key`, au onyo kwenye kisanduku cha "Make it an admin" cha simu).

Kiwango cha 2 ndicho chaguo-msingi kwa sababu huweka funguo nje ya faili popote maunzi yanaporuhusu, bila kuiambia huduma yoyote ya nje una vifaa gani.

Kompyuta iliyosakinishwa bila `sudo` ([bila root](install.md#without-sudo-rootless)) kamwe si mzizi, msimamizi wala kitovu cha aina yoyote, katika kiwango chochote: kila programu ya mtumiaji wake inaweza kusoma funguo zake.

## Kifaa kikipotea

Kiondoe kwenye kikundi haraka iwezekanavyo: tazama [kifaa kikipotea au kuibwa](lost-device.md). Ufunguo ulio kwenye maunzi hauwezi kutumika bila kifaa; ufunguo ulio kwenye faili unaweza, hadi kifaa kiondolewe.

## Kisichojengwa bado

Viwango vilivyo hapo juu ni muundo; toleo hili linajenga sehemu yake:

- Simu za Android huthibitisha funguo zao, na mzizi hukagua uthibitisho na orodha ya Google. Nakala kwenye `cbb.tools` itaanza funguo za kusaini za mradi zitakapokuwepo.
- Kiwango ni mpangilio: Settings, Admin keys, kwenye simu ya mzizi, au `cbb keys` kwenye kompyuta ya mzizi. Kikundi kilichoundwa kwenye simu huanza katika kiwango cha 2; kuifanya msimamizi humo kompyuta yenye funguo kwenye faili, baada ya onyo, huhamisha kikundi hadi kiwango cha 3. Kikundi kilichoundwa kwenye kompyuta ambayo ufunguo wake wa mzizi uko kwenye faili huanza katika kiwango cha 3, kwa kuwa mzizi wake wenyewe haufikii kiwango cha 2. Kiwango cha 1 bado hakiulizi huduma zilizo nje ya nyumba yako, na simu ambayo ufunguo wake wenyewe haujathibitishwa haiwezi kukichagua.
- Kompyuta za Linux na Windows PC zenye TPM 2.0 huweka ndani yake funguo za mwanachama na msimamizi, tangu zinapojiunga na kikundi; kompyuta iliyojiunga mapema huendelea na faili yake hadi ijiunge tena. Kwenye Windows hili bado halijajaribiwa kwenye PC halisi. Mac zenye Apple silicon au chipu ya T2 huziweka kwa njia hiyo hiyo kwenye Secure Enclave. Ufunguo wa mzizi wa kikundi kwenye kompyuta na App Attest bado havijajengwa: hadi hapo funguo zao ziko kwenye faili.
