<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e056f57a7649 -->
# Kifaa kikipotea au kuibwa

Kwa yeyote ambaye simu, kompyuta au kifaa kingine cha kikundi chake kimepotea. Kiondoe kwenye kikundi haraka iwezekanavyo; vifaa vingine hubaki kwenye kikundi na kuendelea kusawazisha.

## 1. Kiondoe

Kwenye simu ambayo ni msimamizi, gusa kifaa kilichopotea kwenye **Mwanzo**, kisha **Remove**. Kwenye kompyuta ya msimamizi:

```sh
sudo cbb remove NAME     # NAME, or the device ID, as cbb status shows it
```

Kila kifaa cha kikundi hujua hilo na kuacha kuzungumza na kilichopotea. Ni mzizi tu, au simu ya msimamizi, anayeweza kumwondoa msimamizi.

## 2. Kama kilikuwa kompyuta ya msimamizi: kigandishe kwanza

Funguo za kompyuta ya msimamizi zinaweza kusaini. Ikiwezekana iko mikononi mwa mtu mwingine, igandishe kutoka kwa msimamizi yeyote, ili chochote itakachosaini kuanzia sasa kisihesabiwe, kisha uiondoe:

```sh
sudo cbb freeze NAME
```

Msimamizi aliyegandishwa hawezi kugandisha mzizi wala simu ya msimamizi. Akigandisha kwa kujibu, wote wawili hubaki wamegandishwa hadi mzizi aamue (`cbb unfreeze` au `cbb remove` kwenye mzizi, au **Unfreeze** na **Remove** kwenye simu ya mzizi).

## 3. Kama kilikuwa mzizi: chukua kikundi

Mzizi unashika ufunguo wa mzizi wa kikundi. Ukipotea, kifaa kingine cha kikundi kinakuwa mzizi
kwa **ufunguo wa urejeshaji** wa kikundi, karatasi au YubiKey uliyohifadhi ulipounda kikundi,
na kila kifaa kingine kinabaki kwenye kikundi:

- kwa simu: kwenye simu yako nyingine, fungua urejeshaji kwenye programu na uipe ufunguo wa
  urejeshaji;
- kwa kompyuta: kwenye kompyuta nyingine ya kikundi, `sudo cbb recovery` na karatasi ya
  urejeshaji (`sudo cbb recovery -yubikey` na YubiKey), ukitaja kifaa kilichopotea kwa
  `-leave NAME`.

Inaonyesha nani anabaki na nani anaondoka na inauliza mara moja; mabadiliko yanaanza mara
moja, na kuanzia hapo kikundi kinakataa kifaa kilichopotea. Hakuna anayechukua kikundi bila
ufunguo wa urejeshaji, hata msimamizi.

Bila ufunguo wa urejeshaji kikundi hakiwezi kuchukuliwa: unda kikundi kipya na uongeze vifaa
tena. Ndiyo sababu programu inauliza jinsi ya kuuhifadhi mara tu kikundi kinapoundwa.

## 4. Zima kile kilichoweza kufikia

Kuondoa kifaa kunatosha kwa kikundi. Ikiwa huwezi kukiondoa bado, au unataka uhakika kuhusu vifaa vingine, msimamizi anaweza pia kuzima ukiwa mbali:

| Nini | Amri kwenye kompyuta ya msimamizi |
|---|---|
| [Kubandika kwa mbali](remote-paste.md) kwenye kifaa, au kwenye vyote | `cbb paste-receive off -on DEVICE`, `-all` |
| [Vitendo vya haraka](quick-actions.md) kwenye kifaa, au kwenye vyote | `cbb action off -on DEVICE`, `-all` |
| Usawazishaji ukiwa mbali na nyumbani kwenye kifaa | `cbb global off -on DEVICE` |

Simu ya msimamizi hutoa hayo hayo kwenye ukurasa wa kifaa, na saa ya msimamizi inaweza pia kutuma haya. Ni mtumiaji wa kila kifaa pekee anayeyawasha tena.

## Mwizi anapata nini

Inategemea mahali kifaa kilipoweka funguo zake ([funguo na uthibitisho](keys.md)):

- **Funguo kwenye maunzi** (simu, Mac zenye Secure Enclave, kompyuta zenye TPM): hakuna cha kunakili. Funguo husaini kwenye kifaa hicho tu, na funguo za mzizi na msimamizi za simu husaini tu baada ya uso wako, alama ya kidole au nambari ya siri.
- **Funguo kwenye faili** (Mac za Intel bila chipu ya T2, na Windows PC na kompyuta za Linux bila TPM, vifaa vidogo): yeyote anayenakili faili anaweza kutenda kama kifaa hicho hadi utakapokiondoa. Simba diski (FileVault, BitLocker, LUKS) ili kifaa kilichoibwa kisitoe chochote.

Historia ya ubao wa kunakili haihifadhiwi kwenye vifaa, na siri hupotea sekunde 60 baada ya kunakiliwa.
