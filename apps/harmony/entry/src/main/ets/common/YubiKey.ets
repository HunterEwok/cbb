// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group's recovery key on a YubiKey over the phone's NFC (docs/apps.md,
// "Recovery key"): reader mode finds the card's IsoDep tag, and the core
// speaks PIV (ffi/src/piv.rs) through the function setCard gives it, which
// carries each APDU with IsoDep's transmit, as the other phones' kits do.

import { bundleManager, common } from '@kit.AbilityKit';
import { nfcController, tag } from '@kit.ConnectivityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import cbb from 'libcbb_napi.so';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';

// How long the app waits for the card to be held to the phone.
const HOLD_MS: number = 60000;
// How long one APDU may take on the card, a signature included.
const APDU_MS: number = 10000;

// What a run with the card answers: the core's answer, or the failure to
// show when no card came.
export class CardRun {
  answer: string = '';
  failure?: Failure;
}

// A failure of the core's PIV in the user's words, its own as the details.
export function cardFailure(f: Failure): Failure {
  const d = `${f.message} ${f.details}`;
  let shown = t('error_yubikey');
  if (d.includes('PIN is blocked')) {
    shown = t('error_yubikey_blocked');
  } else if (d.includes('wrong PIN')) {
    shown = t('error_yubikey_wrong_pin');
  } else if (d.includes('PIN has 6 to 8')) {
    shown = t('error_yubikey_wrong_pin');
  } else if (d.includes('management key is not the factory')) {
    shown = t('error_yubikey_management_key');
  } else if (d.includes('firmware 5.7')) {
    shown = t('error_yubikey_old');
  } else if (d.includes('retired PIV slot of this YubiKey is in use')) {
    shown = t('error_yubikey_full');
  } else if (d.includes('holds no recovery key')) {
    shown = t('error_yubikey_no_key');
  } else if (d.includes('PIV application') || d.includes('no PIV')) {
    shown = t('error_yubikey_no_piv');
  }
  return new Failure(shown, `${f.details} (${f.message})`);
}

function abilityElement(context: common.UIAbilityContext): bundleManager.ElementName {
  const info = context.abilityInfo;
  const element: bundleManager.ElementName = {
    bundleName: info.bundleName, abilityName: info.name, moduleName: info.moduleName
  };
  return element;
}

// Waits for a card held to the phone in reader mode and runs work with it:
// work's calls of cbb.piv and cbb.memberManageCard talk to that card. The
// tag and reader mode end when work does.
export async function withCard(context: common.UIAbilityContext, work: () => Promise<string>): Promise<CardRun> {
  const run = new CardRun();
  if (!canIUse('SystemCapability.Communication.NFC.Tag') || !nfcController.isNfcAvailable()) {
    run.failure = new Failure(t('error_no_nfc'), 'yubikey: the phone has no NFC');
    return run;
  }
  if (nfcController.getNfcState() !== nfcController.NfcState.STATE_ON) {
    run.failure = new Failure(t('error_nfc_off'), 'yubikey: NFC is off');
    return run;
  }
  const element = abilityElement(context);
  let found: (info: tag.TagInfo) => void = () => {};
  let failed: (e: Failure) => void = () => {};
  const held = new Promise<tag.TagInfo>((resolve, reject) => {
    found = resolve;
    failed = reject;
  });
  const onTag = (err: BusinessError, info: tag.TagInfo) => {
    if (err) {
      failed(new Failure(t('error_yubikey'), `yubikey: reader mode: ${err.code} ${err.message}`));
      return;
    }
    found(info);
  };
  const timer = setTimeout(() => {
    failed(new Failure(t('error_yubikey_none'), `yubikey: no card in ${HOLD_MS} ms`));
  }, HOLD_MS);
  try {
    tag.on('readerMode', element, [tag.NFC_A, tag.NFC_B], onTag);
  } catch (e) {
    clearTimeout(timer);
    run.failure = Errors.unexpected('yubikey: reader mode', e as Object);
    return run;
  }
  try {
    const info = await held;
    clearTimeout(timer);
    let iso: tag.IsoDepTag;
    try {
      iso = tag.getIsoDep(info);
    } catch (e) {
      run.failure = new Failure(t('error_yubikey_no_piv'), `yubikey: no IsoDep: ${String(e)}`);
      return run;
    }
    iso.connect();
    iso.setTimeout(APDU_MS);
    cbb.setCard(async (apdu: ArrayBuffer): Promise<ArrayBuffer> => {
      const out = await iso.transmit(Array.from(new Uint8Array(apdu)));
      return new Uint8Array(out).buffer;
    });
    try {
      run.answer = await work();
    } finally {
      try {
        iso.resetConnection();
      } catch (e) {
        Errors.log(`yubikey: closing the tag: ${String(e)}`);
      }
    }
  } catch (e) {
    clearTimeout(timer);
    if (e instanceof Failure) {
      run.failure = e;
    } else {
      run.failure = Errors.unexpected('yubikey', e as Object);
    }
  } finally {
    try {
      tag.off('readerMode', element, onTag);
    } catch (e) {
      Errors.log(`yubikey: leaving reader mode: ${String(e)}`);
    }
  }
  return run;
}
