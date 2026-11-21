// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group's recovery key on a YubiKey held to the phone's NFC or plugged
// into its USB-C port (docs/apps.md, "Recovery key"). Over NFC reader mode
// finds the card's IsoDep tag and the function setCard gives the core
// carries each APDU with IsoDep's transmit. On USB the app finds the
// YubiKey's CCID interface (class 0x0B), asks for the right to use it,
// claims it and moves the bytes of its bulk endpoints, and the core frames
// each APDU (the transport ccid_bulk, member/src/piv/ccid.rs). Either way the
// core speaks PIV (ffi/src/piv.rs), as the other phones' kits do.

import { bundleManager, common } from '@kit.AbilityKit';
import { nfcController, tag } from '@kit.ConnectivityKit';
import { BusinessError, usbManager } from '@kit.BasicServicesKit';
import cbb from 'libcbb_napi.so';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';

// How long the app waits for the card to be held to the phone.
const HOLD_MS: number = 60000;
// How long one APDU may take on the card, a signature included.
const APDU_MS: number = 10000;
// How often the app looks for a YubiKey plugged in while it waits for one.
const POLL_MS: number = 300;
// One bulk-in read on USB: how long it waits, and at most how many bytes
// (the core's own bound on one read).
const READ_MS: number = 1000;
const READ_MAX: number = 16384;
const WRITE_MS: number = 5000;
// The USB interface class of a smart card reader (CCID).
const CLASS_CCID: number = 0x0b;

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
  } else if (d.includes('wrong PIN') || d.includes('PIN has 6 to 8')) {
    shown = t('error_yubikey_wrong_pin');
  } else if (d.includes('firmware 5.3')) {
    shown = t('error_yubikey_old');
  } else if (d.includes('holds no recovery key')) {
    shown = t('error_yubikey_no_key');
  } else if (d.includes('already holds a recovery key')) {
    shown = t('error_yubikey_holds_one');
  } else if (d.includes('already holds something')) {
    shown = t('error_yubikey_taken');
  } else if (d.includes('management key')) {
    shown = t('error_yubikey_management_key');
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

function hostsUsb(): boolean {
  return canIUse('SystemCapability.USB.USBManager');
}

function hasNfc(): boolean {
  return canIUse('SystemCapability.Communication.NFC.Tag') && nfcController.isNfcAvailable();
}

// Whether the phone can reach a YubiKey at all, over NFC or USB.
export function canReachCard(): boolean {
  return hasNfc() || hostsUsb();
}

// The smart card interface of a device, if it has one.
function ccidOf(d: usbManager.USBDevice): usbManager.USBInterface | undefined {
  for (const c of d.configs) {
    for (const i of c.interfaces) {
      if (i.clazz === CLASS_CCID) {
        return i;
      }
    }
  }
  return undefined;
}

// The first plugged-in device with a smart card interface, if any.
function pluggedCard(): usbManager.USBDevice | undefined {
  if (!hostsUsb()) {
    return undefined;
  }
  try {
    return usbManager.getDevices().find((d: usbManager.USBDevice) => ccidOf(d) !== undefined);
  } catch (e) {
    Errors.log(`yubikey: listing USB devices: ${String(e)}`);
    return undefined;
  }
}

// Runs work on the YubiKey d plugged into the USB port, with the transport
// ccid_bulk; the interface is released when work ends.
async function onUsb(d: usbManager.USBDevice, work: (transport: string) => Promise<string>, run: CardRun): Promise<void> {
  if (!usbManager.hasRight(d.name) && !(await usbManager.requestRight(d.name))) {
    run.failure = new Failure(t('error_yubikey_usb_denied'), 'yubikey: the USB device was not allowed');
    return;
  }
  const face = ccidOf(d) as usbManager.USBInterface;
  let input: usbManager.USBEndpoint | undefined = undefined;
  let output: usbManager.USBEndpoint | undefined = undefined;
  for (const e of face.endpoints) {
    if (e.type !== 2) { // bulk
      continue;
    }
    if (e.direction === usbManager.USBRequestDirection.USB_REQUEST_DIR_FROM_DEVICE) {
      input = e;
    } else {
      output = e;
    }
  }
  if (input === undefined || output === undefined) {
    run.failure = new Failure(t('error_yubikey'), 'yubikey: the smart card interface has no bulk endpoints');
    return;
  }
  const bulkIn = input as usbManager.USBEndpoint;
  const bulkOut = output as usbManager.USBEndpoint;
  const pipe = usbManager.connectDevice(d);
  try {
    const claimed = usbManager.claimInterface(pipe, face, true);
    if (claimed !== 0) {
      run.failure = new Failure(t('error_yubikey'), `yubikey: claiming the smart card interface: ${claimed}`);
      return;
    }
    cbb.setCard(async (bytes: ArrayBuffer): Promise<ArrayBuffer> => {
      if (bytes.byteLength > 0) {
        const n = await usbManager.bulkTransfer(pipe, bulkOut, new Uint8Array(bytes), WRITE_MS);
        if (n !== bytes.byteLength) {
          throw new Error(`the YubiKey on USB took ${n} of ${bytes.byteLength} bytes`);
        }
        return new Uint8Array([0]).buffer;
      }
      const buf = new Uint8Array(READ_MAX);
      let n = -1;
      try {
        n = await usbManager.bulkTransfer(pipe, bulkIn, buf, READ_MS);
      } catch (e) {
        n = -1;
      }
      if (n < 0) {
        // A timeout, or a YubiKey that left: only the second ends the step.
        if (pluggedCard() === undefined) {
          throw new Error('the YubiKey left the USB port');
        }
        n = 0;
      }
      const out = new Uint8Array(n + 1);
      out.set(buf.subarray(0, n), 1);
      return out.buffer;
    }, true);
    run.answer = await work('ccid_bulk');
  } finally {
    try {
      usbManager.releaseInterface(pipe, face);
      usbManager.closePipe(pipe);
    } catch (e) {
      Errors.log(`yubikey: releasing the USB device: ${String(e)}`);
    }
  }
}

// Waits for a YubiKey, held to the phone in reader mode or plugged into the
// USB port, whichever comes first, and runs work with it: work's calls of
// cbb.piv, with the transport work is given, talk to that card. plugged is
// called when it is one on USB, so the screen can ask for the touch.
export async function withCard(context: common.UIAbilityContext, work: (transport: string) => Promise<string>,
  plugged: () => void = () => {}): Promise<CardRun> {
  const run = new CardRun();
  const already = pluggedCard();
  if (already !== undefined) {
    plugged();
    try {
      await onUsb(already, work, run);
    } catch (e) {
      run.failure = e instanceof Failure ? e : Errors.unexpected('yubikey: usb', e as Object);
    }
    return run;
  }
  const usb = hostsUsb();
  if (!hasNfc() && !usb) {
    run.failure = new Failure(t('error_no_nfc'), 'yubikey: the phone has neither NFC nor USB host');
    return run;
  }
  const nfcOn = hasNfc() && nfcController.getNfcState() === nfcController.NfcState.STATE_ON;
  if (!nfcOn && !usb) {
    run.failure = new Failure(t('error_nfc_off'), 'yubikey: NFC is off');
    return run;
  }
  const element = abilityElement(context);
  let found: (info: tag.TagInfo | usbManager.USBDevice) => void = () => {};
  let failed: (e: Failure) => void = () => {};
  const held = new Promise<tag.TagInfo | usbManager.USBDevice>((resolve, reject) => {
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
  const poll = usb ? setInterval(() => {
    const d = pluggedCard();
    if (d !== undefined) {
      found(d);
    }
  }, POLL_MS) : -1;
  let reading = false;
  if (nfcOn) {
    try {
      tag.on('readerMode', element, [tag.NFC_A, tag.NFC_B], onTag);
      reading = true;
    } catch (e) {
      if (!usb) {
        clearTimeout(timer);
        run.failure = Errors.unexpected('yubikey: reader mode', e as Object);
        return run;
      }
      Errors.log(`yubikey: reader mode: ${String(e)}`);
    }
  }
  const stop = () => {
    clearTimeout(timer);
    if (poll !== -1) {
      clearInterval(poll);
    }
    if (reading) {
      reading = false;
      try {
        tag.off('readerMode', element, onTag);
      } catch (e) {
        Errors.log(`yubikey: leaving reader mode: ${String(e)}`);
      }
    }
  };
  try {
    const got = await held;
    if ((got as usbManager.USBDevice).configs !== undefined) {
      stop();
      plugged();
      await onUsb(got as usbManager.USBDevice, work, run);
      return run;
    }
    clearTimeout(timer);
    if (poll !== -1) {
      clearInterval(poll);
    }
    let iso: tag.IsoDepTag;
    try {
      iso = tag.getIsoDep(got as tag.TagInfo);
    } catch (e) {
      run.failure = new Failure(t('error_yubikey'), `yubikey: no IsoDep: ${String(e)}`);
      return run;
    }
    iso.connect();
    iso.setTimeout(APDU_MS);
    cbb.setCard(async (apdu: ArrayBuffer): Promise<ArrayBuffer> => {
      const out = await iso.transmit(Array.from(new Uint8Array(apdu)));
      return new Uint8Array(out).buffer;
    }, false);
    try {
      run.answer = await work('apdu');
    } finally {
      try {
        iso.resetConnection();
      } catch (e) {
        Errors.log(`yubikey: closing the tag: ${String(e)}`);
      }
    }
  } catch (e) {
    if (e instanceof Failure) {
      run.failure = e;
    } else {
      run.failure = Errors.unexpected('yubikey', e as Object);
    }
  } finally {
    stop();
  }
  return run;
}
