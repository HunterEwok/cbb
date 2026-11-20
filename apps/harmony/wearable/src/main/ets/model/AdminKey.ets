// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's admin key (docs/apps.md, "HarmonyOS watches"): a P-256 key
// HUKS makes and keeps in the watch's secure storage, usable only while the
// watch has a screen lock; it never leaves the watch. The phone gets its
// public key once, when the root makes the watch an admin, and the watch
// signs with it only a record or command it checked.

import { huks } from '@kit.UniversalKeystoreKit';
import { util } from '@kit.ArkTS';

const ALIAS: string = 'cbb_watch_admin';

function properties(sign: boolean): huks.HuksParam[] {
  const p: huks.HuksParam[] = [
    { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_ECC },
    { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_ECC_KEY_SIZE_256 },
    { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256 }
  ];
  if (sign) {
    p.push({ tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN });
  } else {
    p.push({
      tag: huks.HuksTag.HUKS_TAG_PURPOSE,
      value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN | huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY
    });
    p.push({ tag: huks.HuksTag.HUKS_TAG_IS_DEVICE_PASSWORD_SET, value: true });
  }
  return p;
}

// Makes a new admin key, in place of an earlier one, and answers its
// SubjectPublicKeyInfo in base64; it throws when HUKS made none, as when
// the watch has no screen lock.
export async function makeKey(): Promise<string> {
  const none: huks.HuksOptions = { properties: [] };
  if (await huks.isKeyItemExist(ALIAS, none).catch(() => false)) {
    await huks.deleteKeyItem(ALIAS, none);
  }
  await huks.generateKeyItem(ALIAS, { properties: properties(false) });
  const out = await huks.exportKeyItem(ALIAS, none);
  if (out.outData === undefined || out.outData.length === 0) {
    throw new Error('HUKS exported no public key');
  }
  return new util.Base64Helper().encodeToStringSync(out.outData);
}

// Signs data with the admin key (ECDSA P-256 over its SHA-256, DER) and
// answers the signature in base64.
export async function sign(data: Uint8Array): Promise<string> {
  const options: huks.HuksOptions = { properties: properties(true) };
  const handle = await huks.initSession(ALIAS, options);
  const out = await huks.finishSession(handle.handle, { properties: properties(true), inData: data });
  if (out.outData === undefined || out.outData.length === 0) {
    throw new Error('HUKS made no signature');
  }
  return new util.Base64Helper().encodeToStringSync(out.outData);
}
