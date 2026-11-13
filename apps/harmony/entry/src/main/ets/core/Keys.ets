// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's keys in HUKS (src/main/cpp/keys.cpp): the member key, and the
// admin key, which asks for the user's face, fingerprint or PIN before each
// signature through User Authentication Kit; and whether the device guards
// them as a phone does.

import cbb from 'libcbb_napi.so';
import { BusinessError } from '@kit.BasicServicesKit';
import { userAuth } from '@kit.UserAuthenticationKit';
import { read, Result } from './Core';
import { Errors } from './Errors';

export type Which = 'member' | 'admin';

export interface Key {
  public: string; // the point, base64
  created: boolean;
}

export function ensure(which: Which): Promise<Result<Key>> {
  return cbb.keyEnsure(which).then((text: string) => read<Key>(text, `key: ${which}`));
}

export function forget(): Promise<Result<Object>> {
  return cbb.keyForget().then((text: string) => read<Object>(text, 'key: forget'));
}

// Hands the native module the prompt for the admin key: title is the line
// the system's dialog shows.
export function setPrompt(title: string): void {
  cbb.setAuth((challenge: ArrayBuffer): Promise<ArrayBuffer> => {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const param: userAuth.AuthParam = {
        challenge: new Uint8Array(challenge),
        authType: [userAuth.UserAuthType.FACE, userAuth.UserAuthType.FINGERPRINT, userAuth.UserAuthType.PIN],
        authTrustLevel: userAuth.AuthTrustLevel.ATL3
      };
      const widget: userAuth.WidgetParam = { title: title };
      try {
        const auth = userAuth.getUserAuthInstance(param, widget);
        auth.on('result', {
          onResult(result: userAuth.UserAuthResult): void {
            if (result.result === userAuth.UserAuthResultCode.SUCCESS && result.token !== undefined) {
              resolve(result.token.buffer.slice(result.token.byteOffset, result.token.byteOffset + result.token.byteLength) as ArrayBuffer);
            } else {
              reject(`auth: the user did not confirm (${result.result})`);
            }
          }
        });
        auth.start();
      } catch (e) {
        Errors.log(`auth: could not ask the user: ${String(e)}`);
        reject(`auth: ${String(e)}`);
      }
    });
  });
}

// Whether this device guards its keys as a phone does (docs/apps.md, "Big
// screens"): HUKS keeps them in the TEE, so it takes a fingerprint or face
// sensor strong enough for ATL3, enrolled or not yet. One rule for phones
// and tablets: such a device gets the phone's set; another one the
// computer's, and the app says so before it becomes the group's main device.
export function guardsLikeAPhone(): boolean {
  const types: userAuth.UserAuthType[] = [userAuth.UserAuthType.FINGERPRINT, userAuth.UserAuthType.FACE];
  for (const type of types) {
    try {
      userAuth.getAvailableStatus(type, userAuth.AuthTrustLevel.ATL3);
      return true;
    } catch (e) {
      if ((e as BusinessError).code === userAuth.UserAuthResultCode.NOT_ENROLLED) {
        return true;
      }
    }
  }
  return false;
}
