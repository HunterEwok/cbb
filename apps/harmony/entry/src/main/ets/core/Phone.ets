// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// This phone as the group sees it: its name and its system.

import { deviceInfo } from '@kit.BasicServicesKit';

// The system's name in the protocol (docs/protocol.md, section 6).
export const OS: string = 'harmonyos';

// Where the keys live, as the phone's hello says: HUKS keeps them in the TEE.
export const STORE: string = 'hardware';

// The name the other devices show: the phone's model, as the user named it
// in the settings when the system gives that.
export function phoneName(): string {
  const name = deviceInfo.marketName.length > 0 ? deviceInfo.marketName : deviceInfo.productModel;
  return name.length > 64 ? name.substring(0, 64) : name;
}

// The system's version for the hello, as "HarmonyOS 5.0.1".
export function osVersion(): string {
  return deviceInfo.osFullName.length > 0 ? deviceInfo.osFullName : `HarmonyOS ${deviceInfo.sdkApiVersion}`;
}
