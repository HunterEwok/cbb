// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The app's own words outside a page: the strings of resources/*/element,
// in the phone's language, with %s and %d filled in order.

import { resourceManager } from '@kit.LocalizationKit';

let manager: resourceManager.ResourceManager | undefined = undefined;

export function setResources(m: resourceManager.ResourceManager): void {
  manager = m;
}

export function t(name: string, ...args: (string | number)[]): string {
  if (manager === undefined) {
    return name;
  }
  try {
    return manager.getStringByNameSync(name, ...args);
  } catch (e) {
    return name;
  }
}
