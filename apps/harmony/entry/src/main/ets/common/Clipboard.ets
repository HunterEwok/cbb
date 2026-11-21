// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The text the user copied, read right after a tap on the system's paste
// button, the one moment HarmonyOS lets the app read it without the
// restricted READ_PASTEBOARD permission; '' when it holds no text.

import { pasteboard } from '@kit.BasicServicesKit';
import { Errors } from '../core/Errors';

export async function clipboardText(): Promise<string> {
  try {
    const data = await pasteboard.getSystemPasteboard().getData();
    return data.getPrimaryText() ?? '';
  } catch (e) {
    Errors.log(`clipboard: ${Errors.unexpected('', e as Object).details}`);
    return '';
  }
}
