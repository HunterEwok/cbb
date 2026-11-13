// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Base64 as the core speaks it, to and from the bytes the sockets carry.

import { util } from '@kit.ArkTS';

const helper: util.Base64Helper = new util.Base64Helper();

export function fromBase64(text: string | undefined): ArrayBuffer {
  if (text === undefined || text.length === 0) {
    return new ArrayBuffer(0);
  }
  const b = helper.decodeSync(text);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

export function toBase64(data: ArrayBuffer | Uint8Array): string {
  return helper.encodeToStringSync(data instanceof Uint8Array ? data : new Uint8Array(data));
}

// The text shortened to a line for the main page.
export function shortLine(text: string, max: number): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.substring(0, max - 1)}…` : t;
}
