// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the phone and its HarmonyOS watch say to each other through Wear
// Engine's messages (docs/apps.md, "HarmonyOS watches"), as WatchState does
// for the Wear OS watch: the phone tells the group as it sees it, never the
// clipboard; the watch asks for it and turns the phone's sync and sync away
// from home on or off. A watch the root made an admin also signs, with its
// own key, the emergency actions its wearer picks: the phone shows it each
// record or command whole, in parts, and the watch checks it before it
// signs. The same file is in the phone's module and the watch's; check.sh
// keeps the two the same.

import { util } from '@kit.ArkTS';

// The app's bundle name, the same on the phone and the watch, and the
// fingerprint of the certificate both are signed with, which Wear Engine
// checks: set once the app has its signing certificate from AppGallery
// Connect.
export const BUNDLE: string = 'tools.cbb.harmony';
export const FINGERPRINT: string = '';

// The most a message carries: Wear Engine's short messages are about 1 KB.
export const MAX_MESSAGE: number = 1000;

export interface WatchDevice {
  id: string;
  name: string;
  // phone, watch, computer or board.
  form: string;
  online: boolean;
  // The phone's collection it is in, '' for none.
  collection: string;
  // The watch's own phone.
  phone: boolean;
  // What the watch, an admin, may do to it from the wrist: freeze,
  // remove, paste-off, actions-off, away-off.
  actions: string[];
}

// The phone's state: type is state.
export interface WatchState {
  type: string;
  group: boolean;
  devices: WatchDevice[];
  // How many devices did not fit in the message.
  more: number;
  online: number;
  total: number;
  // Whether the phone's sync is on (the house).
  sync: boolean;
  // Sync away from home: off, home, connecting, connected or waiting.
  away: string;
  // The latest events, newest first.
  events: string[];
  // The watch is an admin of the group.
  admin: boolean;
}

// The watch's ask: hello (send the state), sync or away with on; key, the
// admin key the phone asked for (its SubjectPublicKeyInfo, base64, empty
// when the wearer said no); act, an emergency action for device; signed,
// the signature of what the phone showed (DER, base64, empty when the
// wearer said no).
export interface WatchAsk {
  type: string;
  on: boolean;
  key?: string;
  action?: string;
  device?: string;
  sig?: string;
}

// The phone's note to the watch: make_key (the root asks for an admin
// key); admitted (the watch is an admin: its device ID, the group's tag
// and its admin key's hash as the records name it); sign, one part of a
// record or command to sign (data base64, part of parts); done, how an
// action ended (ok, and message, the reason when it did not).
export interface WatchNote {
  type: string;
  device?: string;
  group?: string;
  signer?: string;
  part?: number;
  parts?: number;
  data?: string;
  ok?: boolean;
  message?: string;
}

// The bytes of a record or command in one sign note, before base64.
export const PART_BYTES: number = 600;

export function encode(o: WatchState | WatchAsk | WatchNote): Uint8Array {
  return new util.TextEncoder().encodeInto(JSON.stringify(o));
}

export function decodeState(data: Uint8Array): WatchState | undefined {
  try {
    const s = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(data)) as WatchState;
    return s.type === 'state' && Array.isArray(s.devices) ? s : undefined;
  } catch (e) {
    return undefined;
  }
}

export function decodeAsk(data: Uint8Array): WatchAsk | undefined {
  try {
    const a = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(data)) as WatchAsk;
    return ['hello', 'sync', 'away', 'key', 'act', 'signed'].includes(a.type) ? a : undefined;
  } catch (e) {
    return undefined;
  }
}

export function decodeNote(data: Uint8Array): WatchNote | undefined {
  try {
    const n = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(data)) as WatchNote;
    return ['make_key', 'admitted', 'sign', 'done'].includes(n.type) ? n : undefined;
  } catch (e) {
    return undefined;
  }
}

// A record or command in sign notes, each small enough for one message.
export function signNotes(body: Uint8Array): WatchNote[] {
  const b64 = new util.Base64Helper();
  const parts = Math.max(1, Math.ceil(body.length / PART_BYTES));
  const out: WatchNote[] = [];
  for (let i = 0; i < parts; i++) {
    const data = b64.encodeToStringSync(body.subarray(i * PART_BYTES, (i + 1) * PART_BYTES));
    out.push({ type: 'sign', part: i, parts: parts, data: data });
  }
  return out;
}

// The state as one message: the events go first, then the devices from the
// end, until it fits; more counts the devices left out.
export function fit(s: WatchState): Uint8Array {
  let out = encode(s);
  const events = s.events.slice();
  const devices = s.devices.slice();
  while (out.length > MAX_MESSAGE && (events.length > 0 || devices.length > 0)) {
    if (events.length > 0) {
      events.pop();
    } else {
      devices.pop();
    }
    const t: WatchState = {
      type: s.type, group: s.group, devices: devices, more: s.devices.length - devices.length, online: s.online,
      total: s.total, sync: s.sync, away: s.away, events: events, admin: s.admin
    };
    out = encode(t);
  }
  return out;
}
