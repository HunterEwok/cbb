// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// This phone as a remote paste target (docs/design.md, "Remote paste"), as
// the Aurora app's PasteReceiver: a paste command an admin signed is typed
// on the device the phone's Bluetooth keyboard is connected to, once this
// phone's user turned remote paste on. HarmonyOS lets no app put keys into
// another app, so the keyboard is the one way in. It keeps the switches,
// the limits per sender and the log of the last pastes (never their text).

import { preferences } from '@kit.ArkData';
import { util } from '@kit.ArkTS';
import { Errors } from '../core/Errors';
import { Keyboard, RemoteTyping } from './Keyboard';

export const LOG_SIZE: number = 100;
export const EVERY_MS: number = 1000;
export const BURST: number = 30;

// One paste in the log: who sent it, when, how long it was and how it
// ended, never its text.
export interface PasteEntry {
  time_ms: number;
  by: string;
  name?: string;
  bytes: number;
  enter: boolean;
  status: string; // done, refused or failed
  reason?: string;
  unverified?: boolean;
}

// The paste command as check_command opens it.
export interface PasteBody {
  type: string;
  by?: string;
  text?: string;
  enter?: boolean;
  kind?: string;
}

export interface CheckedPaste {
  command: PasteBody;
  verified?: boolean;
  sender?: string;
  // The text as it may go in (the computers' cleaning).
  clean?: string;
}

// What the receiver answers the command: status done, refused or failed.
export class PasteAnswer {
  status: string = 'refused';
  reason: string = '';
}

// Counts each sender's pastes: at most one a second and BURST a minute.
export class Limiter {
  private sent: Map<string, number[]> = new Map<string, number[]>();

  // Whether sender may paste at nowMs; it counts the paste if so.
  allow(sender: string, nowMs: number): boolean {
    const gone: string[] = [];
    this.sent.forEach((ts: number[], who: string) => {
      while (ts.length > 0 && nowMs - ts[0] >= 60000) {
        ts.shift();
      }
      if (ts.length === 0) {
        gone.push(who);
      }
    });
    gone.forEach((who: string) => this.sent.delete(who));
    const ts = this.sent.get(sender) ?? [];
    if (ts.length >= BURST || (ts.length > 0 && nowMs - ts[ts.length - 1] < EVERY_MS)) {
      return false;
    }
    ts.push(nowMs);
    this.sent.set(sender, ts);
    return true;
  }
}

// The log with e added, the last LOG_SIZE kept.
export function appended(log: PasteEntry[], e: PasteEntry): PasteEntry[] {
  const out = log.concat([e]);
  return out.slice(Math.max(0, out.length - LOG_SIZE));
}

@ObservedV2
export class Paste {
  // The switches only the phone's own user turns on: on lets the group's
  // admins paste, enter lets a paste press Enter (and hold line breaks).
  @Trace on: boolean = false;
  @Trace enter: boolean = false;
  // The last pastes, oldest first.
  @Trace log: PasteEntry[] = [];
  // A paste went in, for a notification: the sender's name.
  pasted: (name: string) => void = () => {};

  private prefs: preferences.Preferences | undefined = undefined;
  private keyboard: Keyboard | undefined = undefined;
  private limiter: Limiter = new Limiter();

  init(prefs: preferences.Preferences, keyboard: Keyboard): void {
    this.prefs = prefs;
    this.keyboard = keyboard;
    this.on = prefs.getSync('paste_on', false) as boolean;
    this.enter = this.on && prefs.getSync('paste_enter', false) as boolean;
    try {
      this.log = JSON.parse(prefs.getSync('paste_log', '[]') as string) as PasteEntry[];
    } catch (e) {
      this.log = [];
    }
  }

  setOn(on: boolean): void {
    this.on = on;
    this.prefs?.putSync('paste_on', on);
    // Enter goes off with the switch, so that turning it on again asks anew.
    if (!on) {
      this.setEnter(false);
    }
    this.prefs?.flush();
  }

  setEnter(on: boolean): void {
    this.enter = this.on && on;
    this.prefs?.putSync('paste_enter', this.enter);
    this.prefs?.flush();
  }

  // Deletes the log, which names the group's devices, as when the phone
  // leaves its group.
  forgetLog(): void {
    this.log = [];
    this.prefs?.delete('paste_log');
    this.prefs?.flush();
  }

  // Carries out a paste or paste-off command; name is the sender's when
  // the records show it signed.
  carryOut(c: CheckedPaste, name: string): PasteAnswer {
    const body = c.command;
    const by = body.by ?? '';
    const answer = new PasteAnswer();
    if (body.type === 'paste-off') {
      Errors.log(`paste: ${by} turned remote paste off`);
      this.setOn(false);
      answer.status = 'done';
      return answer;
    }
    const verified = c.verified === true;
    const text = c.clean ?? '';
    const raw = body.text ?? '';
    const withEnter = body.enter === true;
    let typing: RemoteTyping | undefined = undefined;
    if (!this.on) {
      answer.reason = 'remote paste is off on this device; its user turns it on in the app\'s settings';
    } else if (body.kind === 'media') {
      answer.reason = 'this phone types remote pastes on its Bluetooth keyboard, which types text only';
    } else if (withEnter && !this.enter) {
      answer.reason = 'this device takes pastes without Enter only; its user allows Enter in the app\'s settings';
    } else if (!this.limiter.allow(c.sender ?? by, Date.now())) {
      answer.reason = 'too many pastes: at most one a second and 30 a minute from one device';
    } else if (text.length === 0) {
      answer.reason = 'the text has nothing that may be pasted: only control characters';
    } else if (text.includes('\n') && !this.enter) {
      // Keys go straight in, so a line break presses Enter.
      answer.reason = 'the text has a line break, which the Bluetooth keyboard types as Enter; this device\'s ' +
        'user allows Enter in the app\'s settings';
    } else if (this.keyboard === undefined) {
      answer.status = 'failed';
      answer.reason = 'this phone has no keyboard';
    } else {
      typing = this.keyboard.typeRemote(withEnter ? `${text}\n` : text);
      answer.reason = typing.reason;
      if (typing.reason.length === 0) {
        answer.status = 'done';
      } else if (!typing.refused) {
        answer.status = 'failed';
      }
    }
    const who = verified ? by : `${by} (unverified)`;
    if (answer.status === 'done') {
      Errors.log(`paste: ${who} pasted ${raw.length} characters here`);
      this.pasted(name.length > 0 ? name : by);
    } else {
      Errors.log(`paste: a paste from ${who}: ${answer.status}: ${answer.reason}`);
    }
    // A secret leaves no trace.
    if (body.kind !== 'secret') {
      const e: PasteEntry = {
        time_ms: Date.now(),
        by: by,
        bytes: new util.TextEncoder().encodeInto(raw).length,
        enter: withEnter,
        status: answer.status
      };
      if (name.length > 0) {
        e.name = name;
      }
      if (answer.reason.length > 0) {
        e.reason = answer.reason;
      }
      if (!verified) {
        e.unverified = true;
      }
      this.keep(e);
    }
    return answer;
  }

  private keep(e: PasteEntry): void {
    this.log = appended(this.log, e);
    this.prefs?.putSync('paste_log', JSON.stringify(this.log));
    this.prefs?.flush();
  }
}
