// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's side of the link to its phone (docs/apps.md, "HarmonyOS
// watches"), as the Wear OS app's: it asks the phone for the group's state
// and shows what the phone tells, keeps the last state when the phone is
// out of reach, and asks the phone to turn its sync or sync away from home
// on or off. As an admin of the group, it makes its key when the root asks
// and its wearer agrees, and signs the emergency action its wearer picked:
// only a record or command that is that action, for that device, from this
// watch in this group.

import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { util } from '@kit.ArkTS';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { decodeNote, decodeState, encode, WatchAsk, WatchNote, WatchState } from '../common/WatchState';
import { Wear } from '../common/Wear';
import { makeKey, sign } from './AdminKey';

const LOOK_MS: number = 10000;
const KEPT: string = 'watch_state';
const ADMITTED: string = 'watch_admitted';
// How long the watch waits for the phone to end an action.
const ACT_MS: number = 60000;

// What the phone told the watch when it became an admin.
interface Admitted {
  device: string;
  group: string;
  signer: string;
}

// The parts of a record or command the watch reads before it signs.
interface Shown {
  type?: string;
  group?: string;
  signer?: string;
  by?: string;
  to?: string;
}

// The type of the record or command each emergency action signs.
function typeOf(action: string): string {
  return action === 'remove' ? 'revoke' : action;
}

@ObservedV2
export class Link {
  // The phone's last state; undefined before the first.
  @Trace state: WatchState | undefined = undefined;
  // Whether the phone is in reach with CBB on it.
  @Trace reachable: boolean = false;
  // Whether the state came from the phone since the page opened.
  @Trace fresh: boolean = false;
  // A switch waits for the phone's new state.
  @Trace asking: boolean = false;
  // The last ask the phone did not take, for the page.
  @Trace failed: boolean = false;
  // The root asks the watch to make its admin key.
  @Trace makeKeyAsked: boolean = false;
  // An emergency action waits for the phone: its device's ID.
  @Trace acting: string = '';
  // How the last action ended, for the page; '' when none.
  @Trace result: string = '';

  private wear: Wear = new Wear();
  private prefs: preferences.Preferences | undefined = undefined;
  private context: common.Context | undefined = undefined;
  private looking: number = -1;
  private admitted: Admitted | undefined = undefined;
  private action: string = '';
  private parts: string[] = [];
  private actTimer: number = -1;

  init(prefs: preferences.Preferences): void {
    this.prefs = prefs;
    const kept = prefs.getSync(KEPT, '') as string;
    if (kept.length > 0) {
      try {
        this.state = JSON.parse(kept) as WatchState;
      } catch (e) {
        this.state = undefined;
      }
    }
    const admitted = prefs.getSync(ADMITTED, '') as string;
    if (admitted.length > 0) {
      try {
        this.admitted = JSON.parse(admitted) as Admitted;
      } catch (e) {
        this.admitted = undefined;
      }
    }
  }

  start(context: common.Context): void {
    this.context = context;
    this.fresh = false;
    this.look();
    this.looking = setInterval(() => this.look(), LOOK_MS);
  }

  stop(): void {
    clearInterval(this.looking);
    this.looking = -1;
    this.wear.close();
    this.reachable = false;
  }

  private async look(): Promise<void> {
    if (this.context === undefined) {
      return;
    }
    const was = this.reachable;
    this.reachable = await this.wear.connect(this.context, false, (data: Uint8Array) => this.got(data));
    if (this.reachable && (!was || !this.fresh)) {
      this.wear.send(encode({ type: 'hello', on: true }));
    }
  }

  private got(data: Uint8Array): void {
    const s = decodeState(data);
    if (s !== undefined) {
      this.state = s;
      this.fresh = true;
      this.asking = false;
      this.prefs?.putSync(KEPT, JSON.stringify(s));
      this.prefs?.flush();
      return;
    }
    const n = decodeNote(data);
    if (n !== undefined) {
      this.noted(n);
    }
  }

  private noted(n: WatchNote): void {
    if (n.type === 'make_key') {
      this.makeKeyAsked = true;
    } else if (n.type === 'admitted') {
      const a: Admitted = { device: n.device ?? '', group: n.group ?? '', signer: n.signer ?? '' };
      if (a.device.length > 0 && a.group.length > 0 && a.signer.length > 0) {
        this.admitted = a;
        this.prefs?.putSync(ADMITTED, JSON.stringify(a));
        this.prefs?.flush();
        Errors.log(`watch: an admin of the group as ${a.device}`);
      }
    } else if (n.type === 'sign') {
      this.part(n);
    } else if (n.type === 'done') {
      this.ended(n.ok === true ? t('done') : `${t('not_done_because')} ${n.message ?? ''}`.trim());
    }
  }

  // The wearer's answer to the root's ask for the admin key.
  async answerMakeKey(yes: boolean): Promise<void> {
    this.makeKeyAsked = false;
    let key = '';
    if (yes) {
      try {
        key = await makeKey();
      } catch (e) {
        Errors.log(`watch: no admin key: ${Errors.unexpected('', e as Object).details}`);
      }
    }
    const a: WatchAsk = { type: 'key', on: key.length > 0, key: key };
    await this.wear.send(encode(a));
  }

  // Asks the phone to turn its sync (sync) or sync away from home (away)
  // on or off; the new state comes back as the phone's next message.
  async ask(type: string, on: boolean): Promise<void> {
    this.failed = false;
    this.asking = true;
    if (!(await this.wear.send(encode({ type: type, on: on })))) {
      this.asking = false;
      this.failed = true;
    }
  }

  // Asks the phone to do an emergency action the wearer confirmed; the
  // phone shows the watch what to sign next.
  async act(action: string, device: string): Promise<void> {
    if (this.admitted === undefined || this.acting.length > 0) {
      return;
    }
    this.result = '';
    this.action = action;
    this.acting = device;
    this.parts = [];
    const a: WatchAsk = { type: 'act', on: true, action: action, device: device };
    if (!(await this.wear.send(encode(a)))) {
      this.ended(t('no_answer'));
      return;
    }
    this.actTimer = setTimeout(() => this.ended(t('no_answer')), ACT_MS);
  }

  private ended(result: string): void {
    clearTimeout(this.actTimer);
    this.actTimer = -1;
    this.acting = '';
    this.action = '';
    this.parts = [];
    this.result = result;
  }

  // One part of a record or command to sign; with the last, it checks the
  // whole and signs it, or answers no signature.
  private async part(n: WatchNote): Promise<void> {
    const i = n.part ?? 0;
    const count = n.parts ?? 1;
    if (i === 0) {
      this.parts = [];
    }
    this.parts.push(n.data ?? '');
    if (this.parts.length < count) {
      return;
    }
    const b64 = new util.Base64Helper();
    const chunks = this.parts.map((p: string) => b64.decodeSync(p));
    this.parts = [];
    let size = 0;
    for (const c of chunks) {
      size += c.length;
    }
    const body = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      body.set(c, at);
      at += c.length;
    }
    let sig = '';
    const why = this.check(body);
    if (why.length > 0) {
      Errors.log(`watch: not signed: ${why}`);
    } else {
      try {
        sig = await sign(body);
      } catch (e) {
        Errors.log(`watch: not signed: ${Errors.unexpected('', e as Object).details}`);
      }
    }
    const a: WatchAsk = { type: 'signed', on: sig.length > 0, sig: sig };
    await this.wear.send(encode(a));
  }

  // Why the watch does not sign body: it must be the action the wearer
  // confirmed, in the watch's group, by this watch, and for the device
  // the wearer picked when it is a command; '' when it signs.
  private check(body: Uint8Array): string {
    const a = this.admitted;
    if (a === undefined || this.action.length === 0) {
      return 'no action waits';
    }
    let s: Shown;
    try {
      s = JSON.parse(util.TextDecoder.create('utf-8').decodeToString(body)) as Shown;
    } catch (e) {
      return 'it does not read';
    }
    if (s.group !== a.group) {
      return 'another group';
    }
    if (s.type !== typeOf(this.action)) {
      return `a ${s.type ?? '?'}, not a ${typeOf(this.action)}`;
    }
    if (s.by !== undefined) {
      return s.by === a.device && s.to === this.acting ? '' : 'another device';
    }
    return s.signer === a.signer ? '' : 'another signer';
  }
}

export const link: Link = new Link();
