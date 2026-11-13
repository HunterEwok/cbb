// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's side of its HarmonyOS watch (docs/apps.md, "HarmonyOS
// watches"), as Android's WatchLink: while a watch with CBB is connected,
// it tells the watch the group as the phone sees it whenever that changes,
// and turns the phone's sync or sync away from home on or off when the
// watch asks, as Home's switches do. The root makes the watch an admin with
// a key the watch makes and keeps; the watch's wearer then picks emergency
// actions, which the phone has the core sign on the watch: each record or
// command goes to the watch whole, and the watch checks it before it signs.

import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import cbb from 'libcbb_napi.so';
import { fromBase64, toBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { form } from '../common/Devices';
import {
  decodeAsk, encode, fit, signNotes, WatchAsk, WatchDevice, WatchNote, WatchState
} from '../common/WatchState';
import { Wear } from '../common/Wear';
import { app, CommandResult } from './AppModel';
import { Device } from './Member';

// How often the phone looks for its watch, and for a change to tell it.
const LOOK_MS: number = 30000;
const CHANGE_MS: number = 2000;
// How long the watch's wearer has to make its key or confirm a signature.
const WEARER_MS: number = 120000;
const KEPT: string = 'watch_admin';

// The watch as an admin, as the phone keeps it: its device ID, its admin
// CA and key point (base64), the group's tag and its key's hash.
interface WatchAdmin {
  device: string;
  admin_ca: string;
  public: string;
  group: string;
  signer: string;
}

interface WatchAnswer {
  result?: CommandResult;
}

// The state the watch shows, from the app: the devices in the phone's
// order, each collection's after one another, this phone first; actions
// what the watch, an admin, may do to each.
export function stateOf(actions: Map<string, string[]>, admin: boolean): WatchState {
  const devices: WatchDevice[] = [];
  let online = 0;
  for (const tile of app.arranged(app.member.devices)) {
    const ds: Device[] = tile.device !== undefined ? [tile.device] : tile.devices;
    for (const d of ds) {
      if (d.online === true || d.self === true) {
        online++;
      }
      devices.push({
        id: d.id, name: d.name, form: form(d), online: d.online === true || d.self === true,
        collection: tile.device !== undefined ? '' : tile.name, phone: d.self === true,
        actions: actions.get(d.id) ?? []
      });
    }
  }
  return {
    type: 'state',
    group: app.membership !== undefined,
    devices: devices,
    more: 0,
    online: online,
    total: devices.length,
    sync: !app.member.paused,
    away: app.member.awayOn ? app.member.awayStatus : 'off',
    events: app.events.recent.slice(0, 5),
    admin: admin
  };
}

// The point of a P-256 key in a SubjectPublicKeyInfo: its last 65 bytes.
function pointOf(spki: string): string {
  const b = new Uint8Array(fromBase64(spki));
  if (b.length < 65 || b[b.length - 65] !== 4) {
    return '';
  }
  return toBase64(b.subarray(b.length - 65));
}

@ObservedV2
export class Watch {
  // A watch with CBB is connected.
  @Trace linked: boolean = false;
  // The watch is an admin of the group.
  @Trace admin: boolean = false;
  // The root waits for the watch to make its key.
  @Trace making: boolean = false;
  // The watch was just made an admin, for Settings.
  @Trace made: boolean = false;

  private wear: Wear = new Wear();
  private context: common.Context | undefined = undefined;
  private prefs: preferences.Preferences | undefined = undefined;
  private kept: WatchAdmin | undefined = undefined;
  private looking: number = -1;
  private watching: number = -1;
  private told: string = '';
  private actions: Map<string, string[]> = new Map<string, string[]>();
  // The answer the phone waits for from the watch: its key or a signature.
  private waiting: ((a: WatchAsk | undefined) => void) | undefined = undefined;
  private waitingFor: string = '';

  start(context: common.Context): void {
    this.context = context;
    this.prefs = preferences.getPreferencesSync(context, { name: 'settings' });
    const kept = this.prefs.getSync(KEPT, '') as string;
    if (kept.length > 0) {
      try {
        this.kept = JSON.parse(kept) as WatchAdmin;
      } catch (e) {
        this.kept = undefined;
      }
    }
    // The core asks the watch to sign through here (cbb_member_manage_watch).
    cbb.setWatch((body: ArrayBuffer): Promise<ArrayBuffer> => this.signOnWatch(new Uint8Array(body)));
    this.look();
    this.looking = setInterval(() => this.look(), LOOK_MS);
  }

  stop(): void {
    clearInterval(this.looking);
    clearInterval(this.watching);
    this.looking = -1;
    this.watching = -1;
    this.answer(undefined);
    this.wear.close();
  }

  // The watch is still an admin of the group: the records list it as one.
  private stillAdmin(): boolean {
    const k = this.kept;
    if (k === undefined || app.membership === undefined) {
      return false;
    }
    return app.member.devices.some((d: Device) => d.id === k.device && d.admin === true);
  }

  private async look(): Promise<void> {
    if (this.context === undefined) {
      return;
    }
    const linked = await this.wear.connect(this.context, true, (data: Uint8Array) => this.asked(data));
    this.linked = linked;
    if (linked && this.watching === -1) {
      this.told = '';
      this.tell();
      this.watching = setInterval(() => this.tell(), CHANGE_MS);
    } else if (!linked && this.watching !== -1) {
      clearInterval(this.watching);
      this.watching = -1;
    }
  }

  // Sends the state when it changed since the watch got it last.
  private async tell(): Promise<void> {
    this.admin = this.stillAdmin();
    if (this.admin) {
      const next = new Map<string, string[]>();
      for (const d of app.member.devices) {
        next.set(d.id, await app.member.watchActions(d.id));
      }
      this.actions = next;
    } else {
      this.actions = new Map<string, string[]>();
    }
    const data = fit(stateOf(this.actions, this.admin));
    const text = data.join(',');
    if (text === this.told) {
      return;
    }
    if (await this.wear.send(data)) {
      this.told = text;
    }
  }

  private asked(data: Uint8Array): void {
    const a: WatchAsk | undefined = decodeAsk(data);
    if (a === undefined) {
      Errors.log('watch: a message that does not read');
      return;
    }
    Errors.log(`watch: asked ${a.type}`);
    if (a.type === 'hello') {
      this.told = '';
      this.tell();
      if (this.admin && this.kept !== undefined) {
        this.admitted(this.kept);
      }
    } else if (a.type === 'sync') {
      if (a.on) {
        app.member.resume();
      } else {
        app.member.pause(0);
      }
    } else if (a.type === 'away') {
      app.member.setAway(a.on);
    } else if (a.type === 'key' || a.type === 'signed') {
      if (this.waitingFor === a.type) {
        this.answer(a);
      }
    } else if (a.type === 'act') {
      this.act(a.action ?? '', a.device ?? '');
    }
  }

  private answer(a: WatchAsk | undefined): void {
    const w = this.waiting;
    this.waiting = undefined;
    this.waitingFor = '';
    if (w !== undefined) {
      w(a);
    }
  }

  // Waits for the watch's answer of the type, at most WEARER_MS.
  private wait(type: string): Promise<WatchAsk | undefined> {
    this.answer(undefined);
    return new Promise<WatchAsk | undefined>((resolve) => {
      this.waitingFor = type;
      this.waiting = resolve;
      setTimeout(() => {
        if (this.waiting === resolve) {
          this.answer(undefined);
        }
      }, WEARER_MS);
    });
  }

  private async note(n: WatchNote): Promise<boolean> {
    return this.wear.send(encode(n));
  }

  private async admitted(k: WatchAdmin): Promise<void> {
    await this.note({ type: 'admitted', device: k.device, group: k.group, signer: k.signer });
  }

  // The root makes the connected watch an admin: the watch makes a key
  // once its wearer agrees, the root key certifies it, and the watch is
  // told its device ID, the group's tag and its key's hash.
  async makeAdmin(): Promise<void> {
    if (!app.isRoot() || this.making) {
      return;
    }
    app.show('');
    this.made = false;
    if (this.stillAdmin()) {
      app.show(t('watch_replace'));
      return;
    }
    this.making = true;
    const answer = this.wait('key');
    if (!this.linked || !(await this.note({ type: 'make_key' }))) {
      this.answer(undefined);
      this.making = false;
      app.show(Errors.shown(new Failure(t('watch_not_reachable'), 'watch: make_key: the watch is not reachable')));
      return;
    }
    const a = await answer;
    const key = a?.key ?? '';
    if (key.length === 0) {
      this.making = false;
      app.show(Errors.shown(new Failure(a === undefined ? t('watch_not_reachable') : t('watch_not_protected'),
        a === undefined ? 'watch: no key in time' : 'watch: the watch made no key')));
      return;
    }
    const made = await app.addWatch(key, t('device_kind_watch'));
    this.making = false;
    if (made === undefined) {
      return; // runManage showed why
    }
    const k: WatchAdmin = {
      device: made.device ?? '', admin_ca: made.admin_ca ?? '', public: pointOf(key), group: made.group ?? '',
      signer: made.signer ?? ''
    };
    this.kept = k;
    this.prefs?.putSync(KEPT, JSON.stringify(k));
    this.prefs?.flush();
    await this.admitted(k);
    this.made = true;
    this.told = '';
    this.tell();
    Errors.log(`watch: made an admin, ${k.device}`);
  }

  // Shows the watch a record or command in parts and waits for its
  // signature; it rejects when the watch said no or did not answer.
  private async signOnWatch(body: Uint8Array): Promise<ArrayBuffer> {
    const answer = this.wait('signed');
    for (const n of signNotes(body)) {
      if (!(await this.note(n))) {
        this.answer(undefined);
        throw new Error('the watch is not reachable');
      }
    }
    const a = await answer;
    const sig = a?.sig ?? '';
    if (sig.length === 0) {
      throw new Error(a === undefined ? 'the watch did not answer' : 'the wearer did not sign');
    }
    return fromBase64(sig);
  }

  // An emergency action the watch's wearer picked, signed on the watch.
  private async act(action: string, device: string): Promise<void> {
    const k = this.kept;
    if (k === undefined || !this.stillAdmin()) {
      await this.note({ type: 'done', ok: false, message: 'the watch is no admin of the group' });
      return;
    }
    const request: Record<string, Object> = {
      'action': action.replace(new RegExp('-', 'g'), '_'), 'device': device, 'watch': k.device, 'public': k.public, 'admin_ca': k.admin_ca
    };
    const r = await app.member.manageWatch<WatchAnswer>(request);
    let failure = r.failure;
    const result = r.ok?.result;
    if (failure === undefined && result !== undefined && result.status !== 'done') {
      failure = new Failure(t('error_command_refused'), `watch: ${result.status ?? ''}: ${result.reason ?? ''}`);
    }
    if (failure !== undefined) {
      Errors.log(`watch: ${action} ${device}: ${failure.message} (${failure.details})`);
      await this.note({ type: 'done', ok: false, message: failure.message });
      return;
    }
    Errors.log(`watch: ${action} ${device}`);
    await this.note({ type: 'done', ok: true });
    this.told = '';
    this.tell();
  }
}

export const watch: Watch = new Watch();
