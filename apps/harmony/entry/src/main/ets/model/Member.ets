// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a member of its group: the Rust member's node in the app's
// process (ffi's cbb_member_*, docs/core-api.md), with the member key in
// HUKS. It dials the members it finds, puts what they send into the
// pasteboard, and sends what the user copied when the user taps the paste
// button: HarmonyOS lets an app read the pasteboard only then, without the
// restricted READ_PASTEBOARD permission. The Aurora app's Member, ported.

import cbb, { Handle } from 'libcbb_napi.so';
import { pasteboard } from '@kit.BasicServicesKit';
import { http } from '@kit.NetworkKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { fileIo } from '@kit.CoreFileKit';
import { image } from '@kit.ImageKit';
import { read, Result } from '../core/Core';
import { shortLine, toBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { Membership } from '../core/Membership';
import { OS, osVersion } from '../core/Phone';
import { t } from '../core/Text';
import { ensure } from '../core/Keys';

// The most bytes the phone fetches of a copy, or sends of shared files.
const MAX_FETCH_BYTES: number = 200 * 1024 * 1024;
export const MAX_SEND_BYTES: number = 50 * 1024 * 1024;
// How often the devices, the mute and sync away from home are brought up to date.
const POLL_MS: number = 3000;
export const IMAGE_TYPES: string[] = ['image/png', 'image/jpeg', 'image/gif'];
// How long a secret the button took stays in the pasteboard (docs/design.md, "Secrets").
const SECRET_TTL_MS: number = 60000;

// A device of the group, as the member's devices op lists it.
export interface Device {
  id: string;
  name: string;
  role?: string;
  os?: string;
  admin?: boolean;
  root?: boolean;
  frozen?: boolean;
  online?: boolean;
  self?: boolean;
  listed?: boolean;
  caps?: string[];
  // "shared" or "own" for a device whose sync an admin turns, else "".
  mode?: string;
  version?: string;
  os_version?: string;
  mac?: string;
}

// What the group's records stop and what ends it (the member's alerts).
// The root's settings as the records hold them (the member's root_view).
interface Peer {
  device: string;
  name?: string;
}

interface Peers {
  peers?: Peer[];
}

interface Devices {
  devices?: Device[];
}

// Why the phone does not sync (cbb_core::why, docs/apps.md "Why it does not
// sync"), the reason that stops the most first.
export interface Why {
  code: string;
  level?: string; // stop, warn or info
  until_ms?: number;
  device?: string;
  devices?: string[];
  value?: string;
  detail?: string;
}

// A device as the group view names it: whether it offered this phone an
// admin key when it paired and is no admin yet.
interface GroupDevice {
  device?: string;
  offers_admin?: boolean;
}

// The member's group of 0.6, the part the app reads: its key level and
// how long copies and secrets live (D-129), null for the default.
interface GroupView {
  key_level?: string;
  devices?: GroupDevice[];
  ttl_ms?: number | null;
  secret_ttl_ms?: number | null;
}

interface Whys {
  why?: Why[];
}

// A tile of the member's view (docs/apps.md, "What the member shows").
export interface ViewCollection {
  id: string;
  name: string;
  devices: Device[];
}

export interface ViewTile {
  device?: Device;
  collection?: ViewCollection;
}

// The device tiles as the member keeps them: in the user's order with this
// device among them, how many of the others are online, and whether the
// user changed the order.
export interface View {
  tiles: ViewTile[];
  online?: number;
  others?: number;
  custom?: boolean;
}

interface Viewed {
  view?: View;
}

interface Muted {
  sync_off?: boolean;
  sync_off_ms?: number;
  muted?: boolean;
  muted_ms?: number;
}

// What the paste button's swap or the app's opening does (D-128): whether
// the pasteboard goes to the group, and the group's copy that comes in.
interface Swap {
  sends?: boolean;
  copy?: Copy;
}

interface Server {
  endpoint?: string;
  registered?: boolean;
  connected?: boolean;
  online?: string[];
  error?: string;
  detail?: string;
}

interface Away {
  keys_in_file?: boolean;
  hub_device?: string;
  through?: boolean;
  error?: string;
  detail?: string;
  // This phone is one of the group's hubs, with its forwarder; or it meets
  // the group at a blind relay.
  hub?: boolean;
  forwarder?: Server;
  relay?: Server;
}

interface Attest {
  pending?: number;
  revoked?: number;
}

// The mirror of Google's revocation list of Android attestations, signed
// with the project's release keys (docs/protocol.md, section 17).
const ATTEST_MIRROR: string = 'https://cbb.tools/attest/';
const ATTEST_EVERY_MS: number = 24 * 3600 * 1000;
// A signed file of the mirror is far smaller.
const ATTEST_MAX: number = 2 * 1024 * 1024;

// The forwarder the group's root set for this phone as a hub (a group of 0.6).
interface RootForwarder {
  endpoint: string;
  key: string;
}

interface AwayAnswer {
  away?: Away;
  root_forwarder?: RootForwarder;
  // On the root phone of a group of 0.6: the group's server credentials
  // need its root key, or expired already.
  period_due?: boolean;
  period_overdue?: boolean;
}

interface Copy {
  id: string;
  origin?: string;
  kind?: string;
  text?: string;
  ttl_ms?: number;
}

// How long a copy and a secret live when the copy does not say (D-129).
const DEFAULT_TTL_MS = 300000;
const DEFAULT_SECRET_TTL_MS = 60000;

interface Part {
  type?: string;
  file?: string;
  path?: string;
  dir?: boolean;
}

interface CopyMade {
  copy?: Copy;
}

interface Fetched {
  parts?: Part[];
}

interface MemberEvent {
  type: string;
  line?: string;
  text?: string;
  kind?: string;
  ttl_ms?: number;
  copy?: Copy;
  details?: string;
}

interface Started {
  device?: string;
}

interface WatchActions {
  actions?: string[];
}

@ObservedV2
export class Member {
  @Trace running: boolean = false;
  // The names of the members connected now.
  @Trace peers: string[] = [];
  @Trace devices: Device[] = [];
  @Trace why: Why[] = [];
  // The group's key level (proven, hardware or files), as its records set it.
  @Trace keyLevel: string = 'hardware';
  // The devices that offered this phone an admin key at pairing and are no
  // admins yet: the root may make them admins.
  @Trace offersAdmin: string[] = [];
  // How long a copy and a secret live, in milliseconds (D-129).
  @Trace ttlMs: number = DEFAULT_TTL_MS;
  @Trace secretTtlMs: number = DEFAULT_SECRET_TTL_MS;
  // The tiles; viewed is false until the member gave them.
  @Trace view: View = { tiles: [] };
  @Trace viewed: boolean = false;
  // What the pasteboard got or sent last, shortened, for the main page.
  @Trace last: string = '';
  // The last copy that came from another device (D-128): its ID, the
  // device's name and its text, empty for a secret, for the main page's
  // line with Copy; lastId is empty when there is none to show.
  @Trace lastId: string = '';
  @Trace lastFrom: string = '';
  @Trace lastText: string = '';
  @Trace error: string = '';
  // Sync turned off (design.md, "Sync on and off"), until pausedUntil
  // (ms since the epoch) or, when 0, until the user turns it on.
  @Trace paused: boolean = false;
  @Trace pausedUntil: number = 0;
  // An admin muted the phone, until mutedUntil or, when 0, until unmuted.
  @Trace muted: boolean = false;
  @Trace mutedUntil: number = 0;
  // Images or files of the group's copy are coming to the phone.
  @Trace fetching: boolean = false;
  // The folder the last received files are in, for the main page's Save.
  @Trace received: string = '';
  // Sync away from home: on, where it stands ("off", "waiting", "home",
  // "connecting", "connected"), the hub's name and what went wrong last.
  @Trace awayOn: boolean = false;
  @Trace awayStatus: string = 'off';
  @Trace awayHub: string = '';
  @Trace awayError: string = '';
  // The phone as one of the group's hubs (docs/apps.md, "The phone as the
  // hub"): on, where its forwarder stands ("off", "home", "registering",
  // "registered", "failed") and why it failed.
  @Trace hubOn: boolean = false;
  @Trace hubStatus: string = 'off';
  @Trace hubError: string = '';
  // The blind relay the phone meets the group at, "" for none, and whether
  // the link is up.
  @Trace relayAt: string = '';
  // On a group of 0.6, the forwarder the group's root set for this phone as
  // a hub and its key's pin, "" while it set none.
  @Trace rootForwarder: string = '';
  @Trace rootForwarderKey: string = '';
  // On the root phone of a group of 0.6, the group's server credentials
  // expired: its relay and its hubs' forwarders take nobody until the root
  // key renews them.
  @Trace periodOverdue: boolean = false;
  private periodDueAway: boolean = false;
  @Trace relayConnected: boolean = false;
  @Trace relayOnline: number = 0;
  @Trace relayError: string = '';
  // The root's next period of the server credentials waits for the user.
  @Trace periodDue: boolean = false;

  // The images or files of a copy are in folder.
  onSaved: (folder: string, count: number) => void = () => {};
  // The devices changed, for the notifications.
  onDevices: (devices: Device[]) => void = () => {};
  // Something in the member broke (docs/core-api.md, "Panics"): details say
  // what and where. The app shows it and starts the member again.
  onPanic: (details: string) => void = () => {};

  // The member's recent log lines, oldest first, for a bug report.
  recentLog: string[] = [];

  private handle: Handle | null = null;
  // The member port is open (listen), for a pairing window of 0.6.
  private listening: boolean = false;
  private timer: number = -1;
  private dir: string = '';
  private tookImage: string = '';
  private awayFailure: string = '';
  // Bumped by every change of the pasteboard, so that a secret leaves it
  // only when nothing replaced it.
  private boardChanges: number = 0;
  private watching: boolean = false;
  private starting: boolean = false;
  // Whether the app is on the screen: only then does the phone write the
  // group's copies (D-128).
  private foreground: boolean = false;
  // boardChanges as the app last saw the pasteboard, -1 when it does not
  // know; and the key of what it held then.
  private seenChanges: number = -1;
  private seenKey: string = '';

  // The core's member, for adding a device and invitations; null when stopped.
  core(): Handle | null {
    return this.handle;
  }

  // Starts the member of m as the phone named name; a second call while it
  // starts does nothing.
  async start(m: Membership, dir: string, name: string): Promise<void> {
    if (this.handle !== null || this.starting) {
      return;
    }
    this.starting = true;
    try {
      await this.begin(m, dir, name);
    } finally {
      this.starting = false;
    }
  }

  private async begin(m: Membership, dir: string, name: string): Promise<void> {
    this.dir = dir;
    const key = await ensure('member');
    if (key.ok === undefined) {
      this.error = Errors.shown(key.failure as Failure);
      return;
    }
    const request: Record<string, Object> = {
      'dir': dir,
      'name': name,
      'os': OS,
      'os_version': osVersion(),
      'version': AppStorage.get<string>('version') ?? '',
      'device': m.member.device,
      'public': key.ok.public
    };
    const made = await cbb.memberStart(JSON.stringify(request), (e: string) => {
      this.event(e);
    });
    const answer = read<Started>(made.answer, 'member');
    if (made.handle === null) {
      this.error = Errors.shown(answer.failure ?? new Failure(t('error_broken'), 'member: no member'));
      return;
    }
    this.handle = made.handle;
    this.running = true;
    this.error = '';
    this.watchBoard();
    Errors.log(`member: started in the group ${m.groupTag()}`);
    this.timer = setInterval(() => {
      this.poll();
    }, POLL_MS);
    await this.pollMuted();
    await this.pollDevices();
  }

  async stop(): Promise<void> {
    const h = this.handle;
    if (h === null) {
      return;
    }
    this.handle = null;
    this.listening = false;
    clearInterval(this.timer);
    this.timer = -1;
    await cbb.memberStop(h);
    this.running = false;
    this.peers = [];
    this.devices = [];
    this.why = [];
    this.view = { tiles: [] };
    this.viewed = false;
    this.paused = false;
    this.muted = false;
    this.fetching = false;
    this.readAway(undefined);
    this.periodDue = false;
    Errors.log('member: stopped');
  }

  // Opens the member port at home, which a pairing window of 0.6 needs
  // (the member's listen op); a second call keeps it open.
  async listen(): Promise<Failure | undefined> {
    if (this.listening) {
      return undefined;
    }
    const r = await this.call<Object>('listen', { 'kind': 'home' } as Record<string, Object>);
    if (r.ok === undefined) {
      return r.failure;
    }
    this.listening = true;
    return undefined;
  }

  // Asks the member: {"op","args"}.
  async call<T>(op: string, args?: Object): Promise<Result<T>> {
    const h = this.handle;
    if (h === null) {
      return Result.failed<T>(new Failure(t('error_not_running'), `member: ${op}: not running`));
    }
    const request: Record<string, Object> = { 'op': op, 'args': args ?? ({} as Record<string, Object>) };
    return read<T>(await cbb.memberCall(h, JSON.stringify(request)), `member: ${op}`);
  }

  // An admin's change, signed with the admin key after the user's consent
  // (the member's manage, docs/core-api.md).
  async manage<T>(request: Record<string, Object>): Promise<Result<T>> {
    const h = this.handle;
    if (h === null) {
      return Result.failed<T>(new Failure(t('error_not_running'), 'member: manage: not running'));
    }
    const r = read<T>(await cbb.memberManage(h, JSON.stringify(request), 'admin'), `member: ${String(request['action'])}`);
    await this.pollDevices();
    return r;
  }

  // What the app's watch, an admin, may do to device from the wrist
  // (manage watch_actions, which signs nothing).
  async watchActions(device: string): Promise<string[]> {
    const h = this.handle;
    if (h === null) {
      return [];
    }
    const request: Record<string, Object> = { 'action': 'watch_actions', 'device': device, 'public': '' };
    const r = read<WatchActions>(await cbb.memberManage(h, JSON.stringify(request), 'admin'), 'member: watch_actions');
    return r.ok?.actions ?? [];
  }

  // What the watch asked from the wrist, signed on the watch through the
  // function setWatch gave the core (cbb_member_manage_watch).
  async manageWatch<T>(request: Record<string, Object>): Promise<Result<T>> {
    const h = this.handle;
    if (h === null) {
      return Result.failed<T>(new Failure(t('error_not_running'), 'member: watch: not running'));
    }
    const r = read<T>(await cbb.memberManageWatch(h, JSON.stringify(request)), `watch: ${String(request['action'])}`);
    await this.pollDevices();
    return r;
  }

  // The one button (docs/design.md, "The one button", D-128): reads the
  // pasteboard and swaps it with the group's copy. What it holds goes to the
  // group, unless it is the group's copy or what this phone sent or took
  // last, and the group's copy comes into the pasteboard; an empty
  // pasteboard only takes. Called from the paste button's tap, the one
  // moment HarmonyOS lets the app read it, and from a quick sync (quiet: a
  // pasteboard the app may not read is no error then). Answers whether it
  // sent.
  async sendPasteboard(quiet?: boolean): Promise<boolean> {
    if (this.handle === null || this.muted) {
      return false;
    }
    let data: pasteboard.PasteData;
    try {
      data = await pasteboard.getSystemPasteboard().getData();
    } catch (e) {
      const f = Errors.unexpected(t('error_pasteboard'), e as Object);
      if (quiet === true) {
        Errors.log(`member: the pasteboard: ${f.details}`);
      } else {
        this.error = Errors.shown(f);
      }
      return false;
    }
    let pixels: image.PixelMap | undefined = undefined;
    for (let i = 0; i < data.getRecordCount(); i++) {
      const record = data.getRecord(i);
      if (record.mimeType === pasteboard.MIMETYPE_PIXELMAP && record.pixelMap !== undefined) {
        pixels = record.pixelMap;
        break;
      }
    }
    let png: ArrayBuffer | undefined = undefined;
    let key = '';
    if (pixels !== undefined) {
      png = await this.packed(pixels);
      if (png === undefined) {
        return false;
      }
      key = Member.imageKey(png);
    } else {
      key = data.getPrimaryText() ?? '';
    }
    this.seen(this.boardChanges, key);
    const swap = await this.call<Swap>('swap', { 'board': key } as Record<string, Object>);
    if (swap.ok === undefined) {
      this.error = Errors.shown(swap.failure as Failure);
      return false;
    }
    let sent = false;
    if (swap.ok.sends === true) {
      sent = png !== undefined ? await this.sendImage(png) : await this.sendText(key);
    }
    if (swap.ok.copy !== undefined) {
      await this.takeCopy(swap.ok.copy);
    }
    return sent;
  }

  // Sends a text the pasteboard held to the group.
  private async sendText(text: string): Promise<boolean> {
    const sent = await this.call<Object>('copy', { 'text': text, 'board': true } as Record<string, Object>);
    if (sent.ok === undefined) {
      this.error = Errors.shown(sent.failure as Failure);
      return false;
    }
    this.error = '';
    this.setLast(text, false);
    return true;
  }

  // The app came to the screen (on) or left it. Coming to it is an opening
  // (D-128), which swaps nothing: the phone takes the group's copy when the
  // pasteboard is as the app last saw it. HarmonyOS lets the app read the
  // pasteboard only on the paste button's tap, so one changed since stays
  // as it is, for the button to send.
  setForeground(on: boolean): void {
    const opening = on && !this.foreground;
    this.foreground = on;
    if (opening) {
      this.opened();
    }
  }

  private async opened(): Promise<void> {
    if (this.handle === null || this.paused || !this.watching || this.seenChanges !== this.boardChanges) {
      return;
    }
    const a = await this.call<Swap>('opened', { 'board': this.seenKey, 'changed': false } as Record<string, Object>);
    if (a.ok === undefined) {
      Errors.log(`member: opening: ${(a.failure as Failure).details}`);
      return;
    }
    if (a.ok.copy !== undefined) {
      await this.takeCopy(a.ok.copy);
    }
  }

  // Puts a copy of the group into the pasteboard, as the button or the
  // opening took it: a text, or images and files fetched; then the core
  // knows the phone took it.
  private async takeCopy(copy: Copy): Promise<void> {
    if (copy.kind === 'media') {
      await this.take(copy);
      return;
    }
    if ((copy.text ?? '').length === 0) {
      return;
    }
    this.write(copy.text ?? '', copy.kind === 'secret', copy.kind === 'secret' ? (copy.ttl_ms ?? SECRET_TTL_MS) : 0);
    await this.call<Object>('took', { 'id': copy.id } as Record<string, Object>);
    this.dismissReceived();
  }

  // Notes the pasteboard as the app saw it: its change count and key.
  private seen(changes: number, key: string): void {
    this.seenChanges = changes;
    this.seenKey = key;
  }

  // A copy from another device, for the main page's last received line.
  private cameIn(copy: Copy): void {
    const me = this.devices.find((d: Device) => d.self === true);
    if (copy.origin === undefined || (me !== undefined && copy.origin === me.id)) {
      return;
    }
    const from = this.devices.find((d: Device) => d.id === copy.origin);
    this.lastId = copy.id;
    this.lastFrom = from !== undefined ? from.name : copy.origin;
    this.lastText = copy.kind === 'secret' || copy.kind === 'media' ? '' : copy.text ?? '';
    // The line goes when the copy's lifetime runs out (D-129).
    const id = copy.id;
    const ttl = copy.ttl_ms ?? (copy.kind === 'secret' ? DEFAULT_SECRET_TTL_MS : DEFAULT_TTL_MS);
    setTimeout(() => {
      if (this.lastId === id) {
        this.dismissReceived();
      }
    }, Math.min(ttl, 24 * 3600 * 1000));
  }

  // Copy on the last received line: the group's copy into the pasteboard,
  // if it is still the group's latest.
  async copyReceived(): Promise<void> {
    const id = this.lastId;
    this.dismissReceived();
    const a = await this.call<Swap>('opened', { 'board': '', 'changed': false } as Record<string, Object>);
    if (a.ok === undefined) {
      this.error = Errors.shown(a.failure as Failure);
      return;
    }
    if (a.ok.copy !== undefined && a.ok.copy.id === id) {
      await this.takeCopy(a.ok.copy);
    }
  }

  private dismissReceived(): void {
    this.lastId = '';
    this.lastFrom = '';
    this.lastText = '';
  }

  // Makes the group's copy of files (paths in the app's sandbox), up to
  // MAX_SEND_BYTES together; a lone image goes as clipboard data. It
  // answers the copy's ID, or the failure to show.
  private async copyFiles(files: string[], types: string[]): Promise<Result<string>> {
    const parts: Record<string, Object>[] = [];
    let total = 0;
    for (let i = 0; i < files.length; i++) {
      try {
        total += fileIo.statSync(files[i]).size;
      } catch (e) {
        continue;
      }
      const name = files[i].substring(files[i].lastIndexOf('/') + 1);
      if (files.length === 1 && IMAGE_TYPES.includes(types[i])) {
        parts.push({ 'type': types[i], 'file': files[i] } as Record<string, Object>);
      } else {
        parts.push({ 'path': name, 'file': files[i] } as Record<string, Object>);
      }
    }
    if (parts.length === 0) {
      return Result.failed<string>(new Failure(t('error_share_nothing'), 'share: no readable file'));
    }
    if (total > MAX_SEND_BYTES) {
      return Result.failed<string>(new Failure(t('error_share_too_large'), `share: ${total} bytes`));
    }
    const sent = await this.call<CopyMade>('copy_media', { 'parts': parts } as Record<string, Object>);
    if (sent.ok === undefined) {
      return Result.failed<string>(sent.failure as Failure);
    }
    return Result.of<string>(sent.ok.copy?.id ?? '');
  }

  // Sends to the group what was dropped beside a big screen's tiles, as the
  // Share menu would: files from the app's cache, or a text. Answers
  // whether it sent.
  async sendDropped(text: string, files: string[], types: string[]): Promise<boolean> {
    if (this.handle === null || this.muted) {
      return false;
    }
    if (files.length > 0) {
      const made = await this.copyFiles(files, types);
      if (made.ok === undefined) {
        this.error = Errors.shown(made.failure as Failure);
        return false;
      }
      Errors.log(`member: sent ${files.length} dropped files`);
      this.error = '';
      return true;
    }
    if (text.length === 0) {
      return false;
    }
    const sent = await this.call<Object>('copy', { 'text': text } as Record<string, Object>);
    if (sent.ok === undefined) {
      this.error = Errors.shown(sent.failure as Failure);
      return false;
    }
    Errors.log('member: sent a dropped text');
    this.error = '';
    this.setLast(text, false);
    return true;
  }

  // The group's copy of the files the user picked to paste on another
  // device, which the paste command names: its ID.
  async copyForPaste(files: string[], types: string[]): Promise<Result<string>> {
    if (this.handle === null) {
      return Result.failed<string>(new Failure(t('error_broken'), 'paste: no member'));
    }
    return this.copyFiles(files, types);
  }

  // Keeps the group's copies out of the pasteboard for minutes (0 for
  // until resume), or takes them again; the phone's own still go out.
  async pause(minutes: number): Promise<void> {
    const a = await this.call<Muted>('sync', { 'on': false, 'for_ms': minutes * 60000 } as Record<string, Object>);
    if (a.ok === undefined) {
      this.error = Errors.shown(a.failure as Failure);
      return;
    }
    Errors.log(minutes > 0 ? `member: sync is off for ${minutes} min` : 'member: sync is off until turned on');
    this.readMuted(a.ok);
  }

  async resume(): Promise<void> {
    const a = await this.call<Muted>('sync', { 'on': true } as Record<string, Object>);
    if (a.ok === undefined) {
      this.error = Errors.shown(a.failure as Failure);
      return;
    }
    Errors.log('member: sync is on');
    this.readMuted(a.ok);
  }

  // Turns sync away from home on, with new tunnel keys that the hellos offer
  // the group's hubs, or off, forgetting them.
  async setAway(on: boolean): Promise<void> {
    const a = await this.call<AwayAnswer>('away', { 'on': on } as Record<string, Object>);
    if (a.ok === undefined) {
      this.error = Errors.shown(a.failure as Failure);
      await this.pollAway();
      return;
    }
    Errors.log(on ? 'member: sync away from home is on' : 'member: sync away from home is off');
    this.readAway(a.ok.away);
  }

  async pollDevices(): Promise<void> {
    if (this.handle === null) {
      return;
    }
    const d = await this.call<Devices>('devices');
    if (d.ok === undefined) {
      const f = d.failure as Failure;
      Errors.log(`member: the devices: ${f.message} (${f.details})`);
      return;
    }
    const devices = d.ok.devices ?? [];
    const w = await this.call<Whys>('why');
    const why = w.ok !== undefined ? (w.ok.why ?? []) : this.why;
    const g = await this.call<GroupView>('group');
    const level = g.ok?.key_level;
    if (level !== undefined && level !== this.keyLevel) {
      this.keyLevel = level;
    }
    if (g.ok !== undefined) {
      const offers = (g.ok.devices ?? []).filter((d: GroupDevice) => d.offers_admin === true)
        .map((d: GroupDevice) => d.device ?? '');
      if (JSON.stringify(offers) !== JSON.stringify(this.offersAdmin)) {
        this.offersAdmin = offers;
      }
      const ttl = g.ok.ttl_ms ?? DEFAULT_TTL_MS;
      const secretTtl = g.ok.secret_ttl_ms ?? DEFAULT_SECRET_TTL_MS;
      if (ttl !== this.ttlMs) {
        this.ttlMs = ttl;
      }
      if (secretTtl !== this.secretTtlMs) {
        this.secretTtlMs = secretTtl;
      }
    }
    await this.readView(await this.call<Viewed>('view'));
    if (JSON.stringify(why) !== JSON.stringify(this.why)) {
      this.why = why;
    }
    if (JSON.stringify(devices) !== JSON.stringify(this.devices)) {
      this.devices = devices;
      this.onDevices(devices);
    }
  }

  // Sends the user's change of the tiles' order (docs/apps.md, "What the
  // member shows": move, into, out, new, rename, ungroup or reset), which
  // the member keeps; a change that does not fit is refused, in failure.
  async arrange(op: Object): Promise<Failure | undefined> {
    if (this.handle === null) {
      return new Failure('no member runs', 'member: arrange without a member');
    }
    const a = await this.call<Viewed>('arrange', { 'arrange': op } as Record<string, Object>);
    await this.readView(a);
    return a.failure;
  }

  private async readView(a: Result<Viewed>): Promise<void> {
    if (a.ok === undefined || a.ok.view === undefined) {
      if (a.failure !== undefined) {
        Errors.log(`member: the view: ${a.failure.message} (${a.failure.details})`);
      }
      return;
    }
    const v = a.ok.view;
    if (!this.viewed || JSON.stringify(v) !== JSON.stringify(this.view)) {
      this.view = v;
      this.viewed = true;
    }
  }

  private async poll(): Promise<void> {
    const a = await this.call<Peers>('peers');
    if (a.ok !== undefined) {
      const names = (a.ok.peers ?? []).map((p: Peer) => p.name !== undefined && p.name.length > 0 ? p.name : p.device.substring(0, 8));
      if (names.join('\n') !== this.peers.join('\n')) {
        this.peers = names;
      }
    }
    // A pause or a mute that ran out ends on its own.
    await this.pollMuted();
    await this.pollDevices();
    await this.pollAway();
    if (this.periodDueAway !== this.periodDue) {
      this.periodDue = this.periodDueAway;
    }
  }

  // Makes this phone one of the group's hubs, reached away from home
  // through the forwarder at forwarder whose key's pin is key ('default'
  // for the project's; both empty on a group of 0.6: the one the root set),
  // hidden as disguise says ('plain' WireGuard,
  // 'obfuscate' AmneziaWG, 'vless' AmneziaWG with VLESS at the forwarder);
  // or stops it being one. Answers why it failed.
  async setHub(on: boolean, forwarder: string, key: string, disguise: string, anyway: boolean): Promise<Failure | undefined> {
    const a = on
      ? await this.call<AwayAnswer>('hub', {
        'forwarder': forwarder,
        'key': key,
        'obfuscate_off': disguise === 'plain',
        'vless_off': disguise !== 'vless'
      } as Record<string, Object>)
      : await this.call<AwayAnswer>('hub_off', { 'anyway': anyway } as Record<string, Object>);
    if (a.ok === undefined) {
      return a.failure;
    }
    const through = forwarder.length > 0 ? forwarder : (a.ok.root_forwarder?.endpoint ?? '');
    Errors.log(on ? `member: this phone is a hub of the group, through ${through}` : 'member: this phone is no hub any more');
    this.readAway(a.ok.away);
    return undefined;
  }

  private attestFetched: number = 0;

  // On the root: fetches the revocation list of Android attestations from
  // the mirror at most once a day and hands it to the member, which checks
  // it with the release keys; then answers how many Android peers'
  // evidence waits for the root key (member/src/phone_attest.rs).
  async attestPending(): Promise<number> {
    if (Date.now() - this.attestFetched >= ATTEST_EVERY_MS) {
      this.attestFetched = Date.now();
      const keys = await this.fetchJson('keys.json');
      const status = keys !== undefined ? await this.fetchJson('attest-status.json') : undefined;
      if (keys !== undefined && status !== undefined) {
        const a = await this.call<Attest>('attest_status', { 'keys': keys, 'status': status } as Record<string, Object>);
        if (a.ok === undefined) {
          Errors.log(`attest: the revocation list was not taken: ${(a.failure as Failure).details}`);
        }
      }
    }
    const a = await this.call<Attest>('attest');
    return a.ok?.pending ?? 0;
  }

  private async fetchJson(name: string): Promise<Object | undefined> {
    const req = http.createHttp();
    try {
      const r = await req.request(ATTEST_MIRROR + name, {
        method: http.RequestMethod.GET,
        expectDataType: http.HttpDataType.STRING,
        connectTimeout: 15000,
        readTimeout: 15000
      });
      const body = r.result as string;
      if (r.responseCode !== 200 || body.length > ATTEST_MAX) {
        Errors.log(`attest: ${name} from the mirror: HTTP ${r.responseCode}`);
        return undefined;
      }
      return JSON.parse(body) as Object;
    } catch (e) {
      Errors.log(`attest: ${name} from the mirror: ${(e as Error).message}`);
      return undefined;
    } finally {
      req.destroy();
    }
  }

  private async pollMuted(): Promise<void> {
    const a = await this.call<Muted>('muted');
    if (a.ok !== undefined) {
      this.readMuted(a.ok);
    }
  }

  private readMuted(a: Muted): void {
    // The core gives what is left, 0 for until it is lifted.
    const until = (left: number | undefined): number => left !== undefined && left > 0 ? Date.now() + left : 0;
    const paused = a.sync_off === true;
    const muted = a.muted === true;
    const pausedUntil = paused ? until(a.sync_off_ms) : 0;
    const mutedUntil = muted ? until(a.muted_ms) : 0;
    // Within a few seconds the same end: the poll's own drift.
    const same = (x: number, y: number): boolean => (x === 0) === (y === 0) && Math.abs(x - y) < 5000;
    if (paused === this.paused && muted === this.muted && same(pausedUntil, this.pausedUntil) && same(mutedUntil, this.mutedUntil)) {
      return;
    }
    this.paused = paused;
    this.muted = muted;
    this.pausedUntil = pausedUntil;
    this.mutedUntil = mutedUntil;
  }

  private async pollAway(): Promise<void> {
    const a = await this.call<AwayAnswer>('away_status');
    if (a.ok === undefined) {
      const f = a.failure as Failure;
      Errors.log(`member: sync away from home: ${f.message} (${f.details})`);
      return;
    }
    this.rootForwarder = a.ok.root_forwarder?.endpoint ?? '';
    this.rootForwarderKey = a.ok.root_forwarder?.key ?? '';
    this.periodDueAway = a.ok.period_due === true;
    if (this.periodOverdue !== (a.ok.period_overdue === true)) {
      this.periodOverdue = a.ok.period_overdue === true;
    }
    this.readAway(a.ok.away);
  }

  private readAway(away: Away | undefined): void {
    const on = away !== undefined && away.keys_in_file === true;
    const hub = away?.hub_device ?? '';
    let status = 'off';
    let hubName = '';
    if (on) {
      let online = false;
      for (const d of this.devices) {
        if (d.id === hub) {
          hubName = d.name;
          online = d.online === true;
        }
      }
      if (hub.length === 0) {
        status = 'waiting';
      } else if (away?.through === true) {
        status = 'connected';
      } else if (online) {
        status = 'home';
      } else {
        status = 'connecting';
      }
    }
    // The error of a state that could not be read shows even while off.
    const message = away?.error ?? '';
    if (message !== this.awayFailure) {
      this.awayFailure = message;
      this.awayError = message.length > 0 ? Errors.shown(new Failure(message, away?.detail ?? '')) : '';
    }
    if (on !== this.awayOn) {
      this.awayOn = on;
    }
    if (status !== this.awayStatus) {
      this.awayStatus = status;
    }
    if (hubName !== this.awayHub) {
      this.awayHub = hubName;
    }
    const hubOn = away?.hub === true;
    const fw = away?.forwarder;
    let hubStatus = 'off';
    if (hubOn) {
      hubStatus = fw === undefined ? 'home' : fw.registered === true ? 'registered' :
        (fw.error ?? '').length > 0 ? 'failed' : 'registering';
    }
    const hubError = hubStatus === 'failed' ? Errors.shown(new Failure(fw?.error ?? '', fw?.detail ?? '')) : '';
    if (hubOn !== this.hubOn || hubStatus !== this.hubStatus || hubError !== this.hubError) {
      this.hubOn = hubOn;
      this.hubStatus = hubStatus;
      this.hubError = hubError;
    }
    const r = away?.relay;
    const relayAt = r?.endpoint ?? '';
    const relayConnected = r?.connected === true;
    const relayOnline = r?.online?.length ?? 0;
    const relayError = (r?.error ?? '').length > 0 ? Errors.shown(new Failure(r?.error ?? '', r?.detail ?? '')) : '';
    if (relayAt !== this.relayAt || relayConnected !== this.relayConnected || relayOnline !== this.relayOnline ||
      relayError !== this.relayError) {
      this.relayAt = relayAt;
      this.relayConnected = relayConnected;
      this.relayOnline = relayOnline;
      this.relayError = relayError;
    }
  }

  // The core's event, on the main thread (the module's threadsafe function).
  private event(json: string): void {
    let e: MemberEvent;
    try {
      e = JSON.parse(json) as MemberEvent;
    } catch (err) {
      Errors.log(`member: an event does not read: ${String(err)}`);
      return;
    }
    if (e.type === 'log') {
      Errors.log(e.line ?? '');
      this.recentLog.push(e.line ?? '');
      if (this.recentLog.length > 300) {
        this.recentLog.shift();
      }
    } else if (e.type === 'panic') {
      Errors.log(`member: ${e.details ?? ''}`);
      this.onPanic(e.details ?? '');
    } else if (e.type === 'write') {
      // While on the screen the phone listens like a computer; in the
      // background it writes nothing (D-128).
      if (this.foreground) {
        this.write(e.text ?? '', e.kind === 'secret', e.ttl_ms ?? 0);
      }
    } else if (e.type === 'mute' || e.type === 'sync') {
      this.pollMuted();
    } else if (e.type === 'copy') {
      // Images or files from another device come by themselves while sync
      // is on, as texts do through write.
      if (e.copy !== undefined) {
        this.cameIn(e.copy);
        // A text written as it came is the app's own write, no copy to send back.
        if (this.foreground && e.copy.kind !== 'media' && (e.copy.text ?? '').length > 0) {
          this.call<Object>('took', { 'id': e.copy.id } as Record<string, Object>);
        }
      }
      if (e.copy !== undefined && e.copy.kind === 'media' && !this.paused && this.foreground) {
        this.take(e.copy);
      }
    }
  }

  // Puts the group's text into the pasteboard. A secret stays on this
  // device (no cross-device pasteboard) and leaves the pasteboard when its
  // time is up, unless something replaced it meanwhile.
  private write(text: string, secret: boolean, ttlMs: number): void {
    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, text);
    if (secret) {
      const props = data.getProperty();
      props.shareOption = pasteboard.ShareOption.LOCALDEVICE;
      data.setProperty(props);
    }
    const board = pasteboard.getSystemPasteboard();
    board.setData(data).then(() => {
      const mark = this.boardChanges;
      // The app's own write is no copy: the next opening finds the
      // pasteboard as it left it.
      this.seen(mark + 1, text);
      if (secret && ttlMs > 0) {
        setTimeout(() => {
          if (this.boardChanges === mark + 1) {
            board.clearData().catch(() => {});
          }
        }, Math.min(ttlMs, 24 * 3600 * 1000));
      }
    }).catch((e: Error) => {
      this.error = Errors.shown(Errors.unexpected(t('error_pasteboard'), e));
    });
    this.setLast(text, secret);
  }

  // Counts the pasteboard's changes, for the secrets' clearing.
  private watchBoard(): void {
    if (this.watching) {
      return;
    }
    this.watching = true;
    pasteboard.getSystemPasteboard().on('update', () => {
      this.boardChanges++;
    });
  }

  // The key the core's rule compares an image by: its PNG's SHA-256.
  private static imageKey(png: ArrayBuffer): string {
    const md = cryptoFramework.createMd('SHA256');
    md.updateSync({ data: new Uint8Array(png) });
    const sum = md.digestSync().data;
    let hex = '';
    for (let i = 0; i < sum.length; i++) {
      hex += sum[i].toString(16).padStart(2, '0');
    }
    return `\u0000image:${hex}`;
  }

  // A pasteboard image as PNG, undefined when it does not pack.
  private async packed(pixels: image.PixelMap): Promise<ArrayBuffer | undefined> {
    const packer = image.createImagePacker();
    try {
      return await packer.packToData(pixels, { format: 'image/png', quality: 100 });
    } catch (e) {
      this.error = Errors.shown(Errors.unexpected(t('error_image'), e as Object));
      return undefined;
    } finally {
      packer.release();
    }
  }

  // Sends an image the pasteboard held to the group, unless it is the one
  // the phone took or too large.
  private async sendImage(png: ArrayBuffer): Promise<boolean> {
    if (Member.imageKey(png) === this.tookImage || png.byteLength > MAX_SEND_BYTES) {
      return false;
    }
    const part: Record<string, Object> = { 'type': 'image/png', 'data': toBase64(png) };
    const sent = await this.call<Object>('copy_media', { 'parts': [part], 'board': true } as Record<string, Object>);
    if (sent.ok === undefined) {
      this.error = Errors.shown(sent.failure as Failure);
      return false;
    }
    this.error = '';
    this.last = t('last_image');
    return true;
  }

  // Takes the group's images or files: fetched into the app's folder of
  // received copies (the main page saves them where the user picks), one
  // image into the pasteboard too; then tells the core it took them.
  private async take(copy: Copy): Promise<void> {
    if (this.fetching) {
      return;
    }
    const d = new Date();
    const pad = (n: number): string => n.toString().padStart(2, '0');
    const folder = `${this.dir}/received/${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}.${pad(d.getMinutes())}.${pad(d.getSeconds())}`;
    this.fetching = true;
    const got = await this.call<Fetched>('fetch', { 'id': copy.id, 'max': MAX_FETCH_BYTES, 'out': folder } as Record<string, Object>);
    this.fetching = false;
    if (got.ok === undefined) {
      this.error = Errors.shown(got.failure as Failure);
      return;
    }
    await this.call<Object>('took', { 'id': copy.id } as Record<string, Object>);
    let files = 0;
    let picture = '';
    for (const p of got.ok.parts ?? []) {
      if (p.dir === true) {
        continue;
      }
      files++;
      if (IMAGE_TYPES.includes(p.type ?? '') && p.file !== undefined) {
        picture = p.file;
      }
    }
    if (files === 1 && picture.length > 0) {
      await this.putImage(picture);
    }
    this.error = '';
    this.received = folder;
    this.last = files === 1 && picture.length > 0 ? t('last_image') : t('last_files', files);
    Errors.log(`member: saved ${files} files of the group's copy`);
    this.onSaved(folder, files);
  }

  // One image of the group into the pasteboard, kept out of the next sending.
  private async putImage(path: string): Promise<void> {
    try {
      const source = image.createImageSource(path);
      const pixels = await source.createPixelMap();
      source.release();
      await pasteboard.getSystemPasteboard().setData(pasteboard.createData(pasteboard.MIMETYPE_PIXELMAP, pixels));
      const packer = image.createImagePacker();
      this.tookImage = Member.imageKey(await packer.packToData(pixels, { format: 'image/png', quality: 100 }));
      packer.release();
    } catch (e) {
      Errors.log(`member: the image stays a file: ${String(e)}`);
    }
  }

  private setLast(text: string, secret: boolean): void {
    this.last = secret ? t('last_secret') : shortLine(text, 60);
  }
}

