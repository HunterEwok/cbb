// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the pages show and do: the phone's group, its member, joining,
// adding devices, invitations, the admin's changes, changing the root with
// the recovery key, the settings. One for the app, as
// the Aurora app's App.

import { common } from '@kit.AbilityKit';
import cbb from 'libcbb_napi.so';
import { preferences } from '@kit.ArkData';
import { deviceInfo } from '@kit.BasicServicesKit';
import { util } from '@kit.ArkTS';
import { read, Result } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure, forget } from '../core/Keys';
import { cardFailure, withCard } from '../common/YubiKey';
import { Membership } from '../core/Membership';
import { OS, osVersion, phoneName, STORE } from '../core/Phone';
import { t } from '../core/Text';
import { Bugs } from './Bugs';
import { Events } from './Events';
import { Invite } from './Invite';
import { Join } from './Join';
import { Joiner, PairWindow } from './Pairing06';
import { Keyboard } from './Keyboard';
import { Device, Member } from './Member';
import { Paste } from './Paste';

// The root's duties (the attestations, the next period of the server
// keys) are due days ahead, so a look every few hours, and one a minute
// after the member starts, once it reached its peers, is plenty.
const DUTIES_EVERY_MS: number = 6 * 3600 * 1000;
const DUTIES_FIRST_MS: number = 60 * 1000;
// What the core says when the hub to stop is the group's only one.
const ONLY_HUB: string = 'no other hub';

// What sealing the recovery key onto a YubiKey did (cbb_piv seal): the
// retired slot, and whether the card keeps its factory management key,
// which cbb never changes (D-127).
interface Sealed {
  slot?: number;
  default_key?: boolean;
}

// How the YubiKey found was reached (findCard).
interface Reached {
  transport?: string;
}

interface Opened {
  secret?: string;
}

// A device in the "who stays" list of a change of root.
export interface ChangeRow {
  device: string;
  name: string;
  os: string;
  outcome: string;
  frozen: boolean;
}

export interface ChangePreview {
  rows: ChangeRow[];
  waiting: boolean;
}

// What manage answers: a command's status and reason, the key level's
// devices below it, how many attestations were recorded, the watch's.
export interface ManageAnswer {
  status?: string;
  reason?: string;
  recorded?: number;
  below?: string[];
  device?: string;
  group?: string;
}

// An item of the main page: a device, or a collection of devices.
export class Tile {
  kind: string = 'device'; // device or collection
  device?: Device;
  id: string = '';
  name: string = '';
  devices: Device[] = [];
}

// The core's answer of a new group of 0.6 (ffi's found.rs).
interface Sheet06 {
  qr?: string;
  text?: string[];
  modules?: string[];
}

interface Made06 {
  group?: string;
  device?: string;
  recovery?: Sheet06;
}

@ObservedV2
export class AppModel {
  @Trace membership: Membership | undefined = undefined;
  @Trace busy: boolean = false;
  // The last error as shown (with its details when Errors.showDetails()).
  @Trace error: string = '';
  // The recovery sheet of the group the phone just made, shown once.
  @Trace recoveryText: string = '';
  @Trace recoveryModules: string[] = [];
  // The sheet's QR code text, which sealing it onto a YubiKey takes.
  recoveryQr: string = '';
  // The admins and hubs the key level set last does not let in.
  @Trace belowLevel: string[] = [];
  // Bumped when the user's arrangement of the tiles changes.
  @Trace arrangement: number = 0;
  @Trace deviceList: boolean = false;
  // A big screen's devices: orbit, tiles or list.
  @Trace wideLayout: string = 'orbit';
  @Trace errorDetails: boolean = false;
  // The switch for the advanced settings, as on the other phones.
  @Trace advanced: boolean = false;

  readonly member: Member = new Member();
  readonly join: Join = new Join();
  // Pairing in a group of 0.6: the admin's window and the new phone's joiner.
  readonly window: PairWindow = new PairWindow();
  readonly joiner: Joiner = new Joiner();
  readonly invite: Invite = new Invite();
  readonly events: Events = new Events();
  // The bug report the app asks about in release mode (docs/core-api.md, "Bug reports").
  readonly bugs: Bugs = new Bugs();
  // The lab (docs/apps.md, "The lab"): the phone as a Bluetooth keyboard,
  // which also types an admin's remote paste.
  readonly keyboard: Keyboard = new Keyboard();
  readonly paste: Paste = new Paste();

  private dir: string = '';
  private prefs: preferences.Preferences | undefined = undefined;
  private dutiesTimer: number = -1;

  init(dir: string, prefs: preferences.Preferences): void {
    this.dir = dir;
    this.prefs = prefs;
    this.events.init(prefs);
    this.bugs.init(prefs);
    // Reports that waited for the network go now.
    setTimeout(() => {
      this.bugs.resend();
    }, 0);
    this.deviceList = prefs.getSync('device_list', false) as boolean;
    this.wideLayout = prefs.getSync('wide_layout', 'orbit') as string;
    this.advanced = prefs.getSync('advanced', false) as boolean;
    this.errorDetails = Errors.showDetails();
    const m = Membership.load(dir);
    if (m instanceof Membership) {
      this.membership = m;
      Errors.log(m.isBefore06() ? 'group: from before 0.6, which needs a new group' : `group: ${m.groupTag()} as ${m.member.device}`);
    } else if (m !== undefined) {
      this.show(Errors.shown(m));
    }
    this.member.onDevices = (devices: Device[]) => {
      this.events.observe(devices);
      this.adminFromRecords(devices);
    };
    // A member that broke stops and starts again; the user sees what
    // broke, the details only in debug mode (Errors.shown).
    this.member.onPanic = (details: string) => {
      this.panicked(details);
    };
    this.paste.init(prefs, this.keyboard);
    this.paste.pasted = (name: string) => {
      this.events.post(t('pasted_from', name));
    };
    this.member.onSaved = (folder: string, count: number) => {
      this.events.post(count === 1 ? t('notify_saved_one') : t('notify_saved', count));
    };
    // A phone that joined a group of 0.6: the set is in the app's files.
    this.joiner.onJoined = (group: string, device: string) => {
      if (this.keep(Membership.of06(device, group, false))) {
        this.startMember();
      }
    };
    // Joined from afar: the member reaches the hub through the invitation's
    // guest tunnel, kept with the set, until the hub's offer comes.
    this.join.onJoined = (group: string, device: string) => {
      if (this.keep(Membership.of06(device, group, false))) {
        this.startMember();
      }
    };
  }

  isAdmin(): boolean {
    return this.membership !== undefined && this.membership.isAdmin();
  }

  // On 0.6 the group's records say who is an admin; the member's devices
  // list them.
  private adminFromRecords(devices: Device[]): void {
    const m = this.membership;
    if (m === undefined || m.isBefore06()) {
      return;
    }
    const self = devices.find((d: Device) => d.self === true);
    if (self === undefined) {
      return;
    }
    const admin = self.admin === true;
    if (admin === (m.member.admin06 === true)) {
      return;
    }
    const next = m.copy();
    next.member.admin06 = admin;
    if (this.keep(next)) {
      Errors.log(`admin: the records ${admin ? 'make' : 'no longer make'} this phone an admin`);
    }
  }

  // As an admin of a group of 0.6: opens the member's pairing window.
  openWindow(): void {
    if (this.membership === undefined || !this.membership.isAdmin()) {
      return;
    }
    this.window.open(this.member);
  }

  // Without a group: joins a group of 0.6 by text, the six digits a window
  // of the group shows (the window announced at home), or a window's QR code
  // text, scanned or pasted.
  joinByWindow(text: string): void {
    if (this.membership !== undefined) {
      return;
    }
    const digits = text.replace(/\s/g, '');
    if (/^[0-9]{6}$/.test(digits)) {
      this.joiner.start(this.dir, '', digits, phoneName(), OS);
    } else {
      this.joiner.start(this.dir, text, '', phoneName(), OS);
    }
  }

  isRoot(): boolean {
    return this.membership !== undefined && this.membership.isRoot();
  }

  show(error: string): void {
    this.error = error;
  }

  // A group from before 0.6, which this version no longer runs (D-126).
  isBefore06(): boolean {
    return this.membership !== undefined && this.membership.isBefore06();
  }

  // Starts the member once the phone has a group of 0.6, with the timer of
  // the root's duties.
  async startMember(): Promise<void> {
    const m = this.membership;
    if (m === undefined || m.isBefore06() || this.member.running) {
      return;
    }
    await this.member.start(m, this.dir, phoneName());
    if (!this.member.running) {
      return;
    }
    if (this.dutiesTimer < 0) {
      this.dutiesTimer = setInterval(() => {
        this.duties();
      }, DUTIES_EVERY_MS);
      setTimeout(() => {
        this.duties();
      }, DUTIES_FIRST_MS);
    }
    await this.restoreHub();
  }

  async stopMember(): Promise<void> {
    clearInterval(this.dutiesTimer);
    this.dutiesTimer = -1;
    await this.member.stop();
  }

  // Makes a group of the phone's own, its root key the admin key in HUKS
  // (docs/protocol.md, section 3), and starts the member as its root.
  async makeGroup(): Promise<boolean> {
    if (this.busy || this.membership !== undefined) {
      return false;
    }
    this.busy = true;
    const failure = await this.newGroup();
    this.busy = false;
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      return false;
    }
    this.show('');
    await this.startMember();
    return true;
  }

  // A group of 0.6: the set is kept in the app's files, where the member
  // then starts on it (ffi's cbb_group_new with dir), and its recovery
  // sheet is shown once (pages/Recovery).
  private async newGroup(): Promise<Failure | undefined> {
    const member = await ensure('member');
    if (member.ok === undefined) {
      return member.failure;
    }
    const root = await ensure('admin');
    if (root.ok === undefined) {
      return root.failure;
    }
    const request: Record<string, Object> = {
      'dir': this.dir,
      'name': phoneName(),
      'os': OS,
      'store': STORE,
      'public': member.ok.public,
      'root_public': root.ok.public
    };
    const group = read<Made06>(await cbb.groupNew(JSON.stringify(request)), 'group');
    if (group.ok === undefined) {
      return group.failure;
    }
    const m = Membership.of06(group.ok.device ?? '', group.ok.group ?? '', true);
    if (m.isBefore06() || m.member.device.length === 0) {
      return new Failure(t('error_broken'), 'group: no device in the answer');
    }
    const saved = m.save(this.dir);
    if (saved !== undefined) {
      return saved;
    }
    Errors.log(`group: made ${m.groupTag()} as its root`);
    this.membership = m;
    this.recoveryText = (group.ok.recovery?.text ?? []).join('\n');
    this.recoveryModules = group.ok.recovery?.modules ?? [];
    this.recoveryQr = group.ok.recovery?.qr ?? '';
    return undefined;
  }

  startJoinByInvite(text: string): void {
    this.join.startInvite(this.dir, text, phoneName(), OS);
  }

  startInvite(seconds: number): void {
    if (this.membership !== undefined) {
      this.invite.open(this.member, seconds);
    }
  }

  // An admin's change to a device (remove, rename, thaw, make_admin,
  // sync_on, sync_off) or command for it (mute, unmute), signed with the
  // admin key; forMinutes: how long a mute or a sync off lasts, 0 for until
  // undone. True once the change is in the records or the device took the
  // command.
  async manage(action: string, device: string, name?: string, forMinutes?: number): Promise<boolean> {
    const extra: Record<string, Object> = { 'name': name ?? '', 'for_ms': (forMinutes ?? 0) * 60000 };
    const a = await this.runManage(action, device, extra);
    return a !== undefined;
  }

  // Puts text where a computer's focus is (docs/design.md, "Remote paste"),
  // pasted or typed key by key, with Enter after it if asked; a secret
  // leaves no trace there. Signed with the admin key; true once the
  // computer took it.
  async pasteOn(device: string, text: string, method: string, enter: boolean, secret: boolean): Promise<boolean> {
    // The computer waits 5 s for its target, and 5 ms more for each typed byte.
    const typed = method === 'type' ? new util.TextEncoder().encodeInto(text).length * 5 : 0;
    const a = await this.runManage('paste', device, {
      'mode': method, 'kind': secret ? 'secret' : 'text', 'text': text, 'enter': enter, 'timeout_ms': 10000 + typed
    } as Record<string, Object>);
    return a !== undefined;
  }

  // Pastes images or files where a computer's focus is (docs/protocol.md,
  // section 15): they go to the group as a copy, then a paste command of
  // kind media names it; the computer fetches it, puts it in its
  // clipboard and presses the paste keys. True once it took them.
  async pasteMedia(device: string, files: string[], types: string[], enter: boolean): Promise<boolean> {
    if (this.busy) {
      return false;
    }
    const made = await this.member.copyForPaste(files, types);
    if (made.ok === undefined) {
      this.show(Errors.shown(made.failure as Failure));
      return false;
    }
    // The computer waits up to 20 s for the copy, then 8 s for its desktop.
    const a = await this.runManage('paste', device, {
      'mode': 'paste', 'kind': 'media', 'text': made.ok, 'enter': enter, 'timeout_ms': 35000
    } as Record<string, Object>);
    return a !== undefined;
  }

  async setGroupKeyLevel(level: string): Promise<void> {
    if (!this.isRoot()) {
      return;
    }
    const a = await this.runManage('key_level', '', { 'level': level } as Record<string, Object>);
    if (a !== undefined) {
      this.belowLevel = a.below ?? [];
    }
  }

  // Sets how long a copy or a secret lives for the whole group (D-129);
  // the other is left as it is.
  async setGroupTtl(ttlMs: number | undefined, secretTtlMs: number | undefined): Promise<void> {
    const extra: Record<string, Object> = {};
    if (ttlMs !== undefined) {
      extra['ttl_ms'] = ttlMs;
    }
    if (secretTtlMs !== undefined) {
      extra['secret_ttl_ms'] = secretTtlMs;
    }
    if (await this.runManage('ttl', '', extra) !== undefined) {
      await this.member.pollDevices();
    }
  }

  // The sheet is shown once; nothing of the key stays in the app.
  forgetRecovery(): void {
    this.recoveryText = '';
    this.recoveryModules = [];
    this.recoveryQr = '';
  }

  // The group's ID in hex, which names its slot on a YubiKey.
  private groupId(): string {
    return this.membership?.member.group06 ?? '';
  }

  // Waits for a YubiKey plugged in or held to the phone, with nothing done
  // on it, before its PIN is asked: true when it is on USB, false over NFC,
  // undefined with the failure shown.
  async findCard(context: common.UIAbilityContext): Promise<boolean | undefined> {
    if (this.busy) {
      return undefined;
    }
    const run = await withCard(context, async (transport: string) => {
      const reached: Reached = { transport: transport };
      return JSON.stringify(reached);
    });
    if (run.failure !== undefined) {
      this.show(Errors.shown(run.failure));
      return undefined;
    }
    this.show('');
    return (JSON.parse(run.answer) as Reached).transport === 'ccid_bulk';
  }

  // Seals the sheet's recovery key onto a YubiKey held to the phone or
  // plugged in, after its PIN, into its first empty retired slot, named for
  // this group (cbb_piv seal; docs/protocol.md, "The recovery key on a
  // YubiKey (0.6)"). Answers what to tell the person, empty with the failure
  // shown.
  async sealOnCard(context: common.UIAbilityContext, pin: string,
    plugged: () => void = () => {}): Promise<string> {
    if (this.recoveryQr.length === 0 || this.busy) {
      return '';
    }
    this.busy = true;
    const request: Record<string, Object> = {
      'op': 'seal', 'pin': pin, 'recovery': { 'qr': this.recoveryQr } as Record<string, Object>,
      'group': this.groupId()
    };
    const run = await withCard(context, (transport: string) => {
      request['transport'] = transport;
      return cbb.piv(JSON.stringify(request));
    }, plugged);
    this.busy = false;
    const failure = run.failure ?? read<Sealed>(run.answer, 'yubikey: seal').failure;
    if (failure !== undefined) {
      this.show(Errors.shown(run.failure !== undefined ? failure : cardFailure(failure)));
      return '';
    }
    const sealed = read<Sealed>(run.answer, 'yubikey: seal').ok as Sealed;
    Errors.log(`yubikey: sealed in slot ${(sealed.slot ?? 0).toString(16)}, factory management key ${sealed.default_key === true}`);
    this.show('');
    return t('yubikey_sealed');
  }

  // Opens the recovery key on a YubiKey held to the phone, after its PIN
  // and a touch, for a change of root: the secret in base64, or undefined
  // with the failure shown. The caller drops it after that one change.
  async openCard(context: common.UIAbilityContext, pin: string,
    plugged: () => void = () => {}): Promise<string | undefined> {
    if (this.busy) {
      return undefined;
    }
    this.busy = true;
    const request: Record<string, Object> = { 'op': 'open', 'pin': pin, 'group': this.groupId() };
    const run = await withCard(context, (transport: string) => {
      request['transport'] = transport;
      return cbb.piv(JSON.stringify(request));
    }, plugged);
    this.busy = false;
    if (run.failure !== undefined) {
      this.show(Errors.shown(run.failure));
      return undefined;
    }
    const r = read<Opened>(run.answer, 'yubikey: open');
    if (r.ok === undefined) {
      this.show(Errors.shown(cardFailure(r.failure as Failure)));
      return undefined;
    }
    this.show('');
    return r.ok.secret;
  }

  // Who stays after this phone becomes the root with the recovery key
  // (manage change_preview), leaveOut unticked; undefined with the failure
  // shown. Nothing is signed.
  async changePreview(recovery: Record<string, Object>, leaveOut: string[]): Promise<ChangePreview | undefined> {
    if (!this.member.running) {
      return undefined;
    }
    const r = await this.member.manage<ChangePreview>({
      'action': 'change_preview', 'device': '', 'public': '', 'recovery': recovery, 'leave_out': leaveOut
    } as Record<string, Object>);
    if (r.ok === undefined) {
      this.show(Errors.shown(r.failure as Failure));
      return undefined;
    }
    this.show('');
    return r.ok;
  }

  // Makes this phone the group's root with the recovery key (manage
  // change_root, rule 33): the admin key in HUKS, behind the fingerprint,
  // the face or the PIN, becomes the root key and signs the change with
  // the recovery key; the devices in leaveOut go in the same act.
  async changeRoot(recovery: Record<string, Object>, leaveOut: string[], overWaiting: boolean): Promise<boolean> {
    const m = this.membership;
    if (m === undefined || m.isRoot() || this.busy || !this.member.running) {
      return false;
    }
    this.busy = true;
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.busy = false;
      this.show(Errors.shown(key.failure as Failure));
      return false;
    }
    const r = await this.member.manage<ManageAnswer>({
      'action': 'change_root', 'device': '', 'public': key.ok.public, 'recovery': recovery, 'leave_out': leaveOut,
      'over_waiting': overWaiting
    } as Record<string, Object>);
    this.busy = false;
    if (r.ok === undefined) {
      this.show(Errors.shown(r.failure as Failure));
      return false;
    }
    const next = m.copy();
    next.member.root = true;
    if (!this.keep(next)) {
      return false;
    }
    Errors.log("change root: this phone is the group's root now, by the recovery key");
    this.show('');
    return true;
  }

  // Makes the watch an admin as the root (manage add_watch) with the admin
  // key it made, key its SubjectPublicKeyInfo: the watch's device ID, its
  // admin CA, the group's tag and the key's hash as the records name it.
  async addWatch(key: string, name: string): Promise<ManageAnswer | undefined> {
    if (!this.isRoot()) {
      return undefined;
    }
    return this.runManage('add_watch', '', { 'key': key, 'name': name, 'os': 'harmonyos' } as Record<string, Object>);
  }

  // Signs action for device with extra in the request. Shows a failure
  // (quiet: only logs it) and answers undefined.
  private async runManage(action: string, device: string, extra: Record<string, Object>,
    quiet?: boolean): Promise<ManageAnswer | undefined> {
    const m = this.membership;
    if (m === undefined || !m.isAdmin() || !this.member.running) {
      this.show(Errors.shown(new Failure(t('error_not_admin'), 'manage: not an admin or no member')));
      return undefined;
    }
    if (this.busy) {
      return undefined;
    }
    this.busy = true;
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.busy = false;
      this.show(Errors.shown(key.failure as Failure));
      return undefined;
    }
    const request: Record<string, Object> = extra;
    request['action'] = action;
    request['device'] = device;
    request['public'] = key.ok.public;
    const a: Result<ManageAnswer> = await this.member.manage<ManageAnswer>(request);
    this.busy = false;
    let failure = a.failure;
    // A command the device refused answers with its status and reason.
    const status = a.ok?.status;
    if (failure === undefined && status !== undefined && status !== 'done') {
      failure = new Failure(t('error_command_refused'), `manage: ${status}: ${a.ok?.reason ?? ''}`);
    }
    if (failure !== undefined) {
      if (quiet === true) {
        Errors.log(`manage: ${failure.message} (${failure.details})`);
      } else {
        this.show(Errors.shown(failure));
      }
      return undefined;
    }
    Errors.log(`manage: ${action} ${device}`);
    if (quiet !== true) {
      this.show('');
    }
    return a.ok;
  }

  // The root's duties, quietly: only the log says. It records what the
  // Android phones' attestations show (docs/protocol.md, section 17), with
  // the revocation list, and signs the next period of the server keys.
  private async duties(): Promise<void> {
    if (this.busy || !this.isRoot() || !this.member.running) {
      return;
    }
    if (await this.member.attestPending() > 0) {
      const r = await this.runManage('attest', '', {} as Record<string, Object>, true);
      if (r !== undefined && (r.recorded ?? 0) > 0) {
        Errors.log(`attest: recorded what ${r.recorded} attestations show`);
      }
    }
    // The root key signs the next period of the group's server keys
    // (docs/protocol.md, section 18) when it is due.
    if (this.member.periodDue) {
      if (await this.runManage('period', '', {} as Record<string, Object>, true) !== undefined) {
        Errors.log('servers: signed the next period of the server keys');
        this.member.periodDue = false;
      }
    }
  }

  // This phone as one of the group's hubs, as the user set it; the core
  // does not keep it, so it is set again each time the member starts.
  hubWanted(): boolean {
    return this.prefs !== undefined && this.prefs.getSync('hub_on', false) as boolean;
  }

  hubDisguise(): string {
    return this.prefs !== undefined ? this.prefs.getSync('hub_disguise', 'plain') as string : 'plain';
  }

  // Makes this phone a hub of the group, through the forwarder the group's
  // root set, or stops it being one (anyway: also when it is the group's
  // only hub). Shows why not, except that it is the only hub, which it
  // answers for the user to decide.
  async setHub(on: boolean, disguise: string, anyway: boolean): Promise<Failure | undefined> {
    const failure = await this.member.setHub(on, '', '', disguise, anyway);
    if (failure !== undefined) {
      if (on || anyway || !failure.details.includes(ONLY_HUB)) {
        this.show(Errors.shown(failure));
      }
      return failure;
    }
    this.prefs?.putSync('hub_on', on);
    if (on) {
      this.prefs?.putSync('hub_disguise', disguise);
    }
    this.prefs?.flush();
    this.show('');
    return undefined;
  }

  // Whether a failure of setHub is that this phone is the group's only hub.
  onlyHub(failure: Failure | undefined): boolean {
    return failure !== undefined && failure.details.includes(ONLY_HUB);
  }

  // The root sets the group's relay (manage relay), where every device
  // meets the others: the address with its key's pin, the project's with
  // the key 'default', or none with both empty. Shows why not.
  async setRelay(relay: string, key: string): Promise<boolean> {
    if (!this.isRoot()) {
      this.show(Errors.shown(new Failure(t('relay_by_root'), 'relay: only the root sets the group\'s relay')));
      return false;
    }
    const relays: string[] = relay.length === 0 ? [] : key === 'default' ? ['default'] : [`${relay} ${key}`];
    const a = await this.runManage('relay', '', { 'relays': relays } as Record<string, Object>);
    if (a === undefined) {
      return false;
    }
    Errors.log(relays.length > 0 ? `relay: the group meets at ${relay}` : 'relay: the group meets at no relay');
    this.show('');
    return true;
  }

  private async restoreHub(): Promise<void> {
    if (this.hubWanted() && this.isAdmin()) {
      const failure = await this.member.setHub(true, '', '', this.hubDisguise(), false);
      if (failure !== undefined) {
        Errors.log(`servers: the hub did not start again: ${failure.message} (${failure.details})`);
      }
    }
  }

  // Keeps next as the membership, or shows why it could not.
  private keep(next: Membership): boolean {
    const failure = next.save(this.dir);
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      return false;
    }
    this.membership = next;
    return true;
  }

  // Leaves the group on this phone: stops the member and deletes the
  // membership and the keys (D-83); for a group from before 0.6, its old
  // files too, which only this choice deletes (D-126). The group still
  // lists the phone until an admin removes it.
  async leave(): Promise<boolean> {
    if (this.busy) {
      return false;
    }
    await this.stopMember();
    const failure = Membership.remove(this.dir);
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      return false;
    }
    Errors.log(`group: left ${this.membership?.groupTag() ?? ''}`);
    this.membership = undefined;
    this.events.forget();
    this.paste.forgetLog();
    this.show('');
    // A phone that joined again with its old member key would share it with
    // its old device record, and removing that record revokes the key; the
    // next key is made at the next join.
    this.busy = true;
    const gone = await forget();
    this.busy = false;
    if (gone.ok === undefined) {
      this.show(Errors.shown(gone.failure as Failure));
      return false;
    }
    Errors.log('key: deleted the member and admin keys');
    return true;
  }

  setErrorDetails(on: boolean): void {
    Errors.setShowDetails(on);
    this.errorDetails = Errors.showDetails();
  }

  setAdvanced(on: boolean): void {
    this.advanced = on;
    this.prefs?.putSync('advanced', on);
    this.prefs?.flush();
  }

  // The member broke (docs/core-api.md, "Panics"): in release mode the app
  // asks to send a report, in debug mode the error shows whole and nothing
  // is asked; then the member starts again.
  private panicked(details: string): void {
    this.show(Errors.shown(new Failure(t('bug_broke_restarted'), details)));
    if (!Errors.showDetails()) {
      this.bugs.offer({
        'kind': 'panic', 'code': 5, 'name': 'panic', 'message': 'Something in CBB broke, and it started again.',
        'details': details, 'app': 'harmonyos', 'version': AppStorage.get<string>('version') ?? '', 'os': OS,
        'os_version': osVersion(), 'model': deviceInfo.productModel, 'arch': deviceInfo.abiList,
        'log': this.member.recentLog.slice(), 'names': this.member.devices.map((d: Device) => d.name)
      } as Record<string, Object>);
    }
    setTimeout(async () => {
      await this.stopMember();
      await this.startMember();
    }, 0);
  }

  setDeviceList(on: boolean): void {
    this.deviceList = on;
    this.prefs?.putSync('device_list', on);
    this.prefs?.flush();
  }

  setWideLayout(layout: string): void {
    this.wideLayout = layout;
    this.prefs?.putSync('wide_layout', layout);
    this.prefs?.flush();
  }

  // Whether the user closed a tip shown until closed once, and closing it.
  tipClosed(name: string): boolean {
    return this.prefs !== undefined && this.prefs.getSync(name, false) as boolean;
  }

  closeTip(name: string): void {
    this.prefs?.putSync(name, true);
    this.prefs?.flush();
  }

  // Whether the user changed the tiles' order (the member's view).
  hasArrangement(): boolean {
    return this.member.view.custom === true;
  }

  // The member's devices in the user's order and collections as the member
  // keeps them (docs/apps.md, "What the member shows"); this phone first
  // until the user moves it. Each device as the member's devices list it,
  // or as the view gives it.
  arranged(devices: Device[]): Tile[] {
    const byId = new Map<string, Device>();
    devices.forEach((d: Device) => {
      byId.set(d.id, d);
    });
    if (!this.member.viewed) {
      // The group's order, so the devices still show.
      return devices.map((d: Device) => {
        const tile = new Tile();
        tile.device = d;
        return tile;
      });
    }
    const device = (d: Device): Device => byId.get(d.id) ?? d;
    const view: Tile[] = [];
    for (const item of this.member.view.tiles) {
      const tile = new Tile();
      if (item.device !== undefined) {
        tile.device = device(item.device);
      } else if (item.collection !== undefined) {
        tile.kind = 'collection';
        tile.id = item.collection.id;
        tile.name = item.collection.name;
        tile.devices = item.collection.devices.map(device);
      } else {
        continue;
      }
      view.push(tile);
    }
    return view;
  }

  // Sends a change of the arrangement to the member, which keeps it
  // ("move", "into", "out", "new", "rename", "ungroup", "reset").
  async arrange(op: Record<string, Object>): Promise<boolean> {
    const f = await this.member.arrange(op);
    if (f !== undefined) {
      this.show(Errors.shown(f));
    }
    this.arrangement++;
    return f === undefined;
  }
}

// The app's one model.
export const app: AppModel = new AppModel();
