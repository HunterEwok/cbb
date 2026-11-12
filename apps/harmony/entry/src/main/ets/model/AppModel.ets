// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the pages show and do: the phone's group, its member, joining,
// adding devices, invitations, the admin's changes, restoring from the
// recovery sheet, taking the group over, the settings. One for the app, as
// the Aurora app's App.

import cbb from 'libcbb_napi.so';
import { preferences } from '@kit.ArkData';
import { deviceInfo } from '@kit.BasicServicesKit';
import { util } from '@kit.ArkTS';
import { call, read, Result } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure, forget } from '../core/Keys';
import { Joined, Membership, sealSecret } from '../core/Membership';
import { OS, osVersion, phoneName, STORE } from '../core/Phone';
import { t } from '../core/Text';
import { Admit } from './Admit';
import { Bugs } from './Bugs';
import { Events } from './Events';
import { Invite } from './Invite';
import { Join } from './Join';
import { Keyboard } from './Keyboard';
import { Device, Member } from './Member';
import { CheckedPaste, Paste, PasteAnswer } from './Paste';
import { Shared } from '../common/Share';

// Renewals are due months ahead, so a look every few hours, and one a
// minute after the member starts, once it reached its peers, is plenty.
const RENEW_EVERY_MS: number = 6 * 3600 * 1000;
const RENEW_FIRST_MS: number = 60 * 1000;
// The project's forwarder, its key's pin given as 'default' (docs/protocol.md, section 13).
export const PROJECT_FORWARDER: string = 'cbb.tools:8764';
export const PROJECT_KEY: string = 'default';
// What the core says when the hub to stop is the group's only one.
const ONLY_HUB: string = 'no other hub';
// A waiting claim is looked at every minute, and first once the member had
// time to reach its peers.
const CLAIM_EVERY_MS: number = 60 * 1000;
const CLAIM_FIRST_MS: number = 10 * 1000;

interface SealKey {
  key: string;
}

interface CommandResult {
  status?: string;
  reason?: string;
}

interface ManageAnswer {
  result?: CommandResult;
  root_ca?: string;
  renewed?: number;
  below?: string[];
  text?: string;
  modules?: string[];
  state?: string;
  left_ms?: number;
  cert?: string;
}

interface Restored extends Joined {
  addr?: string;
}

// An item of the main page: a device, or a collection of devices.
export class Tile {
  kind: string = 'device'; // device or collection
  device?: Device;
  id: string = '';
  name: string = '';
  devices: Device[] = [];
}

// What the user reads when restoring failed: the core's refusals it knows
// said in the user's language, the core's own words kept in the details.
function restoreFailure(f: Failure): Failure {
  const d = `${f.message} ${f.details}`;
  let shown = t('error_restore');
  if (d.includes('scan the QR code of the recovery sheet')) {
    shown = t('error_restore_scan');
  } else if (d.includes("not the group's recovery key now")) {
    shown = t('error_restore_not_key');
  } else if (d.includes('no device of the group was found')) {
    shown = t('error_restore_no_device');
  } else if (d.includes('not a cbb recovery sheet')) {
    shown = t('error_restore_not_sheet');
  }
  return new Failure(shown, `${f.details} (${f.message})`);
}

@ObservedV2
export class AppModel {
  @Trace membership: Membership | undefined = undefined;
  @Trace busy: boolean = false;
  // The last error as shown (with its details when Errors.showDetails()).
  @Trace error: string = '';
  // The phone's claim to take the group over: '' without one, else
  // "pending", "competing", "disputed", "none", "effective", "cancelled" or "void".
  @Trace claimState: string = '';
  @Trace claimLeftMs: number = 0;
  // Restoring from the recovery sheet: '', restoring, claiming, claimed or failed.
  @Trace restoreState: string = '';
  // The recovery sheet the root just made, shown once.
  @Trace recoveryText: string = '';
  @Trace recoveryModules: string[] = [];
  // The admins and hubs the key level set last does not let in.
  @Trace belowLevel: string[] = [];
  // Bumped when the user's arrangement of the tiles changes.
  @Trace arrangement: number = 0;
  @Trace deviceList: boolean = false;
  @Trace errorDetails: boolean = false;
  // The switch for the advanced settings, as on the other phones.
  @Trace advanced: boolean = false;

  readonly member: Member = new Member();
  readonly join: Join = new Join();
  readonly admit: Admit = new Admit();
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
  private renewTimer: number = -1;
  private claimTimer: number = -1;
  // What was shared to the app before the member ran.
  private pending: Shared | undefined = undefined;

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
    this.advanced = prefs.getSync('advanced', false) as boolean;
    this.errorDetails = Errors.showDetails();
    const m = Membership.load(dir);
    if (m instanceof Membership) {
      this.membership = m;
      Errors.log(`group: ${m.groupTag()} as ${m.member.device}`);
    } else if (m !== undefined) {
      this.show(Errors.shown(m));
    }
    this.member.onDevices = (devices: Device[]) => {
      this.events.observe(devices);
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
    this.member.onPaste = (c: CheckedPaste, name: string): PasteAnswer => this.paste.carryOut(c, name);
    this.member.onSaved = (folder: string, count: number) => {
      this.events.post(count === 1 ? t('notify_saved_one') : t('notify_saved', count));
    };
    this.member.onIdentity = (cert: string, issuer: string, roots: string[]) => {
      if (this.membership === undefined) {
        return;
      }
      const next = this.membership.copy();
      next.member.cert = cert;
      next.member.issuer = issuer.length > 0 ? issuer : undefined;
      next.member.roots = roots;
      // On a failure the member runs on with it; the next start loads the
      // old one, which an admin renews again.
      if (this.keep(next)) {
        Errors.log('group: kept a new member certificate or root');
      }
    };
    this.join.onJoined = (j: Membership) => {
      this.membership = j;
      this.startMember().then(() => {
        // Joined from afar: sync away from home goes on, and the member
        // offers its tunnel key to the hub through the invitation's guest
        // tunnel until the hub answers.
        if (this.join.byInvite) {
          this.member.joinedByInvite(this.join.invitation());
        }
      });
    };
  }

  isAdmin(): boolean {
    return this.membership !== undefined && this.membership.isAdmin();
  }

  isRoot(): boolean {
    return this.membership !== undefined && this.membership.isRoot();
  }

  show(error: string): void {
    this.error = error;
  }

  // Starts the member once the phone has a group, with the timers of
  // renewals and of a waiting claim.
  async startMember(): Promise<void> {
    const m = this.membership;
    if (m === undefined || this.member.running) {
      return;
    }
    await this.member.start(m, this.dir, phoneName());
    if (!this.member.running) {
      return;
    }
    const shared = this.pending;
    this.pending = undefined;
    if (shared !== undefined) {
      await this.send(shared);
    }
    if (this.renewTimer < 0) {
      this.renewTimer = setInterval(() => {
        this.renew();
      }, RENEW_EVERY_MS);
      setTimeout(() => {
        this.renew();
      }, RENEW_FIRST_MS);
    }
    await this.restoreServers();
    if (m.member.claim !== undefined && m.member.claim.length > 0) {
      this.startClaimTimer();
      setTimeout(() => {
        this.finishTakeover();
      }, CLAIM_FIRST_MS);
    }
  }

  // Sends what another app shared, now or once the member runs.
  async share(shared: Shared): Promise<void> {
    if (!this.member.running) {
      this.pending = shared;
      return;
    }
    await this.send(shared);
  }

  private async send(shared: Shared): Promise<void> {
    if (shared.text.length > 0) {
      await this.member.sendText(shared.text);
    }
    if (shared.files.length > 0) {
      await this.member.sendFiles(shared.files, shared.types);
    }
  }

  async stopMember(): Promise<void> {
    clearInterval(this.renewTimer);
    this.renewTimer = -1;
    this.stopClaimTimer();
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

  private async newGroup(): Promise<Failure | undefined> {
    const seal = this.sealKey();
    if (seal instanceof Failure) {
      return seal;
    }
    const member = await ensure('member');
    if (member.ok === undefined) {
      return member.failure;
    }
    const root = await ensure('admin');
    if (root.ok === undefined) {
      return root.failure;
    }
    const request: Record<string, Object> = {
      'name': phoneName(),
      'os': OS,
      'store': STORE,
      'public': member.ok.public,
      'root_public': root.ok.public,
      'seal': seal
    };
    const group = read<Joined>(await cbb.groupNew(JSON.stringify(request)), 'group');
    if (group.ok === undefined) {
      return group.failure;
    }
    const m = new Membership(group.ok);
    m.member.root = true;
    const saved = m.save(this.dir);
    if (saved !== undefined) {
      return saved;
    }
    Errors.log(`group: made ${m.groupTag()} as its root`);
    this.membership = m;
    return undefined;
  }

  private sealKey(): string | Failure {
    const secret = sealSecret(this.dir);
    if (secret instanceof Failure) {
      return secret;
    }
    const seal = call<SealKey>('seal_public', { 'secret': secret } as Record<string, Object>);
    if (seal.ok === undefined) {
      return seal.failure as Failure;
    }
    return seal.ok.key;
  }

  // Listens for the device that scans this phone's QR code; with admin, the
  // phone asks to be an admin.
  startJoin(admin: boolean): void {
    this.join.start(this.dir, admin);
  }

  startJoinByInvite(text: string): void {
    this.join.startInvite(this.dir, text);
  }

  startAdmit(qr: string, makeAdmin: boolean): void {
    if (this.membership !== undefined) {
      this.admit.admit(qr, this.member, this.membership, makeAdmin);
    }
  }

  startInvite(seconds: number): void {
    if (this.membership !== undefined) {
      this.invite.open(this.member, this.membership, seconds);
    }
  }

  // An admin's change to a device (remove, rename, thaw, make_admin,
  // sync_on, sync_off, resolve) or command for it (mute, unmute), signed
  // with the admin key; forMinutes: how long a mute or a sync off lasts, 0
  // for until undone. True once the change is in the records or the device
  // took the command.
  async manage(action: string, device: string, name?: string, forMinutes?: number, records?: string[]): Promise<boolean> {
    const extra: Record<string, Object> = { 'name': name ?? '', 'for_ms': (forMinutes ?? 0) * 60000 };
    if (records !== undefined) {
      extra['records'] = records;
    }
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
      'method': method, 'kind': secret ? 'secret' : 'text', 'text': text, 'enter': enter, 'timeout_ms': 10000 + typed
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
      'method': 'paste', 'kind': 'media', 'text': made.ok, 'enter': enter, 'timeout_ms': 35000
    } as Record<string, Object>);
    return a !== undefined;
  }

  // The root's decision on an alert: voids the records it names.
  resolve(records: string[]): Promise<boolean> {
    return this.manage('resolve', '', '', 0, records);
  }

  async setTakeoverDelay(hours: number): Promise<void> {
    if (this.isRoot()) {
      await this.runManage('takeover_delay', '', { 'delay_ms': hours * 3600000 } as Record<string, Object>);
    }
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

  async handOver(device: string): Promise<void> {
    if (this.isRoot()) {
      await this.runManage('hand_over', device, {} as Record<string, Object>);
    }
  }

  async makeRecovery(): Promise<void> {
    if (!this.isRoot()) {
      return;
    }
    const a = await this.runManage('make_recovery', '', {} as Record<string, Object>);
    if (a !== undefined) {
      this.recoveryText = a.text ?? '';
      this.recoveryModules = a.modules ?? [];
    }
  }

  // The sheet is shown once; nothing of the key stays in the app.
  forgetRecovery(): void {
    this.recoveryText = '';
    this.recoveryModules = [];
  }

  async removeRecovery(): Promise<void> {
    if (this.isRoot()) {
      await this.runManage('remove_recovery', '', {} as Record<string, Object>);
    }
  }

  // Signs action for device with extra in the request; fallback is tried
  // when the action is refused, as a claim tries take_over when the root
  // handed the group to nobody. Shows a failure and answers undefined.
  private async runManage(action: string, device: string, extra: Record<string, Object>, fallback?: string,
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
    if (!m.isRoot() && m.member.admin_ca !== undefined && request['admin_ca'] === undefined) {
      request['admin_ca'] = m.member.admin_ca;
    }
    let a: Result<ManageAnswer> = await this.member.manage<ManageAnswer>(request);
    if (a.ok === undefined && fallback !== undefined) {
      Errors.log(`manage: ${action} refused (${(a.failure as Failure).details}); trying ${fallback}`);
      request['action'] = fallback;
      a = await this.member.manage<ManageAnswer>(request);
    }
    this.busy = false;
    let failure = a.failure;
    // A command the device refused answers with its reason.
    const result = a.ok?.result;
    if (failure === undefined && result !== undefined && result.status !== 'done') {
      failure = new Failure(t('error_command_refused'), `manage: ${result.status ?? ''}: ${result.reason ?? ''}`);
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

  // As an admin, renews the member certificates that are due, the devices'
  // connected and the phone's own, quietly: only the log says.
  private async renew(): Promise<void> {
    if (this.busy || !this.isAdmin() || !this.member.running) {
      return;
    }
    const a = await this.runManage('renew', '', {} as Record<string, Object>, undefined, true);
    if (a !== undefined && (a.renewed ?? 0) > 0) {
      Errors.log(`renew: renewed ${a.renewed} member certificates`);
    }
    // The root key signs the next period of the group's server keys
    // (docs/protocol.md, section 18) when it is due.
    if (this.isRoot() && this.member.periodDue) {
      if (await this.runManage('period', '', {} as Record<string, Object>, undefined, true) !== undefined) {
        Errors.log('servers: signed the next period of the server keys');
        this.member.periodDue = false;
      }
    }
  }

  // This phone as the group's hub and its blind relay, as the user set
  // them; the core keeps neither, so they are set again each time the
  // member starts.
  hubWanted(): boolean {
    return this.prefs !== undefined && this.prefs.getSync('hub_on', false) as boolean;
  }

  hubForwarder(): string {
    return this.prefs !== undefined ? this.prefs.getSync('hub_forwarder', '') as string : '';
  }

  hubKey(): string {
    return this.prefs !== undefined ? this.prefs.getSync('hub_key', '') as string : '';
  }

  hubDisguise(): string {
    return this.prefs !== undefined ? this.prefs.getSync('hub_disguise', 'plain') as string : 'plain';
  }

  relayAddress(): string {
    return this.prefs !== undefined ? this.prefs.getSync('relay', '') as string : '';
  }

  relayKey(): string {
    return this.prefs !== undefined ? this.prefs.getSync('relay_key', '') as string : '';
  }

  // Makes this phone a hub of the group, through the forwarder at
  // forwarder with key (both empty for the project's), or stops it being
  // one (anyway: also when it is the group's only hub). Shows why not,
  // except that it is the only hub, which it answers for the user to decide.
  async setHub(on: boolean, forwarder: string, key: string, disguise: string, anyway: boolean): Promise<Failure | undefined> {
    const own = forwarder.length > 0;
    const failure = await this.member.setHub(on, own ? forwarder : PROJECT_FORWARDER, own ? key : PROJECT_KEY, disguise, anyway);
    if (failure !== undefined) {
      if (on || anyway || !failure.details.includes(ONLY_HUB)) {
        this.show(Errors.shown(failure));
      }
      return failure;
    }
    this.prefs?.putSync('hub_on', on);
    if (on) {
      this.prefs?.putSync('hub_forwarder', forwarder);
      this.prefs?.putSync('hub_key', key);
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

  // Meets the group at the blind relay at relay with key, or leaves it
  // with both empty. Shows why not.
  async setRelay(relay: string, key: string): Promise<boolean> {
    const failure = await this.member.setRelay(relay, key);
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      return false;
    }
    this.prefs?.putSync('relay', relay);
    this.prefs?.putSync('relay_key', key);
    this.prefs?.flush();
    this.show('');
    return true;
  }

  private async restoreServers(): Promise<void> {
    if (this.hubWanted() && this.isAdmin()) {
      const forwarder = this.hubForwarder();
      const own = forwarder.length > 0;
      const failure = await this.member.setHub(true, own ? forwarder : PROJECT_FORWARDER, own ? this.hubKey() : PROJECT_KEY,
        this.hubDisguise(), false);
      if (failure !== undefined) {
        Errors.log(`servers: the hub did not start again: ${failure.message} (${failure.details})`);
      }
    }
    const relay = this.relayAddress();
    if (relay.length > 0) {
      const failure = await this.member.setRelay(relay, this.relayKey());
      if (failure !== undefined) {
        Errors.log(`servers: the relay was not met again: ${failure.message} (${failure.details})`);
      }
    }
  }

  // Keeps next as the membership, or shows why it could not.
  private keep(next: Membership): boolean {
    const failure = next.saveIdentity(this.dir);
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      return false;
    }
    this.membership = next;
    return true;
  }

  // Takes the group over from its lost root (cbb_core::takeover): a new
  // root CA for the admin key, kept first, and the claim, as the root
  // handed the group to this phone or else after the group's delay.
  async takeOver(device: string): Promise<void> {
    const m = this.membership;
    if (this.busy || m === undefined || !m.isAdmin() || m.isRoot() || (m.member.claim ?? '').length > 0 || !this.member.running) {
      return;
    }
    // The new root is the admin key itself, which stays in HUKS: a root CA
    // for it first, kept before the claim goes out, so that a claim never
    // takes effect for a root this phone lost.
    const rootCa = await this.newRootCa();
    if (rootCa === undefined) {
      return;
    }
    const claim = await this.runManage('take_handed_over', device,
      { 'root_ca': rootCa, 'admin_ca': m.member.admin_ca ?? '' } as Record<string, Object>, 'take_over');
    if (claim === undefined) {
      this.dropClaim();
      return;
    }
    Errors.log(`takeover: claimed the group from ${device}`);
    this.claimState = 'pending';
    this.startClaimTimer();
    this.finishTakeover();
  }

  // The root CA of the admin key as a new root, kept as the claim's.
  private async newRootCa(): Promise<string | undefined> {
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.show(Errors.shown(key.failure as Failure));
      return undefined;
    }
    const a = read<ManageAnswer>(await this.manageAsRestorer({ 'action': 'root_ca', 'public': key.ok.public }), 'takeover');
    const rootCa = a.ok?.root_ca ?? '';
    if (a.ok === undefined || rootCa.length === 0 || this.membership === undefined) {
      if (a.failure !== undefined) {
        this.show(Errors.shown(a.failure));
      }
      return undefined;
    }
    const next = this.membership.copy();
    next.member.claim = rootCa;
    return this.keep(next) ? rootCa : undefined;
  }

  private dropClaim(): void {
    if (this.membership === undefined) {
      return;
    }
    const next = this.membership.copy();
    next.member.claim = undefined;
    this.keep(next);
  }

  private startClaimTimer(): void {
    if (this.claimTimer < 0) {
      this.claimTimer = setInterval(() => {
        this.finishTakeover();
      }, CLAIM_EVERY_MS);
    }
  }

  private stopClaimTimer(): void {
    if (this.claimTimer >= 0) {
      clearInterval(this.claimTimer);
      this.claimTimer = -1;
    }
  }

  // While the phone has a claim: where it stands, and once it took effect,
  // the phone as the group's root.
  private async finishTakeover(): Promise<void> {
    const m = this.membership;
    if (m === undefined || (m.member.claim ?? '').length === 0) {
      this.stopClaimTimer();
      return;
    }
    if (this.busy || !this.member.running) {
      return;
    }
    const extra: Record<string, Object> = {
      'root_ca': m.member.claim ?? '',
      'name': phoneName(),
      'os': OS,
      'store': STORE
    };
    const seal = this.sealKey();
    if (!(seal instanceof Failure)) {
      extra['seal'] = seal;
    }
    // Tried again in a minute; the log says why.
    const a = await this.runManage('finish_takeover', '', extra, undefined, true);
    if (a === undefined) {
      return;
    }
    const state = a.state ?? '';
    this.claimLeftMs = a.left_ms ?? 0;
    if (state === 'effective') {
      const next = m.copy();
      next.member.root = true;
      next.member.admin_ca = undefined;
      next.member.claim = undefined;
      next.member.cert = a.cert ?? next.member.cert;
      next.member.issuer = undefined;
      if (!this.keep(next)) {
        return;
      }
      this.stopClaimTimer();
      Errors.log("takeover: this phone is the group's root now");
    } else if (state === 'cancelled' || state === 'void') {
      const next = m.copy();
      next.member.claim = undefined;
      if (!this.keep(next)) {
        return;
      }
      this.stopClaimTimer();
      Errors.log(`takeover: the claim is ${state}`);
      // A phone that restored the group from its sheet is no admin.
      const admin = next.isAdmin();
      const cancelled = state === 'cancelled';
      const shown = admin ? (cancelled ? t('takeover_cancelled_admin') : t('takeover_void_admin')) :
        (cancelled ? t('takeover_cancelled_restore') : t('takeover_void_restore'));
      if (!admin) {
        this.restoreState = 'failed';
      }
      this.show(Errors.shown(new Failure(shown, `takeover: the claim is ${state}`)));
    }
    this.claimState = state;
  }

  // Restores the group of the recovery sheet's QR code on this new phone
  // (cbb_restore), then claims it with the sheet's key for a new root CA of
  // the admin key, as takeOver does. A phone that restored the group but
  // whose claim failed only claims again.
  async restore(sheet: string): Promise<void> {
    if (this.busy) {
      return;
    }
    const m = this.membership;
    if (m !== undefined) {
      if (!m.isAdmin() && (m.member.claim ?? '').length === 0 && this.member.running) {
        await this.claimWithSheet(sheet);
      }
      return;
    }
    this.busy = true;
    this.restoreState = 'restoring';
    this.show('');
    const key = await ensure('member');
    if (key.ok === undefined) {
      this.busy = false;
      this.show(Errors.shown(key.failure as Failure));
      this.restoreState = 'failed';
      return;
    }
    const request: Record<string, Object> = { 'sheet': sheet.trim(), 'public': key.ok.public, 'name': phoneName(), 'os': OS };
    const answer = read<Restored>(await cbb.restore(JSON.stringify(request)), 'restore');
    this.busy = false;
    if (answer.ok === undefined) {
      this.show(Errors.shown(restoreFailure(answer.failure as Failure)));
      this.restoreState = 'failed';
      return;
    }
    const restored = new Membership(answer.ok);
    restored.member.root = false;
    const failure = restored.save(this.dir);
    if (failure !== undefined) {
      this.show(Errors.shown(failure));
      this.restoreState = 'failed';
      return;
    }
    Errors.log(`restore: restored ${restored.groupTag()} as ${restored.member.device} from ${answer.ok.addr ?? ''}`);
    this.membership = restored;
    await this.startMember();
    await this.claimWithSheet(sheet);
  }

  private async claimWithSheet(sheet: string): Promise<void> {
    if (!this.member.running) {
      this.show(Errors.shown(new Failure(t('error_not_running'), 'restore: no member')));
      this.restoreState = 'failed';
      return;
    }
    this.restoreState = 'claiming';
    // The membership of a restored phone is no admin's: the core signs the
    // root CA and the claim with the admin key as the claim's new root.
    const rootCa = await this.newRootCa();
    if (rootCa === undefined) {
      this.restoreState = 'failed';
      return;
    }
    const key = await ensure('admin');
    const claim = read<ManageAnswer>(await this.manageAsRestorer(
      { 'action': 'recover_with_sheet', 'sheet': sheet.trim(), 'root_ca': rootCa, 'public': key.ok?.public ?? '' }), 'restore');
    if (claim.ok === undefined) {
      this.dropClaim();
      this.show(Errors.shown(restoreFailure(claim.failure as Failure)));
      this.restoreState = 'failed';
      return;
    }
    Errors.log('restore: claimed the group with the recovery key');
    this.claimState = 'pending';
    this.show('');
    this.restoreState = 'claimed';
    this.startClaimTimer();
    this.finishTakeover();
  }

  // A restoring phone is no admin yet, so its root CA and claim skip
  // runManage's check.
  private async manageAsRestorer(request: Record<string, Object>): Promise<string> {
    const h = this.member.core();
    if (h === null) {
      return '';
    }
    this.busy = true;
    const answer = await cbb.memberManage(h, JSON.stringify(request), 'admin');
    this.busy = false;
    return answer;
  }

  resetRestore(): void {
    if (this.restoreState !== 'restoring' && this.restoreState !== 'claiming') {
      this.restoreState = '';
    }
  }

  // Leaves the group on this phone: stops the member and deletes the
  // membership and the keys (D-83). The group still lists the phone until
  // an admin removes it.
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
    this.claimState = '';
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
