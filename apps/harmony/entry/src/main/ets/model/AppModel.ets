// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the pages show and do: the phone's group, its member, joining,
// adding devices, invitations, the admin's changes, restoring from the
// recovery sheet, taking the group over, the settings. One for the app, as
// the Aurora app's App.

import cbb from 'libcbb_napi.so';
import { preferences } from '@kit.ArkData';
import { call, read, Result } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure, forget } from '../core/Keys';
import { Joined, Membership, sealSecret } from '../core/Membership';
import { OS, phoneName, STORE } from '../core/Phone';
import { t } from '../core/Text';
import { Admit } from './Admit';
import { Events } from './Events';
import { Invite } from './Invite';
import { Join } from './Join';
import { Device, Member } from './Member';
import { Shared } from '../common/Share';

// Renewals are due months ahead, so a look every few hours, and one a
// minute after the member starts, once it reached its peers, is plenty.
const RENEW_EVERY_MS: number = 6 * 3600 * 1000;
const RENEW_FIRST_MS: number = 60 * 1000;
// A waiting claim is looked at every minute, and first once the member had
// time to reach its peers.
const CLAIM_EVERY_MS: number = 60 * 1000;
const CLAIM_FIRST_MS: number = 10 * 1000;
const ARRANGEMENT_KEY: string = 'arrangement';

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

interface ViewCollection {
  id: string;
  name: string;
  devices: string[];
}

interface ViewItem {
  device?: string;
  collection?: ViewCollection;
}

interface Stored {
  items?: Object[];
}

interface Arranged {
  view?: ViewItem[];
  stored?: Stored;
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

  readonly member: Member = new Member();
  readonly join: Join = new Join();
  readonly admit: Admit = new Admit();
  readonly invite: Invite = new Invite();
  readonly events: Events = new Events();

  private dir: string = '';
  private prefs: preferences.Preferences | undefined = undefined;
  private renewTimer: number = -1;
  private claimTimer: number = -1;
  private arrangeIds: string[] = [];
  // What was shared to the app before the member ran.
  private pending: Shared | undefined = undefined;

  init(dir: string, prefs: preferences.Preferences): void {
    this.dir = dir;
    this.prefs = prefs;
    this.events.init(prefs);
    this.deviceList = prefs.getSync('device_list', false) as boolean;
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
    this.prefs?.deleteSync(ARRANGEMENT_KEY);
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

  hasArrangement(): boolean {
    return this.prefs !== undefined && (this.prefs.getSync(ARRANGEMENT_KEY, '') as string).length > 0;
  }

  // The core's arrange call on ids with op: {view, stored}, the stored
  // arrangement kept in the settings; undefined on a refusal, shown.
  private callArrange(ids: string[], prune: boolean, op?: Object): Arranged | undefined {
    const m = this.membership;
    if (m === undefined || this.prefs === undefined) {
      return undefined;
    }
    const text = this.prefs.getSync(ARRANGEMENT_KEY, '') as string;
    const args: Record<string, Object> = { 'group': m.groupTag(), 'devices': ids, 'prune': prune, 'self': m.member.device };
    if (text.length > 0) {
      try {
        args['stored'] = JSON.parse(text) as Object;
      } catch (e) {
        Errors.log(`arrange: the stored arrangement does not read: ${String(e)}`);
      }
    }
    if (op !== undefined) {
      args['op'] = op;
    }
    const a = call<Arranged>('arrange', args);
    if (a.ok === undefined) {
      this.show(Errors.shown(a.failure as Failure));
      return undefined;
    }
    // Until the user changes something nothing is stored (docs/apps.md).
    const next = a.ok.stored;
    if (next === undefined || (next.items ?? []).length === 0) {
      this.prefs.deleteSync(ARRANGEMENT_KEY);
    } else if (JSON.stringify(next) !== text) {
      this.prefs.putSync(ARRANGEMENT_KEY, JSON.stringify(next));
    }
    this.prefs.flush();
    return a.ok;
  }

  // The member's devices in the user's order and collections (docs/apps.md,
  // "Collections and the order of the tiles"); this phone first until the
  // user moves it.
  arranged(devices: Device[]): Tile[] {
    const ids = devices.map((d: Device) => d.device);
    const byId = new Map<string, Device>();
    devices.forEach((d: Device) => {
      byId.set(d.device, d);
    });
    this.arrangeIds = ids;
    const self = this.membership?.member.device ?? '';
    const a = this.callArrange(ids, ids.includes(self));
    if (a === undefined) {
      // The group's order, so the devices still show.
      return devices.map((d: Device) => {
        const tile = new Tile();
        tile.device = d;
        return tile;
      });
    }
    const view: Tile[] = [];
    for (const item of a.view ?? []) {
      const tile = new Tile();
      if (item.device !== undefined) {
        const d = byId.get(item.device);
        if (d === undefined) {
          continue;
        }
        tile.device = d;
      } else if (item.collection !== undefined) {
        tile.kind = 'collection';
        tile.id = item.collection.id;
        tile.name = item.collection.name;
        tile.devices = item.collection.devices.map((id: string) => byId.get(id)).filter((d: Device | undefined) => d !== undefined) as Device[];
      } else {
        continue;
      }
      view.push(tile);
    }
    return view;
  }

  // Applies a change of the arrangement, an operation of the core's arrange
  // call ("move", "into", "out", "new", "rename", "ungroup", "reset").
  arrange(op: Record<string, Object>): boolean {
    const ok = this.callArrange(this.arrangeIds, false, op) !== undefined;
    this.arrangement++;
    return ok;
  }
}

// The app's one model.
export const app: AppModel = new AppModel();
