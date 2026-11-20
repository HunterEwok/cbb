// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Pairing in a group of 0.6 (docs/apps.md, "Screens"; docs/protocol.md,
// section 3). PairWindow: an admin phone opens its member's pairing window
// (ffi's cbb_window_*), shows its QR code and has the core announce it by
// mDNS; the code a dialing device shows waits for the person's "they
// match". Joiner: a phone without a group finds the one window announced at
// home, or dials the window whose QR code it scanned (cbb_joiner_*), shows
// the same code, and keeps the group's set where its member then starts.
// The Aurora app's PairWindow and Joiner, ported.

import cbb, { Handle } from 'libcbb_napi.so';
import { read } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { t } from '../core/Text';
import { Member } from './Member';
import { qrAddresses } from './Net';

// How often the page's state is asked of the core, as Invite's.
const POLL_MS: number = 300;
// The QR code text of a pairing window.
export const WINDOW_QR: string = 'cbb://pair?';

interface Opened {
  qr?: string;
  modules?: string[];
  expires?: number;
}

interface StateError {
  message?: string;
  details?: string;
}

interface Asking {
  device?: string;
  name?: string;
  os?: string;
  code?: string;
}

interface WindowState {
  version?: number;
  state?: string;
  joining?: Asking;
  name?: string;
  device?: string;
  error?: StateError;
}

interface JoinerState {
  version?: number;
  state?: string;
  shown?: Asking;
  group?: string;
  device?: string;
  error?: StateError;
}

function failureOf(e: StateError | undefined, what: string): Failure {
  return new Failure(e?.message ?? t('error_broken'), `${what}: ${e?.details ?? ''}`);
}

@ObservedV2
export class PairWindow {
  // idle, preparing (finding the admin key), open, joining (the person is
  // asked), done (a device joined; the window stays open for the next),
  // closed (its time is up) or failed.
  @Trace state: string = 'idle';
  @Trace qr: string = '';
  // The QR code's rows, '1' for a dark module.
  @Trace modules: string[] = [];
  // The device that dialed and the code both screens show, while asked.
  @Trace joiningName: string = '';
  @Trace code: string = '';
  // The name of the last device that joined.
  @Trace joined: string = '';
  @Trace error: string = '';

  private handle: Handle | null = null;
  private timer: number = -1;
  private version: number = 0;
  private polling: boolean = false;

  // Opens the window on member with the admin key (the root's on the root),
  // which signs after the user's consent.
  async open(member: Member): Promise<void> {
    await this.free();
    this.error = '';
    this.joined = '';
    this.state = 'preparing';
    const core = member.core();
    if (core === null) {
      this.fail(new Failure(t('error_not_running'), 'window: no member'));
      return;
    }
    const addrs = qrAddresses().map((a: string) => a.substring(0, a.lastIndexOf(':')));
    if (addrs.length === 0) {
      this.fail(new Failure(t('error_window_wifi'), 'window: no private IPv4 address'));
      return;
    }
    const listened = await member.listen();
    if (listened !== undefined) {
      this.fail(listened);
      return;
    }
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return;
    }
    if (this.state !== 'preparing') {
      return; // closed while the key was found
    }
    // HarmonyOS gives the app no DNS-SD of its own here: the core announces it.
    const request: Record<string, Object> = { 'public': key.ok.public, 'addrs': addrs, 'expires': 0, 'mdns': true };
    const made = await cbb.windowNew(core, JSON.stringify(request), 'admin');
    if (this.state !== 'preparing') {
      if (made.handle !== null) {
        await cbb.windowFree(made.handle);
      }
      return;
    }
    const answer = read<Opened>(made.answer, 'window');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'window: no window'));
      return;
    }
    this.handle = made.handle;
    this.qr = answer.ok.qr ?? '';
    this.modules = answer.ok.modules ?? [];
    this.version = 0;
    Errors.log(`window: open for ${answer.ok.expires ?? 0} s`);
    this.state = 'open';
    this.timer = setInterval(() => {
      this.poll();
    }, POLL_MS);
  }

  // The person's answer about the code.
  answer(yes: boolean): void {
    if (this.handle !== null) {
      cbb.windowAnswer(this.handle, yes);
    }
  }

  // Closes it, or forgets how the last one ended.
  async close(): Promise<void> {
    this.state = 'idle';
    await this.free();
    this.error = '';
    this.joined = '';
  }

  private async poll(): Promise<void> {
    const h = this.handle;
    if (h === null || this.polling) {
      return;
    }
    this.polling = true;
    const st = read<WindowState>(await cbb.windowNext(h, this.version, 0), 'window');
    this.polling = false;
    if (this.handle !== h) {
      return;
    }
    if (st.ok === undefined) {
      this.fail(st.failure as Failure);
      return;
    }
    const version = st.ok.version ?? 0;
    if (version <= this.version) {
      return;
    }
    this.version = version;
    const j = st.ok.joining ?? ({} as Asking);
    this.joiningName = j.name ?? '';
    this.code = j.code ?? '';
    const state = st.ok.state ?? '';
    if (state === 'done') {
      this.joined = st.ok.name ?? '';
      this.error = '';
      Errors.log(`window: ${st.ok.device ?? ''} joined`);
      this.state = 'done';
      return;
    }
    if (state === 'failed') {
      // That attempt failed; the window stays open for another.
      this.error = Errors.shown(failureOf(st.ok.error, 'window'));
      this.state = 'open';
      return;
    }
    if (state === 'closed') {
      await this.free();
      this.state = 'closed';
      return;
    }
    if (state === 'joining') {
      this.error = '';
    }
    this.state = state;
  }

  private fail(f: Failure): void {
    this.free();
    this.error = Errors.shown(f);
    this.state = 'failed';
  }

  private async free(): Promise<void> {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    const h = this.handle;
    this.handle = null;
    this.qr = '';
    this.modules = [];
    this.joiningName = '';
    this.code = '';
    if (h !== null) {
      await cbb.windowFree(h);
    }
  }
}

@ObservedV2
export class Joiner {
  // idle, dialing, joining (the person is asked), done or failed.
  @Trace state: string = 'idle';
  // The member that admits the phone, and the code both screens show.
  @Trace memberName: string = '';
  @Trace code: string = '';
  @Trace error: string = '';

  // The phone joined the group (its ID in hex) as the device device.
  onJoined: (group: string, device: string) => void = () => {};

  private handle: Handle | null = null;
  private timer: number = -1;
  private version: number = 0;
  private polling: boolean = false;

  // Joins as the phone named name with system os, keeping the set in dir;
  // qr is a window's QR code text, or empty to find the one window
  // announced at home.
  async start(dir: string, qr: string, name: string, os: string): Promise<void> {
    await this.free();
    this.error = '';
    this.state = 'dialing';
    const key = await ensure('member');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return;
    }
    const request: Record<string, Object> = { 'dir': dir, 'qr': qr.trim(), 'name': name, 'os': os, 'public': key.ok.public };
    const made = await cbb.joinerNew(JSON.stringify(request));
    if (this.state !== 'dialing') {
      if (made.handle !== null) {
        await cbb.joinerFree(made.handle);
      }
      return;
    }
    const answer = read<JoinerState>(made.answer, 'joiner');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'joiner: no joiner'));
      return;
    }
    this.handle = made.handle;
    this.version = 0;
    Errors.log(qr.length === 0 ? 'joiner: looking for a window at home' : 'joiner: dialing the window of the code');
    this.timer = setInterval(() => {
      this.poll();
    }, POLL_MS);
  }

  answer(yes: boolean): void {
    if (this.handle !== null) {
      cbb.joinerAnswer(this.handle, yes);
    }
  }

  async stop(): Promise<void> {
    this.state = 'idle';
    await this.free();
    this.error = '';
  }

  private async poll(): Promise<void> {
    const h = this.handle;
    if (h === null || this.polling) {
      return;
    }
    this.polling = true;
    const st = read<JoinerState>(await cbb.joinerNext(h, this.version, 0), 'joiner');
    this.polling = false;
    if (this.handle !== h) {
      return;
    }
    if (st.ok === undefined) {
      this.fail(st.failure as Failure);
      return;
    }
    const version = st.ok.version ?? 0;
    if (version <= this.version) {
      return;
    }
    this.version = version;
    const shown = st.ok.shown ?? ({} as Asking);
    this.memberName = shown.name ?? '';
    this.code = shown.code ?? '';
    const state = st.ok.state ?? '';
    if (state === 'done') {
      const group = st.ok.group ?? '';
      const device = st.ok.device ?? '';
      await this.free();
      Errors.log(`joiner: joined ${group.substring(0, 16)} as ${device}`);
      this.state = 'done';
      this.onJoined(group, device);
      return;
    }
    if (state === 'failed') {
      this.fail(failureOf(st.ok.error, 'joiner'));
      return;
    }
    this.state = state;
  }

  private fail(f: Failure): void {
    this.free();
    this.error = Errors.shown(f);
    this.state = 'failed';
  }

  private async free(): Promise<void> {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    const h = this.handle;
    this.handle = null;
    this.memberName = '';
    this.code = '';
    if (h !== null) {
      await cbb.joinerFree(h);
    }
  }
}
