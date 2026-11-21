// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group of 0.6 from afar by a remote invitation (docs/protocol.md,
// section 12), through ffi's cbb_joiner_* with the invitation's text: the
// phone dials the hub through the invitation's guest tunnel and shows its
// fingerprint, which the inviting admin compares; once admitted, the set is
// kept where the member then starts, and the member reaches the hub through
// that tunnel until the hub's offer comes. The Aurora app's Join, ported; a
// phone joins at home through the pairing window (Pairing06.ets).

import cbb, { Handle } from 'libcbb_napi.so';
import { read } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { t } from '../core/Text';

// How often the page's state is asked of the core, as the window's.
const POLL_MS: number = 300;

interface StateError {
  message?: string;
  details?: string;
}

interface JoinState {
  version?: number;
  state?: string;
  group?: string;
  device?: string;
  fingerprint?: string;
  answered?: boolean;
  error?: StateError;
}

@ObservedV2
export class Join {
  // idle, dialing (until the hub answered through the guest tunnel),
  // joining (waiting for the inviting admin), joined or failed.
  @Trace state: string = 'idle';
  @Trace error: string = '';
  // The words the phone shows while it joins by an invitation, which the
  // inviting admin compares.
  @Trace fingerprint: string = '';

  // The phone joined the group (its ID in hex) as the device device.
  onJoined: (group: string, device: string) => void = () => {};

  private handle: Handle | null = null;
  private timer: number = -1;
  private version: number = 0;
  private polling: boolean = false;
  private answered: boolean = false;

  // Joins by a remote invitation's text, which the user accepted, as the
  // phone named name with system os, keeping the set in dir.
  async startInvite(dir: string, invite: string, name: string, os: string): Promise<void> {
    await this.free();
    this.error = '';
    this.fingerprint = '';
    this.answered = false;
    this.state = 'dialing';
    const key = await ensure('member');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return;
    }
    const request: Record<string, Object> = {
      'dir': dir, 'qr': '', 'invite': invite.trim(), 'name': name, 'os': os, 'public': key.ok.public
    };
    const made = await cbb.joinerNew(JSON.stringify(request));
    if (this.state !== 'dialing') {
      if (made.handle !== null) {
        await cbb.joinerFree(made.handle);
      }
      return;
    }
    const answer = read<JoinState>(made.answer, 'join');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'join: no joiner'));
      return;
    }
    this.handle = made.handle;
    this.fingerprint = answer.ok.fingerprint ?? '';
    this.version = 0;
    Errors.log('join: dialing the hub of the invitation');
    this.timer = setInterval(() => {
      this.poll();
    }, POLL_MS);
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
    const st = read<JoinState>(await cbb.joinerNext(h, this.version, 0), 'join');
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
    this.answered = this.answered || (st.ok.answered ?? false);
    const state = st.ok.state ?? '';
    if (state === 'done') {
      const group = st.ok.group ?? '';
      const device = st.ok.device ?? '';
      await this.free();
      Errors.log(`join: joined ${group.substring(0, 16)} as ${device} by an invitation`);
      this.state = 'joined';
      this.onJoined(group, device);
      return;
    }
    if (state === 'failed') {
      const details = `join: ${st.ok.error?.details ?? ''}`;
      this.fail(this.answered ? new Failure(st.ok.error?.message ?? t('error_broken'), details) :
        new Failure(t('error_invite_no_hub'), details));
      return;
    }
    this.state = this.answered ? 'joining' : 'dialing';
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
    if (h !== null) {
      await cbb.joinerFree(h);
    }
  }
}
