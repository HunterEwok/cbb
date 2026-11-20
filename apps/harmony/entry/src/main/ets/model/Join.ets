// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group by a remote invitation (docs/protocol.md, section 12):
// the core (ffi's cbb_join_*) starts the invitation's guest tunnel, the
// phone dials its loopback port, and the inviting admin admits the phone by
// the fingerprint it shows. This class only moves the bytes, as the Aurora
// app's Join does. Joining at home goes through the pairing window
// (Pairing06.ets).

import cbb, { Handle } from 'libcbb_napi.so';
import { socket } from '@kit.NetworkKit';
import { call, read } from '../core/Core';
import { fromBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { Joined, Membership, sealSecret } from '../core/Membership';
import { OS, phoneName } from '../core/Phone';
import { t } from '../core/Text';
import { Dialed } from './Net';

// How many times a join by an invitation dials its guest tunnel, and the
// pause between the attempts, as the other phones' apps.
const INVITE_ATTEMPTS: number = 5;
const INVITE_PAUSE_MS: number = 2000;

interface SealKey {
  key: string;
}

interface Made {
  device?: string;
  port?: number;
  fingerprint?: string;
}

interface StepError {
  message?: string;
  details?: string;
}

interface Step {
  state?: string;
  send?: string;
  error?: StepError;
  joined?: Joined;
}

// One way the bytes go: the connection the phone dialed.
interface Wire {
  send: (data: ArrayBuffer) => void;
  close: () => void;
}

@ObservedV2
export class Join {
  // idle, dialing, joining (the invitation's hub answered), joined or
  // failed.
  @Trace state: string = 'idle';
  @Trace error: string = '';
  // The words the phone shows while it joins by an invitation, which the
  // inviting admin compares.
  @Trace fingerprint: string = '';

  // The phone joined; the membership is saved.
  onJoined: (m: Membership) => void = () => {};

  private handle: Handle | null = null;
  private wire: Wire | null = null;
  private invite: string = '';
  private invitePort: number = 0;
  private inviteAttempts: number = 0;
  private dir: string = '';

  // The invitation the phone joins by, until it joined.
  invitation(): string {
    return this.invite;
  }

  // Joins by a remote invitation's text, which the user accepted.
  async startInvite(dir: string, invite: string): Promise<void> {
    await this.stop();
    this.dir = dir;
    this.inviteAttempts = 0;
    this.error = '';
    this.fingerprint = '';
    this.invite = invite.trim();
    const request = await this.request();
    if (request === undefined) {
      return;
    }
    request['invite'] = this.invite;
    const made = await cbb.joinNew(JSON.stringify(request));
    const answer = read<Made>(made.answer, 'join');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'join: no joiner'));
      return;
    }
    this.handle = made.handle;
    this.invitePort = answer.ok.port ?? 0;
    this.fingerprint = answer.ok.fingerprint ?? '';
    if (this.invitePort === 0) {
      this.fail(new Failure(t('error_broken'), "join: the invitation's tunnel has no port"));
      return;
    }
    Errors.log(`join: by an invitation, as ${answer.ok.device ?? ''}, through the guest tunnel on port ${this.invitePort}`);
    this.state = 'dialing';
    this.dialInvite();
  }

  async stop(): Promise<void> {
    if (this.wire !== null) {
      this.wire.close();
      this.wire = null;
    }
    const h = this.handle;
    this.handle = null;
    if (h !== null) {
      await cbb.joinFree(h);
    }
    if (this.state === 'dialing' || this.state === 'joining') {
      this.state = 'idle';
    }
  }

  // The request: the phone's name, system, key and seal.
  private async request(): Promise<Record<string, Object> | undefined> {
    const secret = sealSecret(this.dir);
    if (secret instanceof Failure) {
      this.fail(secret);
      return undefined;
    }
    const seal = call<SealKey>('seal_public', { 'secret': secret } as Record<string, Object>);
    if (seal.ok === undefined) {
      this.fail(seal.failure as Failure);
      return undefined;
    }
    const key = await ensure('member');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return undefined;
    }
    const request: Record<string, Object> = {
      'name': phoneName(),
      'os': OS,
      'public': key.ok.public,
      'seal': seal.ok.key
    };
    return request;
  }

  private async dialInvite(): Promise<void> {
    if (this.handle === null || this.invite.length === 0 || this.wire !== null) {
      return;
    }
    this.inviteAttempts++;
    const d = new Dialed();
    const wire: Wire = {
      send: (data: ArrayBuffer) => {
        d.send(data);
      },
      close: () => {
        d.close();
      }
    };
    this.wire = wire;
    d.onData = (data: ArrayBuffer) => {
      if (this.wire !== wire) {
        return;
      }
      if (this.state === 'dialing') {
        this.state = 'joining';
      }
      this.feed(data);
    };
    d.onClose = (why: string) => {
      if (this.wire === wire) {
        Errors.log(`join: the invitation's tunnel: ${why}`);
        this.wire = null;
        this.inviteAttemptEnded();
      }
    };
    try {
      const loopback: socket.NetAddress = { address: '127.0.0.1', port: this.invitePort, family: 1 };
      await d.dial(loopback, 5000);
    } catch (e) {
      if (this.wire === wire) {
        Errors.log(`join: dialing the invitation's tunnel: ${String(e)}`);
        this.wire = null;
        d.close();
        this.inviteAttemptEnded();
      }
      return;
    }
    if (this.handle === null || this.wire !== wire) {
      return;
    }
    const first = read<Step>(await cbb.joinAccept(this.handle), 'join');
    if (first.ok === undefined) {
      this.fail(first.failure as Failure);
      return;
    }
    wire.send(fromBase64(first.ok.send));
  }

  private inviteAttemptEnded(): void {
    if (this.handle === null || this.state === 'joined' || this.state === 'failed') {
      return;
    }
    if (this.inviteAttempts >= INVITE_ATTEMPTS) {
      if (!cbb.joinAnswered(this.handle)) {
        this.fail(new Failure(t('error_invite_no_hub'), "join: the invitation's hub never answered through the tunnel"));
      } else {
        this.fail(new Failure(t('error_invite_failed'), `join: ${INVITE_ATTEMPTS} attempts through the invitation failed`));
      }
      return;
    }
    this.state = 'dialing';
    setTimeout(() => {
      this.dialInvite();
    }, INVITE_PAUSE_MS);
  }

  private async feed(data: ArrayBuffer): Promise<void> {
    const h = this.handle;
    const wire = this.wire;
    if (h === null || wire === null) {
      return;
    }
    const step = read<Step>(await cbb.joinFeed(h, data, 0), 'join');
    if (step.ok === undefined) {
      this.fail(step.failure as Failure);
      return;
    }
    wire.send(fromBase64(step.ok.send));
    const state = step.ok.state ?? '';
    if (state === 'failed') {
      const e = step.ok.error ?? ({} as StepError);
      const why = `${e.message ?? ''}: ${e.details ?? ''}`;
      Errors.log(`join: an attempt failed: ${why}`);
      this.wire = null;
      wire.close();
      this.inviteAttemptEnded();
      return;
    }
    if (state !== 'joined' || step.ok.joined === undefined) {
      return;
    }
    const m = new Membership(step.ok.joined);
    const failure = m.save(this.dir);
    const last = read<Step>(await cbb.joinFinish(h, failure === undefined), 'join');
    // Let go of the connection first: its close, which may come at once,
    // must not count as a failed attempt.
    this.wire = null;
    if (last.ok !== undefined) {
      wire.send(fromBase64(last.ok.send));
    }
    setTimeout(() => {
      wire.close();
    }, 500);
    if (failure !== undefined) {
      this.fail(failure);
      return;
    }
    Errors.log(`join: joined the group ${m.groupTag()} as ${m.member.device}${m.member.admin_ca !== undefined ? ', an admin' : ''}`);
    await this.stop();
    this.state = 'joined';
    this.onJoined(m);
  }

  private fail(f: Failure): void {
    this.error = Errors.shown(f);
    this.stop();
    this.state = 'failed';
  }
}
