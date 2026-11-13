// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group by the phone's QR code (docs/protocol.md, section 6, "The
// joiner listens"): the phone listens on the member port and shows the QR
// code, the group's phone or computer scans it and dials in, and the core
// (ffi's cbb_join_*) runs the pairing inside its own TLS, signing with the
// key in HUKS. Or by a remote invitation (section 12): the core starts the
// invitation's guest tunnel, the phone dials its loopback port, and the
// inviting admin admits the phone by the fingerprint it shows. This class
// only moves the bytes, as the Aurora app's Join does.

import cbb, { Handle } from 'libcbb_napi.so';
import { socket } from '@kit.NetworkKit';
import { call, read } from '../core/Core';
import { fromBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { Joined, Membership, sealSecret } from '../core/Membership';
import { OS, phoneName } from '../core/Phone';
import { t } from '../core/Text';
import { Dialed, isHome, MEMBER_PORT, qrAddresses } from './Net';

// How many wrong codes a listening join takes (pair::MAX_FAILURES).
const MAX_WRONG_CODES: number = 3;
// How many times a join by an invitation dials its guest tunnel, and the
// pause between the attempts, as the other phones' apps.
const INVITE_ATTEMPTS: number = 5;
const INVITE_PAUSE_MS: number = 2000;

interface SealKey {
  key: string;
}

interface Made {
  device?: string;
  code?: string;
  qr?: string;
  modules?: string[];
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
  wrong_code?: boolean;
  error?: StepError;
  joined?: Joined;
}

// The member port's listener, made once: the system's TCP server has no
// close before API 20, so the app keeps it and lets the join that listens
// now take its connections.
let server: socket.TCPSocketServer | undefined = undefined;
let onConnect: (c: socket.TCPSocketConnection) => void = (c: socket.TCPSocketConnection) => {
  c.close().catch(() => {});
};

async function listen(): Promise<void> {
  if (server !== undefined) {
    return;
  }
  const s: socket.TCPSocketServer = socket.constructTCPSocketServerInstance();
  const any: socket.NetAddress = { address: '0.0.0.0', port: MEMBER_PORT, family: 1 };
  await s.listen(any);
  s.on('connect', (c: socket.TCPSocketConnection) => {
    onConnect(c);
  });
  server = s;
}

// One way the bytes go: a connection the phone took or dialed.
interface Wire {
  send: (data: ArrayBuffer) => void;
  close: () => void;
}

@ObservedV2
export class Join {
  // idle, listening, dialing (by an invitation), joining (a device dialed
  // in, or the invitation's hub answered), joined or failed.
  @Trace state: string = 'idle';
  @Trace code: string = '';
  // The QR code's rows, '1' for a dark module.
  @Trace modules: string[] = [];
  @Trace qr: string = '';
  @Trace error: string = '';
  // The words the phone shows while it joins by an invitation, which the
  // inviting admin compares.
  @Trace fingerprint: string = '';
  @Trace byInvite: boolean = false;

  // The phone joined; the membership is saved.
  onJoined: (m: Membership) => void = () => {};

  private handle: Handle | null = null;
  private wire: Wire | null = null;
  private admin: boolean = false;
  private wrongCodes: number = 0;
  private invite: string = '';
  private invitePort: number = 0;
  private inviteAttempts: number = 0;
  private dir: string = '';

  // The invitation the phone joins by, until it joined.
  invitation(): string {
    return this.invite;
  }

  // Starts listening; with admin, it asks to be an admin, which only the
  // group's root admits.
  async start(dir: string, admin: boolean): Promise<void> {
    await this.stop();
    this.dir = dir;
    this.invite = '';
    this.byInvite = false;
    this.fingerprint = '';
    this.admin = admin;
    this.wrongCodes = 0;
    this.error = '';
    const request = await this.request();
    if (request === undefined) {
      return;
    }
    const addrs = qrAddresses();
    if (addrs.length === 0) {
      this.fail(new Failure(t('error_join_wifi'), 'join: no private IPv4 address'));
      return;
    }
    request['addrs'] = addrs;
    if (admin) {
      const key = await ensure('admin');
      if (key.ok === undefined) {
        this.fail(key.failure as Failure);
        return;
      }
      request['admin_public'] = key.ok.public;
    }
    const made = await cbb.joinNew(JSON.stringify(request), admin);
    const answer = read<Made>(made.answer, 'join');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'join: no joiner'));
      return;
    }
    this.handle = made.handle;
    try {
      await listen();
    } catch (e) {
      this.fail(Errors.unexpected(t('error_join_listen'), e as Object));
      return;
    }
    onConnect = (c: socket.TCPSocketConnection) => {
      this.accept(c);
    };
    // Announced while it listens, so that a computer of the group finds it
    // by the code typed there (docs/protocol.md, section 6).
    if (!cbb.joinAnnounce(made.handle, MEMBER_PORT)) {
      Errors.log('join: no mDNS announcement');
    }
    this.code = answer.ok.code ?? '';
    this.qr = answer.ok.qr ?? '';
    this.modules = answer.ok.modules ?? [];
    Errors.log(`join: listening as ${answer.ok.device ?? ''} on ${JSON.stringify(addrs)}`);
    // With the details on, the QR code's text goes to the log too, so that a
    // test can admit the phone without a camera; it holds the one-time code.
    if (Errors.showDetails()) {
      Errors.log(`join: QR: ${this.qr}`);
    }
    this.state = 'listening';
  }

  // Joins by a remote invitation's text, which the user accepted.
  async startInvite(dir: string, invite: string): Promise<void> {
    await this.stop();
    this.dir = dir;
    this.admin = false;
    this.wrongCodes = 0;
    this.inviteAttempts = 0;
    this.error = '';
    this.fingerprint = '';
    this.invite = invite.trim();
    this.byInvite = true;
    const request = await this.request();
    if (request === undefined) {
      return;
    }
    request['invite'] = this.invite;
    const made = await cbb.joinNew(JSON.stringify(request), false);
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
    onConnect = (c: socket.TCPSocketConnection) => {
      c.close().catch(() => {});
    };
    if (this.wire !== null) {
      this.wire.close();
      this.wire = null;
    }
    const h = this.handle;
    this.handle = null;
    if (h !== null) {
      await cbb.joinFree(h);
    }
    if (this.state === 'listening' || this.state === 'dialing' || this.state === 'joining') {
      this.state = 'idle';
    }
  }

  // The request both ways share: the phone's name, system, key and seal.
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

  private async accept(c: socket.TCPSocketConnection): Promise<void> {
    let peer = '';
    try {
      peer = (await c.getRemoteAddress()).address;
    } catch (e) {
      peer = '';
    }
    // One attempt at a time, and only from the home network.
    if (this.handle === null || this.wire !== null || !isHome(peer)) {
      Errors.log(`join: refused a connection from ${peer}`);
      c.close().catch(() => {});
      return;
    }
    const first = read<Step>(await cbb.joinAccept(this.handle), 'join');
    if (first.ok === undefined) {
      c.close().catch(() => {});
      this.fail(first.failure as Failure);
      return;
    }
    const wire: Wire = {
      send: (data: ArrayBuffer) => {
        if (data.byteLength > 0) {
          c.send({ data: data } as socket.TCPSendOptions).catch(() => {});
        }
      },
      close: () => {
        c.close().catch(() => {});
      }
    };
    this.wire = wire;
    c.on('message', (m: socket.SocketMessageInfo) => {
      if (this.wire === wire) {
        this.feed(m.message);
      }
    });
    c.on('close', () => {
      if (this.wire === wire) {
        this.wire = null;
        if (this.state === 'joining') {
          this.state = 'listening';
        }
      }
    });
    Errors.log(`join: a device dialed in from ${peer}`);
    this.state = 'joining';
    this.feed(new ArrayBuffer(0));
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
      if (this.invite.length > 0) {
        this.inviteAttemptEnded();
        return;
      }
      const wrongCode = step.ok.wrong_code === true;
      if (wrongCode && ++this.wrongCodes >= MAX_WRONG_CODES) {
        this.fail(new Failure(t('error_join_wrong_codes'), 'join: too many wrong codes'));
        return;
      }
      // A window that makes no admins refuses a phone that asks to be one:
      // the page says so, and keeps waiting for the root.
      if (this.admin && !wrongCode) {
        this.error = Errors.shown(new Failure(t('error_join_not_admin'), `join: ${why}`));
      }
      this.state = 'listening';
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
