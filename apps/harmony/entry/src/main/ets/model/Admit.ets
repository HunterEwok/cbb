// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Adding a device by the QR code it shows (docs/protocol.md, section 6):
// the phone dials the code's addresses and the core (ffi's cbb_admit_*)
// admits the device, signing its certificate with the admin key after the
// user's consent. This class only moves the bytes, as the Aurora app's
// Admit does; Scan Kit reads the code.

import { socket } from '@kit.NetworkKit';
import cbb, { Handle } from 'libcbb_napi.so';
import { read } from '../core/Core';
import { fromBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { Membership } from '../core/Membership';
import { t } from '../core/Text';
import { Member } from './Member';
import { Dialed, netAddress } from './Net';

interface Made {
  addrs?: string[];
}

interface StepError {
  message?: string;
  details?: string;
}

interface Admitted {
  device?: string;
  name?: string;
  os?: string;
  role?: string;
  admin?: boolean;
}

interface Step {
  state?: string;
  send?: string;
  error?: StepError;
  device?: Admitted;
  confirmed?: boolean;
  wrong_code?: boolean;
}

function describe(e: StepError | undefined): string {
  return e === undefined ? '' : `${e.message ?? ''}: ${e.details ?? ''}`;
}

@ObservedV2
export class Admit {
  // idle, preparing (finding the admin key), dialing, admitting, admitted
  // (the device has its certificate), confirmed (it stored it) or failed.
  @Trace state: string = 'idle';
  // The admitted device's name.
  @Trace device: string = '';
  @Trace error: string = '';

  private handle: Handle | null = null;
  private conn: Dialed | null = null;
  private addrs: string[] = [];
  private lastError: string = '';

  // Whether a scanned text is a device's join code.
  static isJoinCode(text: string): boolean {
    return text.trim().startsWith('cbb://join?');
  }

  async admit(qr: string, member: Member, m: Membership, makeAdmin: boolean): Promise<void> {
    await this.close();
    this.error = '';
    this.device = '';
    this.state = 'preparing';
    const core = member.core();
    if (core === null) {
      this.fail(new Failure(t('error_not_running'), 'admit: no member'));
      return;
    }
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return;
    }
    const request: Record<string, Object> = { 'qr': qr.trim(), 'public': key.ok.public, 'make_admin': makeAdmin };
    if (!m.isRoot() && m.member.admin_ca !== undefined) {
      request['admin_ca'] = m.member.admin_ca;
    }
    const made = await cbb.admitNew(core, JSON.stringify(request), 'admin');
    const answer = read<Made>(made.answer, 'admit');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'admit: no admission'));
      return;
    }
    this.handle = made.handle;
    this.addrs = answer.ok.addrs ?? [];
    this.lastError = 'no address of the code answered';
    Errors.log(`admit: dialing ${this.addrs.join(', ')}`);
    this.state = 'dialing';
    this.dialNext();
  }

  async reset(): Promise<void> {
    await this.close();
    this.addrs = [];
    this.device = '';
    this.error = '';
    this.state = 'idle';
  }

  private async dialNext(): Promise<void> {
    if (this.conn !== null) {
      this.conn.close();
      this.conn = null;
    }
    let target: socket.NetAddress | undefined = this.addrs.length > 0 ? netAddress(this.addrs[0]) : undefined;
    while (this.addrs.length > 0 && target === undefined) {
      this.addrs.shift();
      target = this.addrs.length > 0 ? netAddress(this.addrs[0]) : undefined;
    }
    const addr = this.addrs.shift();
    if (target === undefined || addr === undefined) {
      this.fail(new Failure(t('error_admit_unreachable'), `admit: ${this.lastError}`));
      return;
    }
    const d = new Dialed();
    this.conn = d;
    const lost = (why: string): void => {
      if (this.conn !== d) {
        return;
      }
      if (this.state === 'admitted') {
        // The device closed after the Welcome without answering: it is in
        // the group whether or not it stored its identity.
        this.close();
        return;
      }
      if (this.state !== 'dialing' && this.state !== 'admitting') {
        return;
      }
      this.lastError = `${addr}: ${why}`;
      Errors.log(`admit: ${this.lastError}`);
      this.state = 'dialing';
      this.dialNext();
    };
    d.onData = (data: ArrayBuffer) => {
      if (this.conn === d) {
        this.feed(data);
      }
    };
    d.onClose = lost;
    try {
      await d.dial(target, 5000);
    } catch (e) {
      d.close();
      lost(String(e));
      return;
    }
    if (this.conn !== d || this.handle === null) {
      return;
    }
    const step = read<Step>(await cbb.admitDial(this.handle), 'admit');
    if (step.ok === undefined) {
      this.fail(step.failure as Failure);
      return;
    }
    this.state = 'admitting';
    this.step(step.ok);
  }

  private async feed(data: ArrayBuffer): Promise<void> {
    if (this.handle === null || this.conn === null) {
      return;
    }
    const step = read<Step>(await cbb.admitFeed(this.handle, data, 0), 'admit');
    if (step.ok === undefined) {
      this.fail(step.failure as Failure);
      return;
    }
    this.step(step.ok);
  }

  private step(s: Step): void {
    if (this.conn !== null) {
      this.conn.send(fromBase64(s.send));
    }
    const e = s.error;
    if (s.state === 'admitted') {
      const d = s.device ?? ({} as Admitted);
      this.device = d.name ?? '';
      Errors.log(`admit: admitted ${d.device ?? ''} (${d.os ?? ''}, ${d.role ?? ''})${d.admin === true ? ', an admin' : ''}`);
      // The record could not go to the group: the device has its
      // certificate, and the app says what went wrong.
      if (e !== undefined && (e.message ?? '').length > 0) {
        this.error = Errors.shown(new Failure(t('error_admit_record'), `admit: ${describe(e)}`));
      }
      this.state = 'admitted';
    } else if (s.state === 'done') {
      const confirmed = s.confirmed === true;
      Errors.log(`admit: the device ${confirmed ? 'stored its identity' : 'did not confirm'}`);
      this.close();
      if (confirmed) {
        this.state = 'confirmed';
      }
    } else if (s.state === 'failed') {
      const message = `${e?.message ?? ''}${e?.details ?? ''}`;
      let shown = t('error_admit_failed');
      if (s.wrong_code === true) {
        shown = t('error_admit_wrong_code');
      } else if (message.includes('asks to be an admin') || message.includes("joins only through the group's root")) {
        shown = t('error_admit_asks_admin');
      } else if (message.includes('not the one in the QR code')) {
        shown = t('error_admit_other_device');
      }
      this.fail(new Failure(shown, `admit: ${describe(e)}`));
    }
  }

  private async close(): Promise<void> {
    if (this.conn !== null) {
      this.conn.close();
      this.conn = null;
    }
    const h = this.handle;
    this.handle = null;
    if (h !== null) {
      await cbb.admitFree(h);
    }
  }

  private fail(f: Failure): void {
    this.error = Errors.shown(f);
    this.close();
    this.state = 'failed';
  }
}
