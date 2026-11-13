// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Remote invitations (docs/protocol.md, section 12): an admin opens one
// through a hub of the group, shares its text or QR code, and admits the
// device that uses it once the user compared its fingerprint. And reading
// one the phone got, before it joins by it. The Aurora app's Invite, ported.

import cbb, { Handle } from 'libcbb_napi.so';
import { call, read } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { Membership } from '../core/Membership';
import { t } from '../core/Text';
import { Member } from './Member';

// How often the page's state is asked of the core.
const POLL_MS: number = 300;

interface Opened {
  invite?: string;
  modules?: string[];
  expires?: number;
}

interface Joining {
  name?: string;
  os?: string;
  fingerprint?: string;
}

interface StateError {
  message?: string;
  details?: string;
}

interface InviteState {
  version?: number;
  state?: string;
  joining?: Joining;
  name?: string;
  device?: string;
  error?: StateError;
}

interface Invitation {
  group?: string;
  hub?: string;
  expires?: number;
}

interface Refused {
  message?: string;
}

interface ReadInvite {
  invitation?: Invitation;
  refused?: Refused;
}

// What the user scanned or pasted, read: the group and hub to show, or the
// error.
export class InvitationText {
  text: string = '';
  group: string = '';
  hub: string = '';
  expiresMs: number = 0;
  error: string = '';
}

export function isInvitation(text: string): boolean {
  return text.trim().startsWith('cbb://invite#');
}

export function readInvitation(text: string): InvitationText {
  const out = new InvitationText();
  out.text = text.trim();
  const r = call<ReadInvite>('read_invite', { 'text': out.text } as Record<string, Object>);
  if (r.ok === undefined) {
    out.error = Errors.shown(r.failure as Failure);
    return out;
  }
  const inv = r.ok.invitation;
  if (inv === undefined) {
    out.error = Errors.shown(new Failure(t('error_invite_not'), `invite: ${r.ok.refused?.message ?? ''}`));
    return out;
  }
  const expiresMs = (inv.expires ?? 0) * 1000;
  if (expiresMs <= Date.now()) {
    out.error = Errors.shown(new Failure(t('error_invite_expired'), 'invite: expired'));
    return out;
  }
  out.group = inv.group ?? '';
  out.hub = (inv.hub ?? '').substring(0, 12);
  out.expiresMs = expiresMs;
  return out;
}

@ObservedV2
export class Invite {
  // idle, preparing (finding the admin key), opening (waiting for the hub),
  // open, joining (the user is asked), done or failed.
  @Trace state: string = 'idle';
  // The invitation's text, cbb://invite#..., and its QR code's rows.
  @Trace text: string = '';
  @Trace modules: string[] = [];
  @Trace expiresMs: number = 0;
  // The device that used it, while the user is asked.
  @Trace joiningName: string = '';
  @Trace joiningOs: string = '';
  @Trace fingerprint: string = '';
  // The name of the device that joined by it.
  @Trace joined: string = '';
  @Trace error: string = '';

  private handle: Handle | null = null;
  private timer: number = -1;
  private version: number = 0;
  private polling: boolean = false;

  // Opens one for seconds, signed with the admin key.
  async open(member: Member, m: Membership, seconds: number): Promise<void> {
    await this.close();
    this.error = '';
    this.joined = '';
    this.state = 'preparing';
    const core = member.core();
    if (core === null) {
      this.fail(new Failure(t('error_not_running'), 'invite: no member'));
      return;
    }
    const key = await ensure('admin');
    if (key.ok === undefined) {
      this.fail(key.failure as Failure);
      return;
    }
    const request: Record<string, Object> = { 'public': key.ok.public, 'expires': seconds };
    if (!m.isRoot() && m.member.admin_ca !== undefined) {
      request['admin_ca'] = m.member.admin_ca;
    }
    this.state = 'opening';
    const made = await cbb.inviteNew(core, JSON.stringify(request), 'admin');
    if (this.state !== 'opening') {
      // Cancelled while it waited for the hub.
      if (made.handle !== null) {
        await cbb.inviteFree(made.handle);
      }
      return;
    }
    const answer = read<Opened>(made.answer, 'invite');
    if (made.handle === null || answer.ok === undefined) {
      this.fail(answer.failure ?? new Failure(t('error_broken'), 'invite: no invitation'));
      return;
    }
    this.handle = made.handle;
    this.text = answer.ok.invite ?? '';
    this.modules = answer.ok.modules ?? [];
    this.expiresMs = Date.now() + (answer.ok.expires ?? 0) * 1000;
    this.version = 0;
    Errors.log(`invite: open for ${answer.ok.expires ?? 0} s`);
    this.state = 'open';
    this.timer = setInterval(() => {
      this.poll();
    }, POLL_MS);
  }

  // The user's answer about the device that used it.
  answer(yes: boolean): void {
    if (this.handle !== null) {
      cbb.inviteAnswer(this.handle, yes);
    }
  }

  // Ends it, or forgets how the last one ended.
  async cancel(): Promise<void> {
    this.state = 'idle';
    await this.close();
    this.error = '';
    this.joined = '';
  }

  private async poll(): Promise<void> {
    const h = this.handle;
    if (h === null || this.polling) {
      return;
    }
    this.polling = true;
    const st = read<InviteState>(await cbb.inviteNext(h, this.version, 0), 'invite');
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
    const j = st.ok.joining ?? ({} as Joining);
    this.joiningName = j.name ?? '';
    this.joiningOs = j.os ?? '';
    this.fingerprint = j.fingerprint ?? '';
    const state = st.ok.state ?? '';
    if (state === 'done') {
      this.joined = st.ok.name ?? '';
      Errors.log(`invite: ${st.ok.device ?? ''} joined`);
      await this.close();
      this.state = 'done';
      return;
    }
    if (state === 'failed') {
      const e = st.ok.error ?? ({} as StateError);
      this.fail(new Failure(e.message ?? t('error_invite_failed'), `invite: ${e.details ?? ''}`));
      return;
    }
    this.state = state;
  }

  private fail(f: Failure): void {
    this.close();
    this.error = Errors.shown(f);
    this.state = 'failed';
  }

  private async close(): Promise<void> {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    const h = this.handle;
    this.handle = null;
    this.text = '';
    this.modules = [];
    this.joiningName = '';
    this.joiningOs = '';
    this.fingerprint = '';
    if (h !== null) {
      await cbb.inviteFree(h);
    }
  }
}
