// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The bug report (docs/core-api.md, "Bug reports"): the core builds and
// seals the report and keeps the state; this class keeps that state in the
// app's settings, posts reports to bug.cbb.tools and sends again what
// waits, and holds the report the app asks about in release mode. The
// Aurora app's Bugs, ported.

import { http } from '@kit.NetworkKit';
import { preferences } from '@kit.ArkData';
import { call } from '../core/Core';
import { Errors, Failure } from '../core/Errors';

const STATE_KEY: string = 'bug_state';
const URL: string = 'https://bug.cbb.tools/';

interface ReportVersion {
  version?: string;
}

// The core's answer to bug_report.
interface Offer {
  action?: string; // ask, send or skip
  fingerprint?: string;
  report?: ReportVersion;
  post?: string;
  url?: string;
  offer_always?: boolean;
  fixed_in?: string;
}

interface Kept {
  state?: Object;
}

interface Waiting {
  fingerprint?: string;
  version?: string;
  post?: string;
}

interface Pending {
  state?: Object;
  queue?: Waiting[];
}

interface FixedIn {
  fixed_in?: string;
}

@ObservedV2
export class Bugs {
  // The app asks "Oops, something broke" while asking is true.
  @Trace asking: boolean = false;
  // Whether the question offers "Always allow": after the user allowed twice.
  @Trace offerAlways: boolean = false;
  // The version the server said fixes this break, '' when none.
  @Trace fixedIn: string = '';
  // The report as it would go, for "Technical details".
  @Trace report: string = '';

  private offered: Offer | undefined = undefined;
  private prefs: preferences.Preferences | undefined = undefined;

  init(prefs: preferences.Preferences): void {
    this.prefs = prefs;
  }

  private state(): Object {
    const none: Record<string, Object> = {};
    const text = this.prefs?.getSync(STATE_KEY, '') as string | undefined;
    if (text === undefined || text.length === 0) {
      return none;
    }
    try {
      return JSON.parse(text) as Object;
    } catch (e) {
      return none;
    }
  }

  private keep(state: Object | undefined): void {
    if (state !== undefined && this.prefs !== undefined) {
      this.prefs.putSync(STATE_KEY, JSON.stringify(state));
      this.prefs.flush();
    }
  }

  // Offers the report of a break: the core's action, ask (asking turns
  // true), send (it goes without asking) or skip; '' when the core refused
  // the input, which goes to the log.
  offer(input: Record<string, Object>): string {
    input['now_ms'] = Date.now();
    const a = call<Offer>('bug_report', { 'input': input, 'state': this.state() } as Record<string, Object>);
    if (a.ok === undefined) {
      const f = a.failure as Failure;
      Errors.log(`bug: no report: ${f.message} ${f.details}`);
      return '';
    }
    const o = a.ok;
    const action = o.action ?? '';
    if (action === 'ask') {
      this.offered = o;
      this.offerAlways = o.offer_always === true;
      this.fixedIn = o.fixed_in ?? '';
      this.report = JSON.stringify(o.report ?? {}, null, 2);
      this.asking = true;
    } else if (action === 'send') {
      this.send(o.fingerprint ?? '', o.report?.version ?? '', o.post ?? '', o.url ?? '');
    }
    return action;
  }

  // The user allowed the report asked about, and maybe always.
  allow(always: boolean): void {
    const o = this.offered;
    if (o === undefined) {
      return;
    }
    this.cancel();
    const a = call<Kept>('bug_allow', { 'state': this.state(), 'always': always } as Record<string, Object>);
    this.keep(a.ok?.state);
    this.send(o.fingerprint ?? '', o.report?.version ?? '', o.post ?? '', o.url ?? '');
  }

  // The user cancelled it: nothing goes.
  cancel(): void {
    this.offered = undefined;
    this.asking = false;
    this.report = '';
  }

  // Sends the reports that wait, as at start.
  resend(): void {
    const a = call<Pending>('bug_pending', { 'state': this.state(), 'now_ms': Date.now() } as Record<string, Object>);
    if (a.ok === undefined) {
      return;
    }
    this.keep(a.ok.state);
    for (const q of a.ok.queue ?? []) {
      this.send(q.fingerprint ?? '', q.version ?? '', q.post ?? '', '');
    }
  }

  private async send(fingerprint: string, version: string, post: string, to: string): Promise<void> {
    if (post.length === 0) {
      return;
    }
    let ok = false;
    let fixed = '';
    const req = http.createHttp();
    try {
      const r = await req.request(to.length > 0 ? to : URL, {
        method: http.RequestMethod.POST,
        header: { 'Content-Type': 'application/json' } as Record<string, string>,
        extraData: post,
        expectDataType: http.HttpDataType.STRING,
        connectTimeout: 15000,
        readTimeout: 15000
      });
      ok = r.responseCode === 200;
      if (ok) {
        try {
          fixed = (JSON.parse((r.result as string).substring(0, 4096)) as FixedIn).fixed_in ?? '';
        } catch (e) {
          fixed = '';
        }
      } else {
        Errors.log(`bug: the report did not go, it waits: HTTP ${r.responseCode}`);
      }
    } catch (e) {
      Errors.log(`bug: the report did not go, it waits: ${(e as Error).message}`);
    } finally {
      req.destroy();
    }
    const a = call<Kept>('bug_sent', {
      'state': this.state(), 'fingerprint': fingerprint, 'version': version, 'post': post, 'ok': ok,
      'fixed_in': fixed, 'now_ms': Date.now()
    } as Record<string, Object>);
    this.keep(a.ok?.state);
  }
}
