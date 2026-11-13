// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group's events the app notifies of (docs/apps.md, Notifications), as
// the iPhone's GroupEvents and the other phones' do: it compares the group's
// devices with what it saw last time, so it learns of events while the app
// runs. The Aurora app's Events, ported.

import { notificationManager } from '@kit.NotificationKit';
import { preferences } from '@kit.ArkData';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { Device } from './Member';

const SEEN_KEY: string = 'events_seen';
export const EVENT_KINDS: string[] = ['devices', 'admins', 'frozen', 'takeover'];

// What the app knew of a device when it last looked.
export interface Seen {
  name: string;
  admin: boolean;
  frozen: boolean;
  root: boolean;
}

export interface GroupEvent {
  kind: string; // devices, admins, frozen or takeover
  text: string;
}

// The other devices of a list from the core, by ID.
export function seenOf(devices: Device[]): Map<string, Seen> {
  const m = new Map<string, Seen>();
  for (const d of devices) {
    if (d.self === true || d.id.length === 0 || m.has(d.id)) {
      continue;
    }
    const s: Seen = { name: d.name, admin: d.admin === true, frozen: d.frozen === true, root: d.root === true };
    m.set(d.id, s);
  }
  return m;
}

function byName(m: Map<string, Seen>): [string, Seen][] {
  const l: [string, Seen][] = [];
  m.forEach((s: Seen, id: string) => {
    l.push([id, s]);
  });
  l.sort((a: [string, Seen], b: [string, Seen]) => a[1].name < b[1].name ? -1 : a[1].name > b[1].name ? 1 : 0);
  return l;
}

// The events between two looks, by name, removals after the rest.
export function between(old: Map<string, Seen>, now: Map<string, Seen>): GroupEvent[] {
  const events: GroupEvent[] = [];
  const add = (kind: string, text: string): void => {
    const e: GroupEvent = { kind: kind, text: text };
    events.push(e);
  };
  for (const e of byName(now)) {
    const n = e[1].name;
    const was = old.get(e[0]);
    if (was === undefined) {
      add('devices', t('event_joined', n));
      continue;
    }
    if (e[1].root && !was.root) {
      add('takeover', t('event_takeover', n));
    } else if (e[1].admin && !was.admin) {
      add('admins', t('event_admin', n));
    }
    if (e[1].frozen !== was.frozen) {
      add('frozen', e[1].frozen ? t('event_frozen', n) : t('event_unfrozen', n));
    }
  }
  for (const e of byName(old)) {
    if (!now.has(e[0])) {
      add('devices', t('event_removed', e[1].name));
    }
  }
  return events;
}

function same(a: Map<string, Seen>, b: Map<string, Seen>): boolean {
  if (a.size !== b.size) {
    return false;
  }
  let equal = true;
  a.forEach((s: Seen, id: string) => {
    const o = b.get(id);
    if (o === undefined || o.name !== s.name || o.admin !== s.admin || o.frozen !== s.frozen || o.root !== s.root) {
      equal = false;
    }
  });
  return equal;
}

@ObservedV2
export class Events {
  // The latest events, newest first.
  @Trace recent: string[] = [];

  private prefs: preferences.Preferences | undefined = undefined;
  private nextId: number = 1;

  init(prefs: preferences.Preferences): void {
    this.prefs = prefs;
  }

  // Each kind's switch, all on by default.
  isOn(kind: string): boolean {
    return this.prefs === undefined || this.prefs.getSync(`notify_${kind}`, true) as boolean;
  }

  setOn(kind: string, on: boolean): void {
    if (this.prefs !== undefined) {
      this.prefs.putSync(`notify_${kind}`, on);
      this.prefs.flush();
    }
  }

  // Notifies of what changed since the last look; the first look only
  // remembers.
  observe(devices: Device[]): void {
    if (devices.length === 0 || this.prefs === undefined) {
      return;
    }
    const now = seenOf(devices);
    const stored = this.prefs.getSync(SEEN_KEY, '') as string;
    const old = new Map<string, Seen>();
    let known = false;
    if (stored.length > 0) {
      try {
        const o = JSON.parse(stored) as Record<string, Seen>;
        Object.keys(o).forEach((id: string) => {
          old.set(id, o[id]);
        });
        known = true;
      } catch (e) {
        known = false;
      }
    }
    if (known && same(old, now)) {
      return;
    }
    const out: Record<string, Seen> = {};
    now.forEach((s: Seen, id: string) => {
      out[id] = s;
    });
    this.prefs.putSync(SEEN_KEY, JSON.stringify(out));
    this.prefs.flush();
    if (!known) {
      return;
    }
    for (const e of between(old, now)) {
      this.recent = [e.text].concat(this.recent).slice(0, 5);
      if (this.isOn(e.kind)) {
        this.post(e.text);
      }
    }
  }

  // Forgets the group's devices, once the phone left it.
  forget(): void {
    if (this.prefs !== undefined) {
      this.prefs.deleteSync(SEEN_KEY);
      this.prefs.flush();
    }
    this.recent = [];
  }

  // A notification, also for the received files (Member's onSaved).
  post(text: string): void {
    const request: notificationManager.NotificationRequest = {
      id: this.nextId++,
      content: {
        notificationContentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: { title: t('app_name'), text: text }
      }
    };
    notificationManager.publish(request).catch((e: Error) => {
      Errors.log(`events: no notification: ${e.message}`);
    });
  }
}
