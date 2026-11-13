// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the app shows outside its window while it runs: the home-screen
// widget's state (common/Widgets.ets) and the Live Views (Live.ets), from
// the model every two seconds, as the watch's state is.

import { common } from '@kit.AbilityKit';
import { showOnWidgets, WidgetState } from '../common/Widgets';
import { t } from '../core/Text';
import { app } from './AppModel';
import { Live } from './Live';

const EVERY_MS: number = 2000;

export class Glance {
  readonly live: Live = new Live();
  private context: common.UIAbilityContext | undefined = undefined;
  private timer: number = -1;
  private shown: string = '';
  private admitSince: number = 0;
  private awaySince: number = 0;

  start(context: common.UIAbilityContext): void {
    this.context = context;
    this.live.init(context);
    this.look();
    if (this.timer < 0) {
      this.timer = setInterval(() => this.look(), EVERY_MS);
    }
  }

  stop(): void {
    clearInterval(this.timer);
    this.timer = -1;
  }

  // A quick action from the widget, the app's shortcuts or an intent
  // (EntryAbility): sync sends what this phone copied when the system lets
  // the app read it, while the member writes what the group copied as it
  // comes; sync_toggle turns sync on this phone on or off.
  async quick(action: string): Promise<void> {
    if (app.membership === undefined) {
      return;
    }
    await app.startMember();
    if (!app.member.running) {
      return;
    }
    if (action === 'sync_toggle') {
      if (app.member.paused) {
        await app.member.resume();
      } else {
        await app.member.pause(0);
      }
      this.look();
    } else if (action === 'sync') {
      if (await app.member.sendPasteboard(true)) {
        await this.live.synced(t('live_sent'));
      }
    }
  }

  private look(): void {
    if (this.context === undefined) {
      return;
    }
    let online = 0;
    for (const d of app.member.devices) {
      if (d.online === true || d.self === true) {
        online++;
      }
    }
    const state: WidgetState = { group: app.membership !== undefined, syncOn: !app.member.paused, online: online };
    const text = `${state.group} ${state.syncOn} ${state.online}`;
    if (text !== this.shown) {
      this.shown = text;
      showOnWidgets(this.context, state);
    }
    // Adding a device, from the scan until it is in the group.
    const s = app.admit.state;
    const adding = s === 'preparing' || s === 'dialing' || s === 'admitting';
    if (adding && this.admitSince === 0) {
      this.admitSince = Date.now();
      this.live.adding(this.admitSince);
    } else if (!adding && this.admitSince > 0) {
      this.admitSince = 0;
      this.live.added(s === 'admitted' || s === 'confirmed', app.admit.error.split('\n')[0]);
    }
    // Away from home through the hub's tunnel.
    const through = app.member.awayOn && app.member.awayStatus === 'connected';
    if (through && this.awaySince === 0) {
      this.awaySince = Date.now();
      this.live.away(true, app.member.awayHub, this.awaySince);
    } else if (!through && this.awaySince > 0) {
      this.awaySince = 0;
      this.live.away(false, '', 0);
    }
  }
}

export const glance: Glance = new Glance();
