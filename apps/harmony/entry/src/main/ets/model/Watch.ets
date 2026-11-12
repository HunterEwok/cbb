// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's side of its HarmonyOS watch (docs/apps.md, "HarmonyOS
// watches"), as Android's WatchLink: while a watch with CBB is connected,
// it tells the watch the group as the phone sees it whenever that changes,
// and turns the phone's sync or sync away from home on or off when the
// watch asks, as Home's switches do.

import { common } from '@kit.AbilityKit';
import { Errors } from '../core/Errors';
import { form } from '../common/Devices';
import { decodeAsk, fit, WatchAsk, WatchDevice, WatchState } from '../common/WatchState';
import { Wear } from '../common/Wear';
import { app } from './AppModel';
import { Device } from './Member';

// How often the phone looks for its watch, and for a change to tell it.
const LOOK_MS: number = 30000;
const CHANGE_MS: number = 2000;

// The state the watch shows, from the app: the devices in the phone's
// order, each collection's after one another, this phone first.
export function stateOf(): WatchState {
  const devices: WatchDevice[] = [];
  let online = 0;
  for (const tile of app.arranged(app.member.devices)) {
    const ds: Device[] = tile.device !== undefined ? [tile.device] : tile.devices;
    for (const d of ds) {
      if (d.online === true || d.self === true) {
        online++;
      }
      devices.push({
        id: d.id, name: d.name, form: form(d), online: d.online === true || d.self === true,
        collection: tile.device !== undefined ? '' : tile.name, phone: d.self === true
      });
    }
  }
  return {
    type: 'state',
    group: app.membership !== undefined,
    devices: devices,
    more: 0,
    online: online,
    total: devices.length,
    sync: !app.member.paused,
    away: app.member.awayOn ? app.member.awayStatus : 'off',
    events: app.events.recent.slice(0, 5)
  };
}

export class Watch {
  private wear: Wear = new Wear();
  private context: common.Context | undefined = undefined;
  private looking: number = -1;
  private watching: number = -1;
  private told: string = '';

  start(context: common.Context): void {
    this.context = context;
    this.look();
    this.looking = setInterval(() => this.look(), LOOK_MS);
  }

  stop(): void {
    clearInterval(this.looking);
    clearInterval(this.watching);
    this.looking = -1;
    this.watching = -1;
    this.wear.close();
  }

  private async look(): Promise<void> {
    if (this.context === undefined) {
      return;
    }
    const linked = await this.wear.connect(this.context, true, (data: Uint8Array) => this.asked(data));
    if (linked && this.watching === -1) {
      this.told = '';
      this.tell();
      this.watching = setInterval(() => this.tell(), CHANGE_MS);
    } else if (!linked && this.watching !== -1) {
      clearInterval(this.watching);
      this.watching = -1;
    }
  }

  // Sends the state when it changed since the watch got it last.
  private async tell(): Promise<void> {
    const data = fit(stateOf());
    const text = data.join(',');
    if (text === this.told) {
      return;
    }
    if (await this.wear.send(data)) {
      this.told = text;
    }
  }

  private asked(data: Uint8Array): void {
    const a: WatchAsk | undefined = decodeAsk(data);
    if (a === undefined) {
      Errors.log('watch: a message that does not read');
      return;
    }
    Errors.log(`watch: asked ${a.type} ${a.on}`);
    if (a.type === 'hello') {
      this.told = '';
      this.tell();
    } else if (a.type === 'sync') {
      if (a.on) {
        app.member.resume();
      } else {
        app.member.pause(0);
      }
    } else if (a.type === 'away') {
      app.member.setAway(a.on);
    }
  }
}
