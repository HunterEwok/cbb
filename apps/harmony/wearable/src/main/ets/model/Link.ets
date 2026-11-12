// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's side of the link to its phone (docs/apps.md, "HarmonyOS
// watches"), as the Wear OS app's: it asks the phone for the group's state
// and shows what the phone tells, keeps the last state when the phone is
// out of reach, and asks the phone to turn its sync or sync away from home
// on or off.

import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { decodeState, encode, WatchState } from '../common/WatchState';
import { Wear } from '../common/Wear';

const LOOK_MS: number = 10000;
const KEPT: string = 'watch_state';

@ObservedV2
export class Link {
  // The phone's last state; undefined before the first.
  @Trace state: WatchState | undefined = undefined;
  // Whether the phone is in reach with CBB on it.
  @Trace reachable: boolean = false;
  // Whether the state came from the phone since the page opened.
  @Trace fresh: boolean = false;
  // A switch waits for the phone's new state.
  @Trace asking: boolean = false;
  // The last ask the phone did not take, for the page.
  @Trace failed: boolean = false;

  private wear: Wear = new Wear();
  private prefs: preferences.Preferences | undefined = undefined;
  private context: common.Context | undefined = undefined;
  private looking: number = -1;

  init(prefs: preferences.Preferences): void {
    this.prefs = prefs;
    const kept = prefs.getSync(KEPT, '') as string;
    if (kept.length > 0) {
      try {
        this.state = JSON.parse(kept) as WatchState;
      } catch (e) {
        this.state = undefined;
      }
    }
  }

  start(context: common.Context): void {
    this.context = context;
    this.fresh = false;
    this.look();
    this.looking = setInterval(() => this.look(), LOOK_MS);
  }

  stop(): void {
    clearInterval(this.looking);
    this.looking = -1;
    this.wear.close();
    this.reachable = false;
  }

  private async look(): Promise<void> {
    if (this.context === undefined) {
      return;
    }
    const was = this.reachable;
    this.reachable = await this.wear.connect(this.context, false, (data: Uint8Array) => this.got(data));
    if (this.reachable && (!was || !this.fresh)) {
      this.wear.send(encode({ type: 'hello', on: true }));
    }
  }

  private got(data: Uint8Array): void {
    const s = decodeState(data);
    if (s === undefined) {
      return;
    }
    this.state = s;
    this.fresh = true;
    this.asking = false;
    this.prefs?.putSync(KEPT, JSON.stringify(s));
    this.prefs?.flush();
  }

  // Asks the phone to turn its sync (sync) or sync away from home (away)
  // on or off; the new state comes back as the phone's next message.
  async ask(type: string, on: boolean): Promise<void> {
    this.failed = false;
    this.asking = true;
    if (!(await this.wear.send(encode({ type: type, on: on })))) {
      this.asking = false;
      this.failed = true;
    }
  }
}

export const link: Link = new Link();
