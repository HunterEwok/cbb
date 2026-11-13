// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Live View (Live View Kit), the iPhone's Live Activity twin: what runs shows
// on the lock screen and in the status bar's capsule, never what was copied:
// adding a device, with a timer, then its result for a moment; sync away from
// home through the hub's tunnel, with the time since it connected; and the
// result of a quick sync for a few seconds (docs/apps.md, "Dynamic Island").
// Huawei grants an app Live View on request; until then isLiveViewEnabled
// answers false and nothing shows.

import { common, wantAgent, WantAgent } from '@kit.AbilityKit';
import { liveViewManager } from '@kit.LiveViewKit';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';

// The Live Views' IDs, one for each thing that runs.
const ADMIT_ID: number = 1;
const AWAY_ID: number = 2;
const SYNC_ID: number = 3;
// The scene Huawei grants the app with Live View.
const EVENT: string = 'SCHEDULE';
// How long a result stays, in seconds.
const RESULT_S: number = 5;

export class Live {
  private context: common.UIAbilityContext | undefined = undefined;
  private enabled: boolean = false;
  private open: WantAgent | undefined = undefined;
  private running: Set<number> = new Set<number>();
  private sequence: number = 0;

  async init(context: common.UIAbilityContext): Promise<void> {
    this.context = context;
    try {
      this.enabled = await liveViewManager.isLiveViewEnabled();
      this.open = await wantAgent.getWantAgent({
        wants: [{ bundleName: context.abilityInfo.bundleName, abilityName: context.abilityInfo.name }],
        actionType: wantAgent.OperationType.START_ABILITY,
        requestCode: 1,
        wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
      });
    } catch (e) {
      this.enabled = false;
      Errors.log(`live: no Live View: ${String(e)}`);
    }
    Errors.log(`live: Live View ${this.enabled ? 'on' : 'off'}`);
  }

  // Shows or changes the Live View id; since is when its timer started,
  // 0 for none; keep how long it stays once it ends.
  private async show(id: number, title: string, text: string, since: number, keep?: number): Promise<void> {
    if (!this.enabled) {
      return;
    }
    this.sequence++;
    const view: liveViewManager.LiveView = {
      id: id,
      event: EVENT,
      sequence: this.sequence,
      isMute: true,
      primary: { title: title, content: [{ text: text }], keepTime: keep ?? 0, clickAction: this.open }
    };
    if (since > 0) {
      view.timer = { time: Date.now() - since, isCountdown: false, isPaused: false };
      view.primary.content = [{ text: text.length > 0 ? `${text} · \${placeholder.timer}` : '${placeholder.timer}' }];
    }
    try {
      if (this.running.has(id)) {
        await liveViewManager.updateLiveView(view);
      } else {
        await liveViewManager.startLiveView(view);
        this.running.add(id);
      }
    } catch (e) {
      Errors.log(`live: ${id} not shown: ${String(e)}`);
    }
  }

  private async end(id: number, title: string, text: string, keep: number): Promise<void> {
    if (!this.enabled || !this.running.has(id)) {
      return;
    }
    this.running.delete(id);
    this.sequence++;
    const view: liveViewManager.LiveView = {
      id: id, event: EVENT, sequence: this.sequence, isMute: true,
      primary: { title: title, content: [{ text: text }], keepTime: keep, clickAction: this.open }
    };
    try {
      await liveViewManager.stopLiveView(view);
    } catch (e) {
      Errors.log(`live: ${id} not ended: ${String(e)}`);
    }
  }

  adding(since: number): void {
    this.show(ADMIT_ID, t('admit_title'), t('live_adding'), since);
  }

  added(ok: boolean, why: string): void {
    this.end(ADMIT_ID, t('admit_title'), ok ? t('live_added') : why, RESULT_S);
  }

  away(connected: boolean, hub: string, since: number): void {
    if (connected) {
      this.show(AWAY_ID, t('live_away'), hub, since);
    } else {
      this.end(AWAY_ID, t('live_away'), '', 0);
    }
  }

  async synced(text: string): Promise<void> {
    await this.show(SYNC_ID, t('widget_name'), text, 0, RESULT_S);
    await this.end(SYNC_ID, t('widget_name'), text, RESULT_S);
  }
}
