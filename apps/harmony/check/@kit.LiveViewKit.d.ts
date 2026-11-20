// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The part of HarmonyOS's Live View Kit the app uses, for check.sh: the
// kit is HarmonyOS's alone, and OpenHarmony's SDK lacks it.

import { WantAgent } from '@ohos.app.ability.wantAgent';

declare namespace liveViewManager {
  interface RichText {
    text: string;
    textColor?: string;
  }

  interface Primary {
    title?: string;
    content?: Array<RichText>;
    keepTime?: number;
    clickAction?: WantAgent;
  }

  interface LiveViewTimer {
    time?: number;
    isCountdown?: boolean;
    isPaused?: boolean;
  }

  interface LiveView {
    id: number;
    event: string;
    sequence?: number;
    isMute?: boolean;
    timer?: LiveViewTimer;
    primary: Primary;
  }

  interface LiveViewResult {
    sequence?: number;
  }

  function isLiveViewEnabled(): Promise<boolean>;
  function startLiveView(liveView: LiveView): Promise<LiveViewResult>;
  function updateLiveView(liveView: LiveView): Promise<LiveViewResult>;
  function stopLiveView(liveView: LiveView): Promise<LiveViewResult>;
}

export { liveViewManager };
