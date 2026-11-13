// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The app's intents (Intents Kit, resources/base/profile/insight_intent.json),
// the iPhone's App Intents twin, which Celia and the system's suggestions
// offer: SyncClipboard syncs as the widget does, ToggleSync turns sync on
// this phone on or off; both open the app, since HarmonyOS lets it read the
// clipboard only in front.

import { insightIntent, InsightIntentExecutor } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { Errors } from '../core/Errors';
import { app } from '../model/AppModel';
import { glance } from '../model/Glance';

export default class SyncIntent extends InsightIntentExecutor {
  onExecuteInUIAbilityForegroundMode(name: string, param: Record<string, Object>,
    pageLoader: window.WindowStage): insightIntent.ExecuteResult {
    const page = app.membership !== undefined ? 'pages/Main' : 'pages/Start';
    pageLoader.loadContent(page, (err) => {
      if (err.code) {
        Errors.log(`intent: ${page} did not load: ${err.code} ${err.message}`);
      }
    });
    Errors.log(`intent: ${name}`);
    glance.quick(name === 'ToggleSync' ? 'sync_toggle' : 'sync');
    const result: insightIntent.ExecuteResult = { code: 0, result: {} };
    return result;
  }
}
