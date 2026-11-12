// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The app's one ability: it sets up the settings, the errors' mode, the
// prompt of the admin key and the model, opens Start or Home, takes what
// another app shares, and keeps the member running in the background as a
// continuous task of the kind "multi-device connection", with the system's
// notification; where the system refuses that, a little longer, so that a
// copy on its way arrives. The widget, the app's shortcuts and its intents
// open it with an action (Glance.quick).

import { AbilityConstant, bundleManager, UIAbility, Want, wantAgent } from '@kit.AbilityKit';
import { backgroundTaskManager } from '@kit.BackgroundTasksKit';
import { preferences } from '@kit.ArkData';
import { notificationManager } from '@kit.NotificationKit';
import { window } from '@kit.ArkUI';
import { Errors } from '../core/Errors';
import { versionLine } from '../core/Core';
import { setPrompt } from '../core/Keys';
import { osVersion } from '../core/Phone';
import { setResources, t } from '../core/Text';
import { sharedOf } from '../common/Share';
import { app } from '../model/AppModel';
import { Watch } from '../model/Watch';
import { glance } from '../model/Glance';

export default class EntryAbility extends UIAbility {
  private delayId: number = -1;
  private running: boolean = false;
  // The HarmonyOS watch, while one with CBB is connected.
  private watch: Watch = new Watch();

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    const prefs = preferences.getPreferencesSync(this.context, { name: 'settings' });
    Errors.init(prefs);
    setResources(this.context.resourceManager);
    AppStorage.setOrCreate<string>('filesDir', this.context.filesDir);
    try {
      const info = bundleManager.getBundleInfoForSelfSync(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT);
      AppStorage.setOrCreate<string>('version', info.versionName);
    } catch (e) {
      Errors.log(`app: no version: ${String(e)}`);
    }
    Errors.log(`app: started, CBB ${AppStorage.get<string>('version') ?? ''}, ${versionLine()}, ${osVersion()}`);
    setPrompt(t('auth_title'));
    app.init(this.context.filesDir, prefs);
    app.keyboard.init(prefs, this.context);
    this.watch.start(this.context);
    glance.start(this.context);
    this.takeShared(want);
    this.takeAction(want);
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    this.takeShared(want);
    this.takeAction(want);
  }

  // The quick action a widget, a shortcut or an intent opened the app with.
  private takeAction(want: Want): void {
    const given = want.parameters?.['action'];
    const action = typeof given === 'string' ? given : '';
    if (action === 'sync' || action === 'sync_toggle') {
      Errors.log(`app: quick action ${action}`);
      glance.quick(action);
    }
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    const page = app.membership !== undefined ? 'pages/Main' : 'pages/Start';
    windowStage.loadContent(page, (err) => {
      if (err.code) {
        Errors.log(`app: ${page} did not load: ${err.code} ${err.message}`);
      }
    });
    // The group's events and the received files are notifications.
    notificationManager.requestEnableNotification(this.context).catch((e: Error) => {
      Errors.log(`app: notifications stay off: ${e.message}`);
    });
  }

  onForeground(): void {
    if (this.delayId >= 0) {
      backgroundTaskManager.cancelSuspendDelay(this.delayId);
      this.delayId = -1;
    }
    if (this.running) {
      this.running = false;
      backgroundTaskManager.stopBackgroundRunning(this.context).catch((e: Error) => {
        Errors.log(`app: the continuous task did not stop: ${e.message}`);
      });
    }
    app.startMember();
  }

  // HarmonyOS suspends an app soon after it leaves the screen: the member
  // goes on as a continuous task while it runs, and otherwise asks for the
  // short delay the system grants and stops when it ends.
  onBackground(): void {
    if (app.membership !== undefined && app.member.running) {
      this.keepRunning().then((kept: boolean) => {
        if (!kept) {
          this.delay();
        }
      });
      return;
    }
    this.delay();
  }

  // The continuous task; its notification opens the app.
  private async keepRunning(): Promise<boolean> {
    try {
      const agent = await wantAgent.getWantAgent({
        wants: [{ bundleName: this.context.abilityInfo.bundleName, abilityName: this.context.abilityInfo.name }],
        actionType: wantAgent.OperationType.START_ABILITY,
        requestCode: 0,
        wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
      });
      await backgroundTaskManager.startBackgroundRunning(this.context,
        backgroundTaskManager.BackgroundMode.MULTI_DEVICE_CONNECTION, agent);
      this.running = true;
      Errors.log('app: the member runs on in the background');
      return true;
    } catch (e) {
      Errors.log(`app: no continuous task: ${(e as Error).message}`);
      return false;
    }
  }

  private delay(): void {
    try {
      const info = backgroundTaskManager.requestSuspendDelay(t('background_reason'), () => {
        this.delayId = -1;
        app.stopMember();
      });
      this.delayId = info.requestId;
    } catch (e) {
      Errors.log(`app: no background delay: ${String(e)}`);
    }
  }

  onDestroy(): void {
    this.watch.stop();
    glance.stop();
    if (this.running) {
      this.running = false;
      backgroundTaskManager.stopBackgroundRunning(this.context).catch(() => {});
    }
    app.stopMember();
  }

  private takeShared(want: Want): void {
    sharedOf(want, this.context.cacheDir).then((shared) => {
      if (shared !== undefined) {
        Errors.log(`share: ${shared.text.length > 0 ? 'a text' : ''} ${shared.files.length} files`);
        app.share(shared);
      }
    }).catch((e: Error) => {
      app.show(Errors.shown(Errors.unexpected(t('error_share_in'), e)));
    });
  }
}
