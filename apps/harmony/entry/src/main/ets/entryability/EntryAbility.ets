// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The app's one ability: it sets up the settings, the errors' mode, the
// prompt of the admin key and the model, opens Start or Home, takes what
// another app shares, and keeps the member a little longer when the app
// goes to the background, so that a copy on its way arrives.

import { AbilityConstant, bundleManager, UIAbility, Want } from '@kit.AbilityKit';
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

export default class EntryAbility extends UIAbility {
  private delayId: number = -1;

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
    this.takeShared(want);
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    this.takeShared(want);
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
    app.startMember();
  }

  // HarmonyOS suspends an app soon after it leaves the screen; the member
  // asks for the short delay the system grants, and stops when it ends.
  onBackground(): void {
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
