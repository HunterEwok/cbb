// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's CBB: its one page, and the link to the phone while it shows.

import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { window } from '@kit.ArkUI';
import { Errors } from '../core/Errors';
import { setResources } from '../core/Text';
import { link } from '../model/Link';

export default class WearAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    const prefs = preferences.getPreferencesSync(this.context, { name: 'settings' });
    Errors.init(prefs);
    setResources(this.context.resourceManager);
    link.init(prefs);
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Watch', (e) => {
      if (e.code !== 0) {
        Errors.log(`watch: the page did not load: ${e.code} ${e.message}`);
      }
    });
  }

  onForeground(): void {
    link.start(this.context);
  }

  onBackground(): void {
    link.stop();
  }
}
