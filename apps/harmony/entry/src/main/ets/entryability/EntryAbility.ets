// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { window } from '@kit.ArkUI';
import { Errors } from '../core/Errors';
import { versionLine } from '../core/Core';
import { setPrompt } from '../core/Keys';
import { Membership } from '../core/Membership';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    Errors.init(preferences.getPreferencesSync(this.context, { name: 'settings' }));
    AppStorage.setOrCreate<string>('filesDir', this.context.filesDir);
    Errors.log(`app: started, ${versionLine()}`);
    setPrompt(this.context.resourceManager.getStringByNameSync('auth_title'));
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    const m = Membership.load(this.context.filesDir);
    const page = m instanceof Membership ? 'pages/Group' : 'pages/Start';
    windowStage.loadContent(page, (err) => {
      if (err.code) {
        Errors.log(`app: ${page} did not load: ${err.code} ${err.message}`);
      }
    });
  }
}
