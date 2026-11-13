// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// CBB in the system's Share menu (docs/apps.md, "HarmonyOS"), as the
// iPhone's share extension: a sheet inside the share panel that sends the
// text, the link, or the images and files at once (model/OneShot.ets),
// without opening the app, and closes itself once they are sent.

import { ShareExtensionAbility, UIExtensionContentSession, Want } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { Errors } from '../core/Errors';
import { setPrompt } from '../core/Keys';
import { setResources, t } from '../core/Text';
import { sharedOf } from '../common/Share';
import { sendOnce } from '../model/OneShot';
import { phoneName } from '../core/Phone';
import { sheet } from '../model/Sheet';

// How long the sheet shows that it sent before it closes.
const SENT_MS: number = 1200;

export default class ShareExtAbility extends ShareExtensionAbility {
  onSessionCreate(want: Want, session: UIExtensionContentSession): void {
    const prefs = preferences.getPreferencesSync(this.context, { name: 'settings' });
    Errors.init(prefs);
    setResources(this.context.resourceManager);
    setPrompt(t('auth_title'));
    sheet.phase = 'sending';
    sheet.message = t('share_sending');
    sheet.close = () => {
      session.terminateSelf().catch((e: Error) => Errors.log(`share: closing: ${e.message}`));
    };
    session.loadContent('pages/ShareSheet');
    this.send(want);
  }

  private async send(want: Want): Promise<void> {
    try {
      const shared = await sharedOf(want, this.context.cacheDir);
      if (shared === undefined) {
        sheet.phase = 'failed';
        sheet.message = t('error_share_nothing');
        return;
      }
      Errors.log(`share: ${shared.text.length > 0 ? 'a text' : ''} ${shared.files.length} files, from the Share menu`);
      const failure = await sendOnce(this.context.filesDir, shared, phoneName());
      if (failure !== undefined) {
        sheet.phase = 'failed';
        sheet.message = Errors.shown(failure);
        return;
      }
      sheet.phase = 'sent';
      sheet.message = t('share_sent');
      setTimeout(() => sheet.close(), SENT_MS);
    } catch (e) {
      sheet.phase = 'failed';
      sheet.message = Errors.shown(Errors.unexpected(t('share_failed'), e as Object));
    }
  }
}
