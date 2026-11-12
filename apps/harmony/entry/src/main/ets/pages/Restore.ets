// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Restoring the group from its recovery sheet on a new phone: the sheet's
// QR code, scanned or pasted; the phone finds a device of the group on the
// network, restores the group and claims it, and becomes its root once the
// group's waiting time passes, unless the root cancels the claim.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';

const SHEET_PREFIX: string = 'cbb://recover?';

@Entry
@ComponentV2
struct Restore {
  @Local pasted: string = '';
  @Local hint: string = '';

  aboutToAppear(): void {
    app.resetRestore();
  }

  take(text: string): void {
    this.hint = '';
    if (!text.trim().startsWith(SHEET_PREFIX)) {
      this.hint = Errors.shown(new Failure(t('error_restore_not_sheet_qr'), 'restore: the text does not start with cbb://recover?'));
      return;
    }
    app.restore(text);
  }

  async scan(): Promise<void> {
    const s = await scanQr(getContext(this) as common.UIAbilityContext);
    if (s.text !== undefined) {
      this.take(s.text);
    } else if (s.failure !== undefined) {
      this.hint = Errors.shown(s.failure);
    }
  }

  lead(): string {
    const state = app.restoreState;
    if (app.isRoot()) {
      return t('restore_root');
    }
    if (state === 'restoring') {
      return t('restore_restoring');
    }
    if (state === 'claiming') {
      return t('restore_claiming');
    }
    if (state === 'claimed') {
      return app.claimLeftMs > 0 ? t('restore_claimed_left', Math.ceil(app.claimLeftMs / 3600000)) : t('restore_claimed');
    }
    return t('restore_lead');
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.restore_title'), back: () => {
          if (app.membership !== undefined) {
            router.clear();
            router.replaceUrl({ url: 'pages/Main' });
          } else {
            router.back();
          }
        } })
        Text(this.lead()).fontColor($r('app.color.text'))
        if (app.restoreState === '' || app.restoreState === 'failed') {
          Button($r('app.string.scan'), { type: ButtonType.Capsule }).width('100%').enabled(!app.busy).onClick(() => {
            this.scan();
          })
          TextInput({ placeholder: $r('app.string.restore_paste'), text: this.pasted })
            .onChange((v: string) => {
              this.pasted = v;
            })
          Button($r('app.string.next'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(!app.busy && this.pasted.trim().length > 0)
            .onClick(() => {
              this.take(this.pasted);
            })
        }
        if (app.restoreState === 'claimed' || app.isRoot()) {
          Button($r('app.string.restore_open'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            router.clear();
            router.replaceUrl({ url: 'pages/Main' });
          })
        }
        BusyLine({ busy: app.restoreState === 'restoring' || app.restoreState === 'claiming' })
        ErrorText({ text: this.hint })
        ErrorText({ text: app.error })
      }
      .padding(24)
      .alignItems(HorizontalAlign.Start)
      .width('100%')
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
