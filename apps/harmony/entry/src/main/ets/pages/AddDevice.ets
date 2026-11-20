// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Adding a device by the code it shows: Scan Kit reads it (or the user
// pastes its text), and the phone admits the device, signing with the admin
// key after the user's consent. A phone joins as a member: the root makes it
// an admin later, from its device page.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { app } from '../model/AppModel';
import { Admit } from '../model/Admit';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct AddDevice {
  @Local pasted: string = '';
  @Local hint: string = '';

  aboutToAppear(): void {
    app.admit.reset();
    const params = router.getParams() as Record<string, Object> | undefined;
    if (params !== undefined && params['qr'] !== undefined) {
      this.take(String(params['qr']));
    }
  }

  take(text: string): void {
    this.hint = '';
    if (!Admit.isJoinCode(text)) {
      this.hint = Errors.shown(new Failure(t('error_not_join_code'), 'admit: the text does not start with cbb://join?'));
      return;
    }
    app.startAdmit(text);
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
    const step = app.admit.state;
    if (step === 'preparing' || step === 'dialing') {
      return t('admit_connecting');
    }
    if (step === 'admitting') {
      return t('admit_admitting');
    }
    if (step === 'admitted' || step === 'confirmed') {
      return app.admit.device.length > 0 ? t('admit_done_named', app.admit.device) : t('admit_done');
    }
    return t('admit_lead');
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.admit_title'), back: () => {
          router.back();
        } })
        Text(this.lead()).fontColor($r('app.color.text'))
        if (app.admit.state === 'idle' || app.admit.state === 'failed') {
          Button(app.admit.state === 'failed' ? $r('app.string.try_again') : $r('app.string.scan'), { type: ButtonType.Capsule })
            .width('100%')
            .onClick(() => {
              this.scan();
            })
          TextInput({ placeholder: $r('app.string.admit_paste'), text: this.pasted })
            .onChange((v: string) => {
              this.pasted = v;
            })
          Button($r('app.string.next'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(this.pasted.trim().length > 0)
            .onClick(() => {
              this.take(this.pasted);
            })
        }
        if (app.admit.state === 'admitted' || app.admit.state === 'confirmed') {
          Button($r('app.string.admit_another'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .onClick(() => {
              app.admit.reset();
            })
          Button($r('app.string.done'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            router.back();
          })
        }
        BusyLine({ busy: app.admit.state === 'preparing' || app.admit.state === 'dialing' || app.admit.state === 'admitting' })
        ErrorText({ text: this.hint })
        ErrorText({ text: app.admit.error })
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
