// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The root's recovery key (docs/apps.md, "Recovery key"): made, shown once
// as its text and QR code to write down or print, or put on a YubiKey held
// to the phone (common/YubiKey.ets); replaced or removed.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { QrView } from '../components/QrView';

@Entry
@ComponentV2
struct Recovery {
  // The YubiKey's PIN, typed when the user chose to put the key on one.
  @Local onCard: boolean = false;
  @Local pin: string = '';

  aboutToAppear(): void {
    app.cardDone = false;
  }

  aboutToDisappear(): void {
    app.forgetRecovery();
    this.pin = '';
  }

  confirm(message: string, button: string, yes: () => void): void {
    this.getUIContext().showAlertDialog({
      message: message,
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: button, fontColor: $r('app.color.error'), action: yes }
    });
  }

  lead(): string {
    if (app.recoveryText.length > 0) {
      return t('recovery_write_down');
    }
    if (app.card === 'put') {
      return t('yubikey_hold');
    }
    if (app.cardDone) {
      return t('yubikey_made');
    }
    if (this.onCard) {
      return t('yubikey_put_body');
    }
    return app.member.rootView.recovery === true ? t('recovery_has') : t('recovery_none');
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.recovery_title'), back: () => {
          router.back();
        } })
        Text(this.lead()).fontColor($r('app.color.text'))
        if (app.recoveryText.length > 0) {
          Column() {
            QrView({ modules: app.recoveryModules, side: 240 })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
          Text(app.recoveryText)
            .fontFamily('monospace')
            .fontSize(18)
            .fontColor($r('app.color.text'))
            .width('100%')
            .textAlign(TextAlign.Center)
          Button($r('app.string.recovery_wrote'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            app.forgetRecovery();
          })
        } else if (app.isRoot() && this.onCard && !app.cardDone) {
          TextInput({ placeholder: $r('app.string.yubikey_pin'), text: this.pin })
            .type(InputType.NUMBER_PASSWORD)
            .maxLength(8)
            .enabled(app.card.length === 0)
            .onChange((v: string) => {
              this.pin = v;
            })
          Button($r('app.string.yubikey_go'), { type: ButtonType.Capsule })
            .width('100%')
            .enabled(!app.busy && app.card.length === 0 && app.member.running && this.pin.length >= 6)
            .onClick(() => {
              const go = () => {
                app.putOnYubiKey(getContext(this) as common.UIAbilityContext, this.pin);
              };
              if (app.member.rootView.recovery === true) {
                this.confirm(t('recovery_replace_confirm'), t('yubikey_go'), go);
              } else {
                go();
              }
            })
          Button($r('app.string.cancel'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(app.card.length === 0)
            .onClick(() => {
              this.onCard = false;
              this.pin = '';
            })
        } else if (app.isRoot()) {
          Button(app.member.rootView.recovery === true ? t('recovery_make_new') : t('recovery_make'),
            { type: ButtonType.Capsule })
            .width('100%')
            .enabled(!app.busy && app.member.running)
            .onClick(() => {
              if (app.member.rootView.recovery === true) {
                this.confirm(t('recovery_replace_confirm'), t('recovery_make_new'), () => {
                  app.makeRecovery();
                });
              } else {
                app.makeRecovery();
              }
            })
          Button($r('app.string.yubikey_put'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(!app.busy && app.member.running)
            .onClick(() => {
              app.cardDone = false;
              this.onCard = true;
            })
          if (app.member.rootView.recovery === true) {
            Button(t('recovery_remove'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
              .width('100%')
              .fontColor($r('app.color.error'))
              .enabled(!app.busy && app.member.running)
              .onClick(() => {
                this.confirm(t('recovery_remove_confirm'), t('recovery_remove'), () => {
                  app.removeRecovery();
                });
              })
          }
        }
        BusyLine({ busy: app.busy || app.card.length > 0 })
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
