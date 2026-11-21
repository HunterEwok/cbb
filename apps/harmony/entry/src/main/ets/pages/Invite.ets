// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Sending a remote invitation (docs/protocol.md, section 12): opened on the
// group's hub for an hour, shown as a QR code and text to share, and the
// device that uses it admitted once the user compared its words.

import { router } from '@kit.ArkUI';
import { pasteboard } from '@kit.BasicServicesKit';
import { systemShare } from '@kit.ShareKit';
import { uniformTypeDescriptor } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { QrView } from '../components/QrView';

const INVITE_SECONDS: number = 3600;

@Entry
@ComponentV2
struct Invite {
  @Local error: string = '';

  aboutToAppear(): void {
    app.startInvite(INVITE_SECONDS);
  }

  aboutToDisappear(): void {
    app.invite.cancel();
  }

  lead(): string {
    const step = app.invite.state;
    if (step === 'preparing' || step === 'opening') {
      return t('invite_opening');
    }
    if (step === 'open' || step === 'joining') {
      return t('invite_lead', new Date(app.invite.expiresMs).toLocaleTimeString());
    }
    if (step === 'done') {
      return t('invite_done', app.invite.joined);
    }
    return '';
  }

  copy(): void {
    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, app.invite.text);
    pasteboard.getSystemPasteboard().setData(data).catch((e: Error) => {
      this.error = Errors.shown(Errors.unexpected(t('error_pasteboard'), e));
    });
  }

  async share(): Promise<void> {
    try {
      const data = new systemShare.SharedData({ utd: uniformTypeDescriptor.UniformDataType.PLAIN_TEXT, content: app.invite.text });
      const controller = new systemShare.ShareController(data);
      await controller.show(getContext(this) as common.UIAbilityContext, {
        previewMode: systemShare.SharePreviewMode.DEFAULT,
        selectionMode: systemShare.SelectionMode.SINGLE
      });
    } catch (e) {
      this.error = Errors.shown(Errors.unexpected(t('error_share'), e as Object));
    }
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.main_invite_title'), back: () => {
          router.back();
        } })
        Text(this.lead()).fontColor($r('app.color.text'))
        if (app.invite.state === 'open' && app.invite.modules.length > 0) {
          Column() {
            QrView({ modules: app.invite.modules, side: 260 })
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
          Text($r('app.string.invite_warning')).fontSize(13).fontColor($r('app.color.secondary'))
          Row({ space: 8 }) {
            Button($r('app.string.invite_copy'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).onClick(() => {
              this.copy();
            })
            Button($r('app.string.invite_share'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).onClick(() => {
              this.share();
            })
          }
        }
        if (app.invite.state === 'joining') {
          Text(t('invite_admit_question', app.invite.joiningName, app.invite.joiningOs)).fontColor($r('app.color.text'))
          Text(app.invite.fingerprint)
            .fontSize(26)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.accent'))
            .width('100%')
            .textAlign(TextAlign.Center)
          Button($r('app.string.invite_admit'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.EMPHASIZED })
            .width('100%')
            .onClick(() => {
              app.invite.answer(true);
            })
          Button($r('app.string.invite_not_this'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .onClick(() => {
              app.invite.answer(false);
            })
        }
        if (app.invite.state === 'done' || app.invite.state === 'failed') {
          Button(app.invite.state === 'failed' ? $r('app.string.try_again') : $r('app.string.invite_another'),
            { type: ButtonType.Capsule })
            .width('100%')
            .onClick(() => {
              app.startInvite(INVITE_SECONDS);
            })
        }
        BusyLine({ busy: app.invite.state === 'preparing' || app.invite.state === 'opening' })
        ErrorText({ text: app.invite.error })
        ErrorText({ text: this.error })
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
