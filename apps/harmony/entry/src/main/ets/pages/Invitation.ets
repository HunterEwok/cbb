// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// An invitation the phone got (docs/protocol.md, section 12): scanned or
// pasted, read by the core, shown with its group, hub and time, then
// accepted (the Join page goes on) or declined.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { InvitationText, isInvitation, readInvitation } from '../model/Invite';
import { ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct Invitation {
  @Local pasted: string = '';
  @Local read: InvitationText | undefined = undefined;
  @Local error: string = '';

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    if (params !== undefined && params['text'] !== undefined) {
      this.take(String(params['text']));
    }
  }

  take(text: string): void {
    this.error = '';
    if (!isInvitation(text)) {
      this.error = Errors.shown(new Failure(t('error_invite_not'), 'invite: the text does not start with cbb://invite#'));
      return;
    }
    const r = readInvitation(text);
    if (r.error.length > 0) {
      this.error = r.error;
      return;
    }
    this.read = r;
  }

  async scan(): Promise<void> {
    const s = await scanQr(getContext(this) as common.UIAbilityContext);
    if (s.text !== undefined) {
      this.take(s.text);
    } else if (s.failure !== undefined) {
      this.error = Errors.shown(s.failure);
    }
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: this.read === undefined ? $r('app.string.start_invitation') : $r('app.string.invitation_title'),
          back: () => {
            router.back();
          } })
        if (this.read === undefined) {
          Text($r('app.string.invitation_scan_lead')).fontColor($r('app.color.text'))
          Button($r('app.string.scan'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            this.scan();
          })
          TextInput({ placeholder: $r('app.string.invitation_paste'), text: this.pasted })
            .onChange((v: string) => {
              this.pasted = v;
            })
            .onSubmit(() => {
              this.take(this.pasted);
            })
          Button($r('app.string.next'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(this.pasted.trim().length > 0)
            .onClick(() => {
              this.take(this.pasted);
            })
        } else {
          Row({ space: 8 }) {
            Text($r('app.string.invitation_group')).fontColor($r('app.color.secondary'))
            Text(this.read.group).fontColor($r('app.color.text'))
          }
          Row({ space: 8 }) {
            Text($r('app.string.invitation_hub')).fontColor($r('app.color.secondary'))
            Text(this.read.hub).fontFamily('monospace').fontColor($r('app.color.text'))
          }
          Row({ space: 8 }) {
            Text($r('app.string.invitation_until')).fontColor($r('app.color.secondary'))
            Text(new Date(this.read.expiresMs).toLocaleString()).fontColor($r('app.color.text'))
          }
          Text($r('app.string.invitation_note')).fontSize(14).fontColor($r('app.color.secondary'))
          Button($r('app.string.invitation_join'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.EMPHASIZED })
            .width('100%')
            .onClick(() => {
              const text = this.read?.text ?? '';
              router.replaceUrl({ url: 'pages/Join', params: { 'invite': text } as Record<string, Object> });
            })
          Button($r('app.string.invitation_decline'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .onClick(() => {
              router.back();
            })
        }
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
