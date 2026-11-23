// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What Home shows above the devices about the group itself, as the other
// phones show it (docs/apps.md, "Notices" and "Changing the main device"):
// that the group removed this phone, with Leave; that the main device
// changed, with "This wasn't me", until the person saw it; and the
// member's notices, each in a sentence, with Hide on one that may be
// hidden.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { Device, Notice } from '../model/Member';
import { NORMAL_BUTTON } from './Common';

// A device's name as the group's devices show it, else its ID.
function nameOf(id: string): string {
  const d = app.member.devices.find((x: Device) => x.id === id);
  return d !== undefined && d.name.length > 0 ? d.name : id;
}

// The notice in a sentence; empty for a kind this app does not show.
export function noticeText(n: Notice): string {
  const args: Record<string, string> = n.args ?? {};
  const device = args['device'] !== undefined ? nameOf(args['device']) : '';
  switch (n.kind) {
    case 'change_arriving':
      return t('notice_change_arriving');
    case 'admins_silent': {
      const days = parseInt(args['days_left'] ?? '0') || 0;
      return days > 0 ? t('notice_admins_silent', device, days) : t('notice_admins_silent_now', device);
    }
    case 'removals_waiting':
      return t('notice_removals_waiting');
    case 'root_room_waiting':
      return t('notice_root_room_waiting', `${args['percent'] ?? ''}%`);
    case 'ack_owed':
      return t('notice_ack_owed');
    case 'frozen_holding':
      return t('notice_frozen_holding', device);
    case 'checkpoint_stuck':
      return t('notice_checkpoint_stuck');
    case 'returned_after_removal':
      return t('notice_returned_after_removal', device);
    case 'recovery_not_saved':
      return t('notice_recovery_not_saved');
    default:
      return '';
  }
}

@ComponentV2
export struct GroupCards {
  @Local notMe: boolean = false;

  leave(): void {
    this.getUIContext().showAlertDialog({
      message: app.isRoot() ? t('settings_leave_root_confirm') : t('settings_leave_confirm'),
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('settings_leave'), fontColor: $r('app.color.error'), action: async () => {
        await app.member.rootChangeSeen();
        if (await app.leave()) {
          router.clear();
          router.replaceUrl({ url: 'pages/Start' });
        }
      } }
    });
  }

  build() {
    Column({ space: 12 }) {
      if (app.member.removed) {
        Column({ space: 8 }) {
          Text($r('app.string.removed_self_title')).fontSize(17).fontWeight(FontWeight.Medium).fontColor($r('app.color.error'))
          Text($r('app.string.removed_self_text')).fontSize(14).fontColor($r('app.color.secondary'))
          Button($r('app.string.settings_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
            .fontColor($r('app.color.error'))
            .enabled(!app.busy)
            .onClick(() => {
              this.leave();
            })
        }
        .alignItems(HorizontalAlign.Start)
        .padding(12)
        .borderRadius(14)
        .backgroundColor($r('app.color.surface'))
        .width('100%')
      }
      if (app.member.rootChangedTo.length > 0) {
        Column({ space: 8 }) {
          Text($r('app.string.root_changed_title')).fontSize(17).fontWeight(FontWeight.Medium).fontColor($r('app.color.text'))
          Text(t('root_changed_body', app.member.rootChangedTo, app.member.rootChangedFrom)).fontSize(14).fontColor($r('app.color.secondary'))
          Row({ space: 12 }) {
            Button($r('app.string.root_changed_ok'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
              .onClick(() => {
                app.member.rootChangeSeen();
              })
            Button($r('app.string.root_changed_not_me'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
              .onClick(() => {
                this.notMe = !this.notMe;
              })
          }
          if (this.notMe) {
            Text($r('app.string.root_changed_not_me_title')).fontSize(15).fontWeight(FontWeight.Bold).fontColor($r('app.color.error'))
            Text($r('app.string.root_changed_not_me_body')).fontSize(14).fontColor($r('app.color.secondary'))
            Button($r('app.string.settings_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
              .fontColor($r('app.color.error'))
              .enabled(!app.busy)
              .onClick(() => {
                this.leave();
              })
          }
        }
        .alignItems(HorizontalAlign.Start)
        .padding(12)
        .borderRadius(14)
        .backgroundColor($r('app.color.surface'))
        .width('100%')
      }
      if (app.member.notices.some((n: Notice) => noticeText(n).length > 0)) {
        Column({ space: 8 }) {
          ForEach(app.member.notices.filter((n: Notice) => noticeText(n).length > 0), (n: Notice) => {
            Row({ space: 8 }) {
              Text(noticeText(n)).fontSize(14).fontColor($r('app.color.text')).layoutWeight(1)
              if (n.dismissable !== false) {
                // A target a finger hits: 48 vp square.
                Button({ type: ButtonType.Circle }) {
                  Text('✕').fontSize(14).fontColor($r('app.color.secondary'))
                }
                .width(48)
                .height(48)
                .backgroundColor(Color.Transparent)
                .accessibilityText(t('notice_hide'))
                .onClick(() => {
                  app.member.dismissNotice(n.id);
                })
              }
            }
            .width('100%')
          }, (n: Notice) => n.id)
        }
        .alignItems(HorizontalAlign.Start)
        .padding(12)
        .borderRadius(14)
        .backgroundColor($r('app.color.surface'))
        .width('100%')
      }
    }
    .width('100%')
  }
}
