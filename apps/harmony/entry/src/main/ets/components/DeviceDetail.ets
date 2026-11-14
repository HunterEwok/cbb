// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A device's details (docs/apps.md, Devices), the page Device and, on a big
// screen, the pane beside Home's devices: its sync, and for an
// admin its changes and commands: paste on it, rename, mute, freeze's thaw, make an admin (the root,
// for a phone or a computer that offers an admin key), hand the group over (the root),
// take the group over (an admin, from a lost root), remove. A removal by
// the root is final, so the page asks first and says so.

import { router } from '@kit.ArkUI';
import { guardsLikeAPhone } from '../core/Keys';
import { t } from '../core/Text';
import { can, kind, line, mark, nameOf, role, status } from '../common/Devices';
import { app } from '../model/AppModel';
import { Device as DeviceInfo } from '../model/Member';

import { BusyLine, ErrorText, PageTitle } from './Common';

// Members take remote pastes, and the phones that type them on a keyboard
// or into their own focus; an iPhone cannot.
export function takesPastes(d: DeviceInfo): boolean {
  return d.role === 'member' || (d.role === 'phone' && ['android', 'aurora', 'harmonyos'].includes(d.os ?? ''));
}

@ComponentV2
export struct DeviceDetail {
  @Param @Require deviceId: string = '';
  // Back from the page, or the pane's close.
  @Event close: () => void = () => {};
  @Local renaming: boolean = false;
  @Local name: string = '';

  @Monitor('deviceId')
  otherDevice(): void {
    this.renaming = false;
  }

  device(): DeviceInfo | undefined {
    return app.member.devices.find((d: DeviceInfo) => d.id === this.deviceId);
  }

  // Whether this phone may act on the device: an admin, not on itself.
  acts(d: DeviceInfo): boolean {
    return app.isAdmin() && app.member.running && d.self !== true;
  }

  confirm(message: string, button: string, yes: () => void): void {
    this.getUIContext().showAlertDialog({
      message: message,
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: button, fontColor: $r('app.color.error'), action: yes }
    });
  }

  async remove(d: DeviceInfo): Promise<void> {
    if (await app.manage('remove', d.id)) {
      this.close();
    }
  }

  claimLine(): string {
    if (app.claimState === 'pending') {
      return t('device_claim_left', Math.ceil(app.claimLeftMs / 3600000));
    }
    if (app.claimState === 'none') {
      return t('device_claim_none');
    }
    return t('device_claim_disputed');
  }

  @Builder
  action(label: string, danger: boolean, act: () => void) {
    Button(label, { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
      .width('100%')
      .fontColor(danger ? $r('app.color.error') : $r('app.color.text'))
      .enabled(!app.busy)
      .onClick(act)
  }

  @Builder
  detail(label: string, value: string) {
    if (value.length > 0) {
      Row({ space: 8 }) {
        Text(label).fontSize(13).fontColor($r('app.color.secondary')).width('40%')
        Text(value).fontSize(13).fontColor($r('app.color.text')).layoutWeight(1).copyOption(CopyOptions.LocalDevice)
      }
      .width('100%')
    }
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        if (this.device() !== undefined) {
          PageTitle({ title: nameOf(this.device() as DeviceInfo), back: () => {
            this.close();
          } })
          Text([mark(this.device() as DeviceInfo), (this.device() as DeviceInfo).self === true ? '' : status(this.device() as DeviceInfo)]
            .filter((s: string) => s.length > 0).join(' · '))
            .fontColor($r('app.color.secondary'))
          Text(line(this.device() as DeviceInfo)).fontColor($r('app.color.accent'))

          // This phone's sync, or for an admin another device's, through a
          // mode command it signs.
          if ((this.device() as DeviceInfo).self === true ? app.member.running :
            this.acts(this.device() as DeviceInfo) && ((this.device() as DeviceInfo).mode ?? '').length > 0) {
            Row() {
              Text($r('app.string.main_switch_sync')).fontColor($r('app.color.text')).layoutWeight(1)
              Toggle({
                type: ToggleType.Switch,
                isOn: (this.device() as DeviceInfo).self === true ? !app.member.paused : (this.device() as DeviceInfo).mode === 'shared'
              })
                .selectedColor($r('app.color.accent'))
                .enabled(!app.busy)
                .onChange((on: boolean) => {
                  const d = this.device() as DeviceInfo;
                  if (d.self === true) {
                    if (on) {
                      app.member.resume();
                    } else {
                      app.member.pause(0);
                    }
                  } else {
                    app.manage(on ? 'sync_on' : 'sync_off', d.id);
                  }
                })
            }
            .width('100%')
          }

          if (app.isRoot() && app.member.rootView.handed_to === this.deviceId) {
            Text($r('app.string.device_handed_over')).fontSize(14).fontColor($r('app.color.accent'))
          }
          if ((this.device() as DeviceInfo).root === true && app.claimState.length > 0) {
            Text(this.claimLine()).fontSize(14).fontColor($r('app.color.accent'))
          }

          if (this.renaming) {
            TextInput({ text: this.name, placeholder: $r('app.string.device_name') })
              .maxLength(64)
              .onChange((v: string) => {
                this.name = v;
              })
            Row({ space: 8 }) {
              Button(t('cancel'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).onClick(() => {
                this.renaming = false;
              })
              Button(t('device_rename'), { type: ButtonType.Capsule }).enabled(this.name.trim().length > 0).onClick(() => {
                this.renaming = false;
                app.manage('rename', this.deviceId, this.name.trim());
              })
            }
          }

          if (this.acts(this.device() as DeviceInfo) || (app.isAdmin() && app.member.running)) {
            Column({ space: 8 }) {
              if (app.isAdmin() && app.member.running) {
                this.action(t('device_rename'), false, () => {
                  this.name = (this.device() as DeviceInfo).name;
                  this.renaming = true;
                })
              }
              if (this.acts(this.device() as DeviceInfo) && takesPastes(this.device() as DeviceInfo)) {
                this.action(t('paste_on_it'), false, () => {
                  router.pushUrl({ url: 'pages/Paste', params: { 'device': this.deviceId } });
                })
              }
              if (this.acts(this.device() as DeviceInfo)) {
                if ((this.device() as DeviceInfo).root === true && !app.isRoot() && app.claimState.length === 0) {
                  this.action(t('device_take_over'), true, () => {
                    // Before this device becomes the group's main device: how well it guards the group.
                    const weak = guardsLikeAPhone() ? '' : `\n\n${t('key_guard_weak')}`;
                    this.confirm(t('device_take_over_confirm') + weak, t('device_take_over'), () => {
                      app.takeOver(this.deviceId);
                    });
                  })
                }
                // The admin key comes from the device's hello: a computer's
                // with the admin capability, or a phone's.
                if (app.isRoot() && (this.device() as DeviceInfo).admin !== true &&
                  ((this.device() as DeviceInfo).role === 'phone' || can(this.device() as DeviceInfo, 'admin'))) {
                  this.action(t('device_make_admin'), false, () => {
                    const phone = (this.device() as DeviceInfo).role === 'phone';
                    this.confirm(t(phone ? 'device_make_admin_phone_confirm' : 'device_make_admin_confirm'), t('device_make_admin'), () => {
                      app.manage('make_admin', this.deviceId);
                    });
                  })
                }
                if (app.isRoot() && (this.device() as DeviceInfo).admin === true && (this.device() as DeviceInfo).frozen !== true) {
                  this.action(t('device_hand_over'), true, () => {
                    this.confirm(t('device_hand_over_confirm'), t('device_hand_over'), () => {
                      app.handOver(this.deviceId);
                    });
                  })
                }
                if ((this.device() as DeviceInfo).frozen === true) {
                  this.action(t('device_thaw'), false, () => {
                    this.confirm(t('device_thaw_confirm'), t('device_thaw'), () => {
                      app.manage('thaw', this.deviceId);
                    });
                  })
                }
                this.action(t('device_mute_hour'), false, () => {
                  app.manage('mute', this.deviceId, '', 60);
                })
                this.action(t('device_mute'), false, () => {
                  app.manage('mute', this.deviceId, '', 0);
                })
                this.action(t('device_unmute'), false, () => {
                  app.manage('unmute', this.deviceId);
                })
                if ((this.device() as DeviceInfo).root !== true) {
                  this.action(t('device_remove'), true, () => {
                    const d = this.device() as DeviceInfo;
                    this.confirm(app.isRoot() ? t('device_remove_confirm_final') : t('device_remove_confirm'),
                      t('device_remove'), () => {
                        this.remove(d);
                      });
                  })
                }
              }
            }
            .width('100%')
          }

          Divider()
          this.detail(t('device_type'), kind(this.device() as DeviceInfo))
          this.detail(t('device_in_group'), role(this.device() as DeviceInfo))
          this.detail(t('device_os_version'), (this.device() as DeviceInfo).os_version ?? '')
          this.detail(t('device_mac'), (this.device() as DeviceInfo).mac ?? '')
          this.detail(t('device_id'), this.deviceId)
        } else {
          PageTitle({ title: '', back: () => {
            this.close();
          } })
          Text($r('app.string.device_gone')).fontColor($r('app.color.secondary'))
        }
        BusyLine({ busy: app.busy })
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
