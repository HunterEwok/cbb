// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Moving the group's main device to this phone with the recovery key
// (docs/apps.md, "Changing the main device"): the key from the sheet's QR
// code, its typed text or a YubiKey that holds it, then the list of who
// stays, which the core writes and the person only unticks (this phone is
// never in it), then the fingerprint, the face or the PIN that the root key
// in HUKS asks for. The old main device starts unticked. The key stays on
// the page only until the change is made or the page closes.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { canReachCard } from '../common/YubiKey';
import { scanQr } from '../common/Scan';
import { Errors } from '../core/Errors';
import { app, ChangePreview, ChangeRow } from '../model/AppModel';
import { Device } from '../model/Member';
import { BusyLine, EMPHASIZED_BUTTON, ErrorText, NORMAL_BUTTON, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct ChangeRoot {
  @Local recovery: Record<string, Object> | undefined = undefined;
  @Local preview: ChangePreview | undefined = undefined;
  @Local leaveOut: string[] = [];
  @Local overWaiting: boolean = false;
  @Local typed: string = '';
  @Local askingPin: boolean = false;
  @Local pin: string = '';
  @Local note: string = '';

  aboutToAppear(): void {
    app.show('');
  }

  aboutToDisappear(): void {
    this.recovery = undefined;
    this.pin = '';
  }

  hasCard(): boolean {
    return canReachCard();
  }

  async start(r: Record<string, Object>): Promise<void> {
    if (this.recovery !== undefined || app.busy) {
      return;
    }
    const old = app.member.devices.filter((d: Device) => d.root === true).map((d: Device) => d.id);
    const p = await app.changePreview(r, old);
    if (p !== undefined) {
      this.recovery = r;
      this.leaveOut = old;
      this.preview = p;
    }
  }

  async toggle(device: string): Promise<void> {
    const r = this.recovery;
    if (r === undefined) {
      return;
    }
    this.leaveOut = this.leaveOut.includes(device) ? this.leaveOut.filter((d: string) => d !== device) :
      this.leaveOut.concat([device]);
    const p = await app.changePreview(r, this.leaveOut);
    if (p !== undefined) {
      this.preview = p;
    }
  }

  async scan(): Promise<void> {
    const s = await scanQr(getContext(this) as common.UIAbilityContext);
    if (s.text !== undefined) {
      await this.start({ 'qr': s.text } as Record<string, Object>);
    } else if (s.failure !== undefined) {
      app.show(Errors.shown(s.failure));
    }
  }

  async openCard(): Promise<void> {
    const pin = this.pin;
    this.pin = '';
    this.askingPin = false;
    const secret = await app.openCard(getContext(this) as common.UIAbilityContext, pin, () => {
      this.note = t('yubikey_touch_usb');
    });
    this.note = '';
    if (secret !== undefined) {
      this.note = t('yubikey_opened');
      // The secret goes to the core for this change only.
      await this.start({ 'secret': secret } as Record<string, Object>);
    }
  }

  confirm(): void {
    this.getUIContext().showAlertDialog({
      message: t('change_root_cannot_undo'),
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('change_root_confirm'), fontColor: $r('app.color.error'), action: () => {
        this.change();
      } }
    });
  }

  async change(): Promise<void> {
    const r = this.recovery;
    if (r === undefined) {
      return;
    }
    if (await app.changeRoot(r, this.leaveOut, this.overWaiting)) {
      this.recovery = undefined;
      router.back();
    }
  }

  outcome(row: ChangeRow): string {
    switch (row.outcome) {
      case 'out':
        return t('change_root_out');
      case 'admin_kept':
        return t('change_root_admin_kept');
      case 'admin_lost':
        return t('change_root_admin_lost');
      case 'frozen':
        return t('change_root_frozen');
      default:
        return row.frozen ? t('change_root_frozen') : t('change_root_stays');
    }
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.change_root'), back: () => {
          router.back();
        } })
        if (this.note.length > 0) {
          Text(this.note).fontColor($r('app.color.secondary'))
        }
        if (this.preview === undefined) {
          Text(t('change_root_tip')).fontColor($r('app.color.text'))
          Button($r('app.string.scan'), { type: ButtonType.Capsule }).width('100%').enabled(!app.busy).onClick(() => {
            this.scan();
          })
          TextArea({ placeholder: t('change_root_key_text'), text: this.typed })
            .fontFamily('monospace')
            .height(120)
            .onChange((v: string) => {
              this.typed = v;
            })
          Button(t('change_root_next'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
            .width('100%')
            .enabled(!app.busy && this.typed.trim().length > 0)
            .onClick(() => {
              this.start({ 'text': this.typed } as Record<string, Object>);
            })
          Text(t('change_root_key_hint')).fontSize(14).fontColor($r('app.color.secondary'))
          if (this.hasCard()) {
            if (!this.askingPin) {
              Button(t('yubikey_open'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
                .width('100%')
                .enabled(!app.busy)
                .onClick(() => {
                  this.askingPin = true;
                })
            } else {
              Text(t('yubikey_open_title')).fontWeight(FontWeight.Medium).fontColor($r('app.color.text'))
              Text(t('yubikey_open_body')).fontColor($r('app.color.text'))
              TextInput({ placeholder: t('yubikey_pin'), text: this.pin })
                .type(InputType.Password)
                .maxLength(8)
                .onChange((v: string) => {
                  this.pin = v;
                })
              Button(t('yubikey_go'), { type: ButtonType.Capsule })
                .width('100%')
                .enabled(!app.busy && this.pin.length >= 6)
                .onClick(() => {
                  this.openCard();
                })
            }
          }
        } else {
          Text(t('change_root_who_stays')).fontWeight(FontWeight.Medium).fontColor($r('app.color.text'))
          ForEach(this.preview.rows, (row: ChangeRow) => {
            Row({ space: 8 }) {
              Column() {
                Text(row.name).fontColor($r('app.color.text'))
                Text(this.outcome(row)).fontSize(14).fontColor($r('app.color.secondary'))
              }.alignItems(HorizontalAlign.Start).layoutWeight(1)
              Toggle({ type: ToggleType.Switch, isOn: !this.leaveOut.includes(row.device) })
                .enabled(!app.busy)
                .onChange(() => {
                  this.toggle(row.device);
                })
            }.width('100%')
          }, (row: ChangeRow) => `${row.device}:${row.outcome}:${this.leaveOut.includes(row.device)}`)
          if (this.preview.waiting) {
            Text(t('change_root_waiting_body')).fontSize(14).fontColor($r('app.color.error'))
            Row({ space: 8 }) {
              Text(t('change_root_over_waiting')).fontColor($r('app.color.text')).layoutWeight(1)
              Toggle({ type: ToggleType.Switch, isOn: this.overWaiting }).onChange((on: boolean) => {
                this.overWaiting = on;
              })
            }.width('100%')
          }
          Button(t('change_root_confirm'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.EMPHASIZED }).attributeModifier(EMPHASIZED_BUTTON)
            .width('100%')
            .enabled(!app.busy && (!this.preview.waiting || this.overWaiting))
            .onClick(() => {
              this.confirm();
            })
          Text(t('change_root_cannot_undo')).fontSize(14).fontColor($r('app.color.secondary'))
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
