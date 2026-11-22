// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The root's recovery key (docs/apps.md, "Recovery key"): made with the
// group. Right after the group is made the page offers where to save it:
// "Write on a sheet" shows the sheet (its text and QR code), which prints
// or saves as a picture through the system's printing and save picker, and
// "Write to YubiKey" waits for a YubiKey plugged in or held to the phone,
// asks its PIN, and the core seals the key into the card's first empty
// retired slot. Both are allowed; leaving without either asks first. On 0.6
// the key is part of the group's ID: nothing makes a new one or removes it
// (D-126), and later the page only says so.

import { common } from '@kit.AbilityKit';
import { componentSnapshot, promptAction, router } from '@kit.ArkUI';
import { print } from '@kit.BasicServicesKit';
import { fileIo, fileUri, picker } from '@kit.CoreFileKit';
import { image } from '@kit.ImageKit';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { canReachCard } from '../common/YubiKey';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { QrView } from '../components/QrView';

// The sheet's component, which the picture is taken of.
const SHEET_ID: string = 'recoverySheet';

@Entry
@ComponentV2
struct Recovery {
  // What the person looks at: the choice, the sheet, or the YubiKey's PIN.
  @Local step: string = 'choice';
  @Local sheetSeen: boolean = false;
  @Local kept: boolean = false;
  @Local sealed: boolean = false;
  @Local note: string = '';
  // The YubiKey found, waiting for its PIN: true on USB, false over NFC.
  @Local usb: boolean = false;
  @Local pin: string = '';
  // The picture of the sheet in the app's temporary files, while it lives.
  private picture: string = '';

  aboutToDisappear(): void {
    this.pin = '';
    this.dropPicture();
    app.forgetRecovery();
  }

  context(): common.UIAbilityContext {
    return getContext(this) as common.UIAbilityContext;
  }

  dropPicture(): void {
    if (this.picture.length > 0) {
      try {
        fileIo.unlinkSync(this.picture);
      } catch (e) {
        Errors.log(`recovery: the sheet's picture stays: ${String(e)}`);
      }
      this.picture = '';
    }
  }

  // The sheet as a PNG: taken of its component on screen, written to the
  // app's temporary files for printing, and its bytes.
  async sheetPicture(): Promise<ArrayBuffer> {
    const pixels = await componentSnapshot.get(SHEET_ID);
    const png = await image.createImagePacker().packing(pixels, { format: 'image/png', quality: 100 });
    this.dropPicture();
    const path = `${this.context().tempDir}/recovery-sheet.png`;
    const f = fileIo.openSync(path, fileIo.OpenMode.CREATE | fileIo.OpenMode.TRUNC | fileIo.OpenMode.WRITE_ONLY);
    try {
      fileIo.writeSync(f.fd, png);
    } finally {
      fileIo.closeSync(f);
    }
    this.picture = path;
    return png;
  }

  async printSheet(): Promise<void> {
    try {
      await this.sheetPicture();
      await print.print([fileUri.getUriFromPath(this.picture)]);
      this.kept = true;
    } catch (e) {
      app.show(Errors.shown(Errors.unexpected('recovery: printing the sheet', e as Object)));
    }
  }

  async saveSheet(): Promise<void> {
    try {
      const png = await this.sheetPicture();
      const uris = await new picker.DocumentViewPicker(this.context()).save({ newFileNames: [`${t('recovery_page_title')}.png`] });
      if (uris.length === 0) {
        return;
      }
      const f = fileIo.openSync(uris[0], fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.TRUNC);
      try {
        fileIo.writeSync(f.fd, png);
      } finally {
        fileIo.closeSync(f);
      }
      this.kept = true;
      Errors.log('recovery: the sheet saved through the save picker');
    } catch (e) {
      app.show(Errors.shown(Errors.unexpected('recovery: saving the sheet', e as Object)));
    } finally {
      this.dropPicture();
    }
  }

  async findKey(): Promise<void> {
    this.note = t('yubikey_insert_or_hold');
    const usb = await app.findCard(this.context());
    this.note = '';
    if (usb !== undefined) {
      this.usb = usb;
      this.step = 'pin';
    }
  }

  async seal(): Promise<void> {
    const pin = this.pin;
    this.pin = '';
    this.note = this.usb ? t('yubikey_writing') : t('yubikey_hold');
    const said = await app.sealOnCard(this.context(), pin, () => {
      this.note = t('yubikey_writing');
    });
    this.note = said;
    this.step = 'choice';
    if (said.length > 0) {
      this.sealed = true;
    }
  }

  leave(): void {
    if (this.sealed || this.kept) {
      app.forgetRecovery();
      router.back();
      return;
    }
    const sheetOnly = this.sheetSeen;
    promptAction.showDialog({
      title: sheetOnly ? t('recovery_done_title') : t('recovery_unsaved_title'),
      message: t('recovery_unsaved_body'),
      buttons: [
        { text: sheetOnly ? t('recovery_wrote') : t('recovery_leave_unsaved'), color: '#d0021b' },
        { text: t('back'), color: '#007dff' }
      ]
    }).then((r: promptAction.ShowDialogSuccessResponse) => {
      if (r.index === 0) {
        app.forgetRecovery();
        router.back();
      }
    });
  }

  @Builder
  sheet() {
    Column({ space: 12 }) {
      Text($r('app.string.recovery_page_title')).fontWeight(FontWeight.Bold).fontSize(20).fontColor('#000000')
      Column() {
        QrView({ modules: app.recoveryModules, side: 240 })
      }
      .width('100%')
      .alignItems(HorizontalAlign.Center)
      Text(app.recoveryText)
        .fontFamily('monospace')
        .fontSize(18)
        .fontColor('#000000')
        .width('100%')
        .textAlign(TextAlign.Center)
      Text($r('app.string.recovery_page_keep')).fontSize(14).fontColor('#000000')
    }
    .id(SHEET_ID)
    .padding(20)
    .backgroundColor('#ffffff')
    .borderRadius(12)
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({
          title: app.recoveryText.length > 0 ? $r('app.string.recovery_save_title') : $r('app.string.recovery_title'),
          back: () => {
            if (app.recoveryText.length === 0) {
              router.back();
            } else if (this.step !== 'choice') {
              this.step = 'choice';
            } else {
              this.leave();
            }
          }
        })
        if (app.recoveryText.length === 0) {
          Text(t('recovery_06')).fontColor($r('app.color.text'))
        } else if (this.step === 'sheet') {
          Text(t('recovery_write_down')).fontColor($r('app.color.text'))
          this.sheet()
          Button(t('recovery_print'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            this.printSheet();
          })
          Button(t('recovery_save_file'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .onClick(() => {
              this.saveSheet();
            })
          Text(t('recovery_file_warning')).fontColor($r('app.color.secondary'))
          Button(t('back'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.TEXTUAL }).width('100%').onClick(() => {
            this.step = 'choice';
          })
        } else if (this.step === 'pin') {
          Text(t('yubikey_write')).fontWeight(FontWeight.Medium).fontColor($r('app.color.text'))
          Text(this.usb ? t('yubikey_pin_type') : t('yubikey_pin_then_hold')).fontColor($r('app.color.text'))
          TextInput({ placeholder: t('yubikey_pin'), text: this.pin })
            .type(InputType.Password)
            .maxLength(8)
            .enterKeyType(EnterKeyType.Go)
            .onChange((v: string) => {
              this.pin = v;
            })
            .onSubmit(() => {
              if (!app.busy && this.pin.length >= 6) {
                this.seal();
              }
            })
          Button(t('yubikey_go'), { type: ButtonType.Capsule })
            .width('100%')
            .enabled(!app.busy && this.pin.length >= 6)
            .onClick(() => {
              this.seal();
            })
          Button(t('back'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.TEXTUAL }).width('100%').onClick(() => {
            this.pin = '';
            this.step = 'choice';
          })
        } else {
          Text(t('recovery_save_body')).fontColor($r('app.color.text'))
          Button(t('recovery_write_sheet'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            this.step = 'sheet';
            this.sheetSeen = true;
          })
          if (canReachCard() && app.recoveryQr.length > 0) {
            Button(t('yubikey_write'), { type: ButtonType.Capsule })
              .width('100%')
              .enabled(!app.busy && !this.sealed)
              .onClick(() => {
                this.findKey();
              })
          }
          Button(t('done'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).width('100%').onClick(() => {
            this.leave();
          })
        }
        if (this.note.length > 0) {
          Text(this.note).fontColor($r('app.color.secondary'))
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
