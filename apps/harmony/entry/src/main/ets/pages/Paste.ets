// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Remote paste (docs/design.md, "Remote paste"), as the iPhone's and
// Android's: a text to put where a device's focus is, pasted or typed, with
// Enter after it if asked; a secret leaves no trace there. The device takes
// it only when its user turned remote paste on there. A picture or files
// go to the group as a copy, which the device pastes as Ctrl+V would. The
// admin key signs it after the face, fingerprint or PIN.

import { common } from '@kit.AbilityKit';
import { picker } from '@kit.CoreFileKit';
import { router } from '@kit.ArkUI';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { clipboardText } from '../common/Clipboard';
import { copyIn, Shared } from '../common/Share';
import { app } from '../model/AppModel';
import { Device } from '../model/Member';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct Paste {
  @Local deviceId: string = '';
  @Local text: string = '';
  @Local typing: boolean = false;
  @Local enter: boolean = false;
  @Local secret: boolean = false;
  @Local error: string = '';

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    this.deviceId = params !== undefined && params['device'] !== undefined ? String(params['device']) : '';
    app.show('');
  }

  name(): string {
    const d = app.member.devices.find((d: Device) => d.id === this.deviceId);
    return d !== undefined ? d.name : this.deviceId;
  }

  async send(): Promise<void> {
    if (this.text.length === 0) {
      this.error = t('paste_clipboard_empty');
      return;
    }
    this.error = '';
    if (await app.pasteOn(this.deviceId, this.text, this.typing ? 'type' : 'paste', this.enter, this.secret)) {
      this.getUIContext().getPromptAction().showToast({ message: t('pasted') });
      router.back();
    }
  }

  // Picks a picture or files with the system's picker, which needs no
  // permission, and pastes them.
  async pick(): Promise<void> {
    const context = getContext(this) as common.UIAbilityContext;
    let uris: string[] = [];
    try {
      const options = new picker.DocumentSelectOptions();
      options.maxSelectNumber = 20;
      uris = await new picker.DocumentViewPicker(context).select(options);
    } catch (e) {
      this.error = Errors.shown(Errors.unexpected(t('error_share_nothing'), e as Object));
      return;
    }
    if (uris.length === 0) {
      return;
    }
    const picked = new Shared();
    copyIn(uris, `${context.cacheDir}/paste-${Date.now()}`, picked);
    this.error = '';
    if (await app.pasteMedia(this.deviceId, picked.files, picked.types, this.enter)) {
      this.getUIContext().getPromptAction().showToast({ message: t('pasted') });
      router.back();
    }
  }

  @Builder
  switchRow(label: string, on: boolean, change: (on: boolean) => void) {
    Row() {
      Text(label).fontColor($r('app.color.text')).layoutWeight(1)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor($r('app.color.accent'))
        .onChange(change)
    }
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: t('paste_on_title', this.name()), back: () => {
          router.back();
        } })

        TextArea({ text: this.text, placeholder: t('paste_text') })
          .height(120)
          .onChange((value: string) => {
            this.text = value;
          })
        Text(t('paste_on_body', this.name())).fontSize(12).fontColor($r('app.color.secondary'))

        // HarmonyOS lets an app read what was copied only through the
        // system's paste button: a tap puts it in the field.
        PasteButton({ icon: PasteIconStyle.LINES, text: PasteDescription.PASTE, buttonType: ButtonType.Capsule })
          .onClick(async (event: ClickEvent, result: PasteButtonOnClickResult) => {
            if (result === PasteButtonOnClickResult.SUCCESS) {
              this.text = await clipboardText();
            }
          })

        this.switchRow(t('paste_type'), this.typing, (on: boolean) => {
          this.typing = on;
        })
        this.switchRow(t('paste_enter'), this.enter, (on: boolean) => {
          this.enter = on;
        })
        this.switchRow(t('paste_secret'), this.secret, (on: boolean) => {
          this.secret = on;
        })
        Text($r('app.string.paste_note')).fontSize(12).fontColor($r('app.color.secondary'))

        Button($r('app.string.paste'), { type: ButtonType.Capsule })
          .width('100%')
          .enabled(!app.busy && this.text.length > 0)
          .onClick(() => {
            this.send();
          })
        Button($r('app.string.paste_pick'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
          .width('100%')
          .enabled(!app.busy)
          .onClick(() => {
            this.pick();
          })
        Text($r('app.string.paste_pick_note')).fontSize(12).fontColor($r('app.color.secondary'))
        BusyLine({ busy: app.busy })
        ErrorText({ text: this.error })
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
