// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a Bluetooth keyboard (docs/apps.md, "The lab"), as on
// Aurora and Android: it types the clipboard, at a tap, into a TV, a
// tablet, a console or a computer that paired with it, which needs nothing
// installed. The system asks the user about a
// new device's pairing.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { clipboardText } from '../common/Clipboard';
import { app } from '../model/AppModel';
import { LAYOUTS, RATES } from '../model/Keyboard';
import { ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct Keyboard {
  layoutName(code: string): string {
    return code === 'ru' ? t('keyboard_layout_ru') : t('keyboard_layout_us');
  }

  stateLine(): string {
    const kb = app.keyboard;
    if (kb.state === 'starting') {
      return t('keyboard_starting');
    }
    if (kb.state === 'connected') {
      const host = kb.host();
      return host.length > 0 ? t('keyboard_connected', host) : t('keyboard_device_connected');
    }
    return t('keyboard_no_host');
  }

  @Builder
  switchRow(label: string, note: string, on: boolean, change: (on: boolean) => void) {
    Row() {
      Column({ space: 2 }) {
        Text(label).fontColor($r('app.color.text'))
        if (note.length > 0) {
          Text(note).fontSize(12).fontColor($r('app.color.secondary'))
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor($r('app.color.accent'))
        .onChange(change)
    }
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: $r('app.string.keyboard'), back: () => {
          router.back();
        } })

        this.switchRow(t('keyboard_switch'), t('keyboard_body'), app.keyboard.on, (on: boolean) => {
          app.keyboard.setOn(on);
        })

        if (app.keyboard.on) {
          if (app.keyboard.state === 'failed') {
            ErrorText({ text: app.keyboard.error })
            Button(app.keyboard.denied ? t('keyboard_allow') : t('keyboard_retry'), { type: ButtonType.Capsule })
              .onClick(() => {
                app.keyboard.retry();
              })
          } else {
            Text(this.stateLine()).fontSize(14).fontColor($r('app.color.accent'))
            Text($r('app.string.keyboard_find')).fontSize(12).fontColor($r('app.color.secondary'))
          }
        }

        Row() {
          Text($r('app.string.keyboard_layout')).fontColor($r('app.color.text')).layoutWeight(1)
          Select(LAYOUTS.map((c: string) => {
            const option: SelectOption = { value: this.layoutName(c) };
            return option;
          }))
            .selected(Math.max(LAYOUTS.indexOf(app.keyboard.layout), 0))
            .value(this.layoutName(app.keyboard.layout))
            .onSelect((index: number) => {
              app.keyboard.setLayout(LAYOUTS[index]);
            })
        }
        .width('100%')

        // As on Android: slow devices drop keys typed too fast.
        Row() {
          Text($r('app.string.keyboard_rate')).fontColor($r('app.color.text')).layoutWeight(1)
          Select(RATES.map((r: number) => {
            const option: SelectOption = { value: t('keyboard_rate_value', r) };
            return option;
          }))
            .selected(Math.max(RATES.indexOf(app.keyboard.rate), 0))
            .value(t('keyboard_rate_value', app.keyboard.rate))
            .onSelect((index: number) => {
              app.keyboard.setRate(RATES[index]);
            })
        }
        .width('100%')

        // HarmonyOS lets an app read what was copied only through the
        // system's paste button: a tap types it.
        if (app.keyboard.on) {
          Row({ space: 12 }) {
            PasteButton({ icon: PasteIconStyle.LINES, text: PasteDescription.PASTE, buttonType: ButtonType.Capsule })
              .enabled(app.keyboard.state === 'connected' && !app.keyboard.typing)
              .onClick(async (event: ClickEvent, result: PasteButtonOnClickResult) => {
                if (result === PasteButtonOnClickResult.SUCCESS) {
                  app.keyboard.type(await clipboardText());
                }
              })
            Text(app.keyboard.typing ? t('keyboard_typing') : t('keyboard_type_clipboard'))
              .fontSize(13).fontColor($r('app.color.secondary')).layoutWeight(1)
          }
          .width('100%')
          if (app.keyboard.typed.length > 0 && app.keyboard.typed !== 'typed') {
            ErrorText({ text: app.keyboard.typed })
          }
        }
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
