// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The bug report's question in release mode (docs/core-api.md, "Bug
// reports"): "Oops, something broke", Allow and Cancel, "Always allow"
// after the user allowed twice, and a small "Technical details" link that
// shows the report as it would go.

import { t } from '../core/Text';
import { Bugs } from '../model/Bugs';

@ComponentV2
export struct BugCard {
  @Param @Require bugs: Bugs;
  @Local always: boolean = false;
  @Local open: boolean = false;

  build() {
    if (this.bugs.asking) {
      Column({ space: 10 }) {
        Text($r('app.string.bug_title')).fontSize(18).fontWeight(FontWeight.Medium).fontColor($r('app.color.text'))
        Text($r('app.string.bug_text')).fontSize(14).fontColor($r('app.color.text'))
        if (this.bugs.fixedIn.length > 0) {
          Text(t('bug_fixed_in', this.bugs.fixedIn)).fontSize(14).fontColor($r('app.color.accent'))
        }
        if (this.bugs.offerAlways) {
          Row() {
            Text($r('app.string.bug_always')).fontColor($r('app.color.text')).layoutWeight(1)
            Toggle({ type: ToggleType.Checkbox, isOn: this.always })
              .selectedColor($r('app.color.accent'))
              .onChange((on: boolean) => {
                this.always = on;
              })
          }
          .width('100%')
        }
        Text($r('app.string.bug_details'))
          .fontSize(12)
          .fontColor($r('app.color.secondary'))
          .decoration({ type: TextDecorationType.Underline })
          .onClick(() => {
            this.open = !this.open;
          })
        if (this.open) {
          Text(this.bugs.report).fontSize(11).fontFamily('monospace').fontColor($r('app.color.secondary'))
            .copyOption(CopyOptions.LocalDevice)
        }
        Row({ space: 12 }) {
          Button($r('app.string.cancel'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .layoutWeight(1)
            .onClick(() => {
              this.bugs.cancel();
            })
          Button($r('app.string.bug_allow'), { type: ButtonType.Capsule })
            .layoutWeight(1)
            .backgroundColor($r('app.color.accent'))
            .fontColor($r('app.color.on_accent'))
            .onClick(() => {
              this.bugs.allow(this.always);
            })
        }
        .width('100%')
      }
      .padding(16)
      .borderRadius(16)
      .backgroundColor($r('app.color.surface'))
      .alignItems(HorizontalAlign.Start)
      .width('100%')
    }
  }
}
