// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The code both screens show while a device joins a group of 0.6, and the
// person's answer (docs/apps.md, "Screens"): pages/Window and pages/JoinWindow.

@ComponentV2
export struct CodeQuestion {
  @Param who: string = '';
  @Param code: string = '';
  @Event answered: (yes: boolean) => void = () => {};

  build() {
    Column({ space: 16 }) {
      Text(this.who).fontSize(17).fontColor($r('app.color.text')).width('100%').textAlign(TextAlign.Center)
      Text(this.code)
        .fontSize(34)
        .fontFamily('monospace')
        .fontWeight(FontWeight.Bold)
        .letterSpacing(4)
        .fontColor($r('app.color.text'))
        .width('100%')
        .textAlign(TextAlign.Center)
        .accessibilityText(this.code.split('').join(' '))
      Text($r('app.string.code_question')).fontColor($r('app.color.text')).width('100%').textAlign(TextAlign.Center)
      Button($r('app.string.code_match'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
        this.answered(true);
      })
      Button($r('app.string.code_differ'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
        .width('100%')
        .onClick(() => {
          this.answered(false);
        })
    }
    .width('100%')
  }
}
