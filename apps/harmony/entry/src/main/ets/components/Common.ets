// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Small pieces every page shows: an error as Errors.shown gave it (its
// details under it in debug mode, selectable to copy), and the busy line.

@ComponentV2
export struct ErrorText {
  @Param text: string = '';

  build() {
    if (this.text.length > 0) {
      Text(this.text)
        .fontColor($r('app.color.error'))
        .fontSize(14)
        .copyOption(CopyOptions.LocalDevice)
        .width('100%')
    }
  }
}

@ComponentV2
export struct BusyLine {
  @Param busy: boolean = false;
  @Param label: ResourceStr = $r('app.string.busy');

  build() {
    if (this.busy) {
      Row({ space: 8 }) {
        LoadingProgress().width(24).height(24).color($r('app.color.accent'))
        Text(this.label).fontColor($r('app.color.secondary'))
      }
    }
  }
}

// A page's title row with a way back.
@ComponentV2
export struct PageTitle {
  @Param title: ResourceStr = '';
  @Event back: () => void = () => {};

  build() {
    Row({ space: 8 }) {
      Button({ type: ButtonType.Circle }) {
        Text('‹').fontSize(28).fontColor($r('app.color.text'))
      }
      .width(40)
      .height(40)
      .backgroundColor(Color.Transparent)
      .accessibilityText($r('app.string.back'))
      .onClick(() => {
        this.back();
      })
      Text(this.title).fontSize(24).fontWeight(FontWeight.Bold).fontColor($r('app.color.text')).layoutWeight(1)
    }
    .width('100%')
  }
}
