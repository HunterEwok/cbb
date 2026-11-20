// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Small pieces every page shows: an error as Errors.shown gave it (its
// details under it in debug mode, selectable to copy), the busy line, the
// page's title and the note on how well this device guards the group.

import { guardsLikeAPhone } from '../core/Keys';

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

// Before this device becomes the group's main device (making a group,
// restoring one, taking it over): on one that does not guard its keys as a
// phone does, that it guards the group less well; with hint, on a big screen
// that does, that the main device is best one always at hand (docs/apps.md,
// "Big screens").
@ComponentV2
export struct KeyGuardNote {
  @Param hint: boolean = false;
  @Local guards: boolean = true;
  @Local wide: boolean = false;

  aboutToAppear(): void {
    this.guards = guardsLikeAPhone();
  }

  build() {
    Column() {
      if (!this.guards) {
        Text($r('app.string.key_guard_weak')).fontSize(13).fontColor($r('app.color.error')).width('100%')
      } else if (this.hint && this.wide) {
        Text($r('app.string.create_group_main_hint')).fontSize(13).fontColor($r('app.color.secondary')).width('100%')
      }
    }
    .width('100%')
    .onAreaChange((_: Area, area: Area) => {
      this.wide = Number(area.width) >= 600;
    })
  }
}
