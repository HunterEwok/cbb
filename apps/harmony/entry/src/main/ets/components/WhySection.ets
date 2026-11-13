// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// "Why it does not sync" in the advanced settings (docs/apps.md): the
// member's reasons for this phone, the one that stops the most first and
// large, the code and the core's detail under each in debug mode.

import { whyAction, whyDetail, whyTitle } from '../common/Why';
import { Why } from '../model/Member';

@ComponentV2
export struct WhySection {
  @Param why: Why[] = [];
  @Param details: boolean = false;

  build() {
    Column({ space: 8 }) {
      Text($r('app.string.why_screen')).fontSize(15).fontWeight(FontWeight.Medium).fontColor($r('app.color.accent'))
      if (this.why.length === 0) {
        Text($r('app.string.why_ok')).fontColor($r('app.color.text'))
      }
      ForEach(this.why, (r: Why, i: number) => {
        Column({ space: 2 }) {
          if (i === 1) {
            Text($r('app.string.why_also')).fontSize(13).fontColor($r('app.color.secondary')).accessibilityLevel('yes')
          }
          Text(whyTitle(r))
            .fontSize(i === 0 ? 18 : 15)
            .fontWeight(i === 0 ? FontWeight.Medium : FontWeight.Normal)
            .fontColor(r.level === 'stop' ? $r('app.color.error') : $r('app.color.text'))
          if (whyAction(r).length > 0) {
            Text(whyAction(r)).fontSize(13).fontColor($r('app.color.secondary'))
          }
          if (this.details) {
            Text(whyDetail(r)).fontSize(12).fontFamily('monospace').fontColor($r('app.color.secondary'))
              .copyOption(CopyOptions.LocalDevice)
          }
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')
      }, (r: Why) => `${r.code}:${r.device ?? ''}:${r.until_ms ?? 0}`)
    }
    .alignItems(HorizontalAlign.Start)
    .width('100%')
  }
}
