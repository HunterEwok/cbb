// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group, once the phone has one. This first version shows which group
// and device it is; the devices, sync and the admin's actions come next.

import { Errors } from '../core/Errors';
import { Membership } from '../core/Membership';

@Entry
@Component
struct Group {
  @State tag: string = '';
  @State device: string = '';
  @State root: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    const m = Membership.load(AppStorage.get<string>('filesDir') as string);
    if (m instanceof Membership) {
      this.tag = m.groupTag();
      this.device = m.member.device;
      this.root = m.isRoot();
    } else if (m !== undefined) {
      this.error = Errors.shown(m);
    }
  }

  build() {
    Column({ space: 12 }) {
      Text($r('app.string.group_title')).fontSize(28).fontWeight(FontWeight.Bold)
      Row({ space: 8 }) {
        Text($r('app.string.group_tag')).opacity(0.6)
        Text(this.tag).fontFamily('monospace')
      }
      Row({ space: 8 }) {
        Text($r('app.string.group_device')).opacity(0.6)
        Text(this.device).fontFamily('monospace')
      }
      if (this.root) {
        Text($r('app.string.group_role_root'))
      }
      if (this.error.length > 0) {
        Text(this.error).fontColor(Color.Red).fontSize(14).copyOption(CopyOptions.LocalDevice)
      }
    }
    .padding(24)
    .alignItems(HorizontalAlign.Start)
    .width('100%')
    .height('100%')
  }
}
