// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The home-screen widget "Sync clipboard", the iPhone's and Android's twin:
// a tap on Sync opens the app, which syncs at once (EntryAbility, action
// sync); the line under it shows whether sync is on and how many devices are
// online, and a tap on it turns sync on or off (action sync_toggle).

const storage = new LocalStorage();

@Entry(storage)
@Component
struct SyncCard {
  @LocalStorageProp('group') group: boolean = false;
  @LocalStorageProp('syncOn') syncOn: boolean = true;
  @LocalStorageProp('online') online: number = 0;

  open(action: string): void {
    postCardAction(this, { action: 'router', abilityName: 'EntryAbility', params: { action: action } });
  }

  build() {
    Column({ space: 8 }) {
      Row({ space: 6 }) {
        Image($r('app.media.icon')).width(20).height(20)
        Text($r('app.string.widget_name'))
          .fontSize(13)
          .fontColor($r('app.color.text'))
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .layoutWeight(1)
      }
      .width('100%')
      Button($r('app.string.widget_sync'), { type: ButtonType.Capsule })
        .width('100%')
        .height(36)
        .enabled(this.group)
        .onClick(() => {
          this.open('sync');
        })
      Row({ space: 6 }) {
        Circle({ width: 8, height: 8 }).fill(this.group && this.syncOn ? $r('app.color.online') : $r('app.color.offline'))
        if (this.group) {
          Text(this.syncOn ? $r('app.string.main_sync_on') : $r('app.string.main_sync_off'))
            .fontSize(12)
            .fontColor($r('app.color.secondary'))
            .layoutWeight(1)
          Text(this.online.toString()).fontSize(12).fontColor($r('app.color.secondary'))
        } else {
          Text($r('app.string.widget_no_group')).fontSize(12).fontColor($r('app.color.secondary'))
        }
      }
      .width('100%')
      .onClick(() => {
        this.open(this.group ? 'sync_toggle' : 'open');
      })
    }
    .padding(12)
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.SpaceBetween)
    .backgroundColor($r('app.color.background'))
    .onClick(() => {
      this.open('open');
    })
  }
}
