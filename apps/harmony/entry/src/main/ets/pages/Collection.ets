// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A collection's devices (docs/apps.md, "Collections and the order of the
// tiles"): a tap opens a device, a long press arranges it; and ungrouping.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { line, mark, nameOf, glyph } from '../common/Devices';
import { app, Tile } from '../model/AppModel';
import { Device, Member } from '../model/Member';
import { PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct Collection {
  @Local member: Member = app.member;
  @Local collectionId: string = '';
  @Local tile: Tile | undefined = undefined;

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    this.collectionId = params !== undefined && params['collection'] !== undefined ? String(params['collection']) : '';
    this.refresh();
  }

  onPageShow(): void {
    this.refresh();
  }

  @Monitor('member.devices')
  refresh(): void {
    this.tile = app.arranged(app.member.devices).find((x: Tile) => x.kind === 'collection' && x.id === this.collectionId);
  }

  build() {
    Column({ space: 8 }) {
      PageTitle({ title: this.tile?.name ?? '', back: () => {
        router.back();
      } })
      if (this.tile !== undefined) {
        List() {
          ForEach(this.tile.devices, (d: Device) => {
            ListItem() {
              Row({ space: 12 }) {
                Text(glyph(d)).fontSize(24)
                Column({ space: 2 }) {
                  Text(nameOf(d)).fontColor($r('app.color.text'))
                  Text([mark(d), line(d)].filter((s: string) => s.length > 0).join(' · '))
                    .fontSize(12)
                    .fontColor($r('app.color.secondary'))
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)
              }
              .padding(12)
              .width('100%')
            }
            .onClick(() => {
              router.pushUrl({ url: 'pages/Device', params: { 'device': d.id } as Record<string, Object> });
            })
            .gesture(LongPressGesture().onAction(() => {
              router.pushUrl({ url: 'pages/Arrange', params: { 'device': d.id } as Record<string, Object> });
            }))
          }, (d: Device) => JSON.stringify(d))
        }
        .layoutWeight(1)
        Button(t('arrange_ungroup'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
          .width('100%')
          .onClick(() => {
            app.arrange({ 'op': 'ungroup', 'collection': this.collectionId } as Record<string, Object>);
            router.back();
          })
      } else {
        Text($r('app.string.collection_gone')).fontColor($r('app.color.secondary'))
      }
    }
    .padding(24)
    .alignItems(HorizontalAlign.Start)
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
