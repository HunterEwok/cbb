// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Every change of the arrangement for one tile, which a long press opens
// (docs/apps.md, "Collections and the order of the tiles"): the moves in
// its level, into and out of a collection, and on a collection its name and
// ungrouping. Nothing leaves the phone.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { move, tilesOf } from '../common/Arrange';
import { nameOf } from '../common/Devices';
import { app, Tile } from '../model/AppModel';
import { Device } from '../model/Member';
import { ErrorText, PageTitle } from '../components/Common';

interface Choice {
  label: string;
  act: () => void;
}

@Entry
@ComponentV2
struct Arrange {
  @Local device: string = '';
  @Local collection: string = '';
  @Local choices: Choice[] = [];
  @Local title: string = '';

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    this.device = params !== undefined && params['device'] !== undefined ? String(params['device']) : '';
    this.collection = params !== undefined && params['collection'] !== undefined ? String(params['collection']) : '';
    this.makeChoices();
  }

  apply(op: Record<string, Object> | undefined): void {
    if (op !== undefined) {
      app.arrange(op);
    }
    router.back();
  }

  // The tile, its level and where it is in it.
  makeChoices(): void {
    const view = app.arranged(app.member.devices);
    let level: Tile[] = view;
    let index = -1;
    let inCollection = '';
    for (let i = 0; i < view.length; i++) {
      const tile = view[i];
      if (this.collection.length > 0 && tile.kind === 'collection' && tile.id === this.collection) {
        index = i;
      } else if (this.device.length > 0 && tile.kind === 'device' && tile.device?.id === this.device) {
        index = i;
      } else if (this.device.length > 0 && tile.kind === 'collection' &&
        tile.devices.some((d: Device) => d.id === this.device)) {
        level = tilesOf(tile);
        index = level.findIndex((x: Tile) => x.device?.id === this.device);
        inCollection = tile.id;
      }
      if (index >= 0) {
        break;
      }
    }
    if (index < 0) {
      return;
    }
    const item = level[index];
    this.title = item.kind === 'collection' ? item.name : nameOf(item.device as Device);
    const last = level.length - 1;
    const choices: Choice[] = [];
    const add = (show: boolean, label: string, act: () => void): void => {
      if (show) {
        const c: Choice = { label: label, act: act };
        choices.push(c);
      }
    };
    add(index > 0, t('arrange_start'), () => { this.apply(move(level, index, 'start')); });
    add(index > 0, t('arrange_earlier'), () => { this.apply(move(level, index, 'earlier')); });
    add(index < last, t('arrange_later'), () => { this.apply(move(level, index, 'later')); });
    add(index < last, t('arrange_end'), () => { this.apply(move(level, index, 'end')); });
    if (item.kind === 'device') {
      const id = this.device;
      for (const c of view) {
        if (c.kind === 'collection' && c.id !== inCollection) {
          add(true, t('arrange_into', c.name), () => {
            this.apply({ 'op': 'into', 'device': id, 'collection': c.id } as Record<string, Object>);
          });
        }
      }
      add(inCollection.length === 0, t('collection_new'), () => {
        router.replaceUrl({ url: 'pages/CollectionName', params: { 'device': id } as Record<string, Object> });
      });
      add(inCollection.length > 0, t('arrange_out'), () => {
        this.apply({ 'op': 'out', 'device': id } as Record<string, Object>);
      });
    } else {
      add(true, t('arrange_rename'), () => {
        router.replaceUrl({ url: 'pages/CollectionName', params: { 'collection': item.id, 'name': item.name } as Record<string, Object> });
      });
      add(true, t('arrange_ungroup'), () => {
        this.apply({ 'op': 'ungroup', 'collection': item.id } as Record<string, Object>);
      });
    }
    this.choices = choices;
  }

  build() {
    Column({ space: 8 }) {
      PageTitle({ title: this.title, back: () => {
        router.back();
      } })
      Text($r('app.string.arrange_title')).fontSize(13).fontColor($r('app.color.secondary'))
      List() {
        ForEach(this.choices, (c: Choice) => {
          ListItem() {
            Text(c.label).fontColor($r('app.color.text')).padding(14).width('100%')
          }
          .onClick(() => {
            c.act();
          })
        }, (c: Choice) => c.label)
      }
      .divider({ strokeWidth: 1, color: $r('app.color.surface') })
      .layoutWeight(1)
      ErrorText({ text: app.error })
    }
    .padding(24)
    .alignItems(HorizontalAlign.Start)
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
