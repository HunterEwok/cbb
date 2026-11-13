// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The devices on orbits around this phone, which stands at the centre, a
// dashed line to each one online, for a big screen (docs/apps.md, "Big
// screens"), as the iPad's and the Android tablet's: up to six on the inner
// orbit, the rest on the outer, from the top clockwise, in the group's
// order. A device, this phone too, opens its details beside them.

import { t } from '../core/Text';
import { glyph, nameOf } from '../common/Devices';
import { Device } from '../model/Member';

// How many devices the inner orbit holds.
const INNER: number = 6;
const NODE_W: number = 104;
const NODE_H: number = 84;
const HUB: number = 96;

class Spot {
  x: number = 0;
  y: number = 0;
}

// Where each of n devices stands around (cx, cy).
function spots(n: number, cx: number, cy: number, inner: number, outer: number): Spot[] {
  const onInner = Math.min(n, INNER);
  const onOuter = n - onInner;
  const ring = (count: number, radius: number, turn: number): Spot[] => {
    const out: Spot[] = [];
    for (let i = 0; i < count; i++) {
      const a = -Math.PI / 2 + turn + 2 * Math.PI * i / count;
      out.push({ x: cx + radius * Math.cos(a), y: cy + radius * Math.sin(a) });
    }
    return out;
  };
  return ring(onInner, inner, 0).concat(ring(onOuter, outer, onOuter > 0 ? Math.PI / onOuter : 0));
}

@ComponentV2
export struct Orbit {
  @Param @Require devices: Device[] = [];
  @Param selected: string = '';
  @Event select: (id: string) => void = () => {};
  @Local w: number = 0;
  @Local h: number = 0;

  others(): Device[] {
    return this.devices.filter((d: Device) => d.self !== true);
  }

  me(): Device | undefined {
    return this.devices.find((d: Device) => d.self === true);
  }

  build() {
    Stack({ alignContent: Alignment.TopStart }) {
      if (this.w > 0 && this.h > 0) {
        // The orbits and the lines to the devices online.
        Circle()
          .width(Math.min(this.w, this.h) * 0.56)
          .height(Math.min(this.w, this.h) * 0.56)
          .fillOpacity(0)
          .stroke($r('app.color.grid'))
          .strokeWidth(1)
          .position({ x: this.w / 2 - Math.min(this.w, this.h) * 0.28, y: this.h / 2 - Math.min(this.w, this.h) * 0.28 })
        if (this.others().length > INNER) {
          Circle()
            .width(Math.min(this.w, this.h) * 0.88)
            .height(Math.min(this.w, this.h) * 0.88)
            .fillOpacity(0)
            .stroke($r('app.color.grid'))
            .strokeWidth(1)
            .position({ x: this.w / 2 - Math.min(this.w, this.h) * 0.44, y: this.h / 2 - Math.min(this.w, this.h) * 0.44 })
        }
        ForEach(this.spotted(), (p: Spot, i: number) => {
          if (this.others()[i]?.online === true) {
            Line()
              .width(this.w)
              .height(this.h)
              .startPoint([this.w / 2, this.h / 2])
              .endPoint([p.x, p.y])
              .stroke($r('app.color.accent'))
              .strokeOpacity(0.5)
              .strokeWidth(1.5)
              .strokeDashArray([6, 6])
              .position({ x: 0, y: 0 })
          }
        }, (p: Spot, i: number) => `l:${i}:${Math.round(p.x)}:${Math.round(p.y)}:${this.others()[i]?.online === true}`)

        // The centre: this phone, which opens its own details.
        if (this.me() !== undefined) {
          Column() {
            Text(glyph(this.me() as Device)).fontSize(44)
          }
          .width(HUB)
          .height(HUB)
          .borderRadius(HUB / 2)
          .backgroundColor($r('app.color.accent'))
          .border(this.selected === (this.me() as Device).id ? { width: 3, color: $r('app.color.text') } : { width: 0 })
          .justifyContent(FlexAlign.Center)
          .position({ x: this.w / 2 - HUB / 2, y: this.h / 2 - HUB / 2 })
          .accessibilityText(t('device_status_self'))
          .onClick(() => {
            this.select((this.me() as Device).id);
          })
        }

        ForEach(this.spotted(), (p: Spot, i: number) => {
          Column({ space: 4 }) {
            Text(glyph(this.others()[i]))
              .fontSize(34)
              .opacity(this.others()[i].online === true ? 1 : 0.4)
              .padding(6)
              .borderRadius(30)
              .border(this.selected === this.others()[i].id ? { width: 2, color: $r('app.color.accent') } : { width: 0 })
            Text(nameOf(this.others()[i]))
              .fontSize(12)
              .fontFamily('monospace')
              .fontColor($r('app.color.text'))
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .textAlign(TextAlign.Center)
              .width('100%')
          }
          .width(NODE_W)
          .height(NODE_H)
          .justifyContent(FlexAlign.Center)
          .position({ x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 })
          .accessibilityGroup(true)
          .accessibilityText(`${nameOf(this.others()[i])}, ${this.others()[i].online === true ? t('device_status_online') :
            t('device_status_offline')}`)
          .onClick(() => {
            this.select(this.others()[i].id);
          })
        }, (p: Spot, i: number) => `n:${this.others()[i]?.id ?? i}:${Math.round(p.x)}:${Math.round(p.y)}:${this.others()[i]?.online === true}:${this.selected}`)
      }
    }
    .width('100%')
    .height('100%')
    .onAreaChange((_: Area, area: Area) => {
      this.w = Number(area.width);
      this.h = Number(area.height);
    })
  }

  spotted(): Spot[] {
    const side = Math.min(this.w, this.h);
    return spots(this.others().length, this.w / 2, this.h / 2, side * 0.28, side * 0.44);
  }
}
