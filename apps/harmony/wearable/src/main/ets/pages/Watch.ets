// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's page (docs/apps.md, "HarmonyOS watches"), as the Wear OS
// app's: how many devices are online, the house (the phone's sync) and the
// globe (sync away from home) with where it stands, each device with its
// glyph and live dot, the latest events; the last state when the phone is
// out of reach. As an admin, each device's emergency actions, each asked
// once before the watch signs it, and the root's ask for the admin key.

import { t } from '../core/Text';
import { WatchDevice, WatchState } from '../common/WatchState';
import { link } from '../model/Link';

function glyph(form: string): string {
  if (form === 'phone') {
    return '\u{1F4F1}';
  }
  if (form === 'watch') {
    return '⌚';
  }
  return form === 'board' ? '\u{1F50C}' : '\u{1F4BB}';
}

function awayLine(away: string): string {
  if (away === 'home') {
    return t('away_at_home');
  }
  if (away === 'connected') {
    return t('away_connected');
  }
  if (away === 'waiting') {
    return t('away_waiting');
  }
  return away === 'connecting' ? t('away_connecting') : t('away_off');
}

// The label of an emergency action and its question.
function actLabel(action: string): string {
  return t(`act_${action.replace('-', '_').replace('-', '_')}`);
}

// A device's actions; a state kept from an older phone has none.
function actionsOf(d: WatchDevice): string[] {
  return Array.isArray(d.actions) ? d.actions.filter((a: string) => a !== 'action') : [];
}

function askOf(action: string, name: string): string {
  return t(`ask_${action.replace('-', '_').replace('-', '_')}`, name);
}

@Entry
@ComponentV2
struct Watch {
  // The action the wearer picked and is asked to confirm: action, device's
  // ID and name; '' when none.
  @Local confirmAction: string = '';
  @Local confirmDevice: string = '';
  @Local confirmName: string = '';

  @Builder
  question(text: string, yes: string, answer: (yes: boolean) => void) {
    Column({ space: 6 }) {
      Text(text).fontSize(13).fontColor($r('app.color.text')).textAlign(TextAlign.Center)
      Row({ space: 6 }) {
        Button(t('cancel'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
          .fontSize(12).layoutWeight(1)
          .onClick(() => answer(false))
        Button(yes, { type: ButtonType.Capsule })
          .fontSize(12).layoutWeight(1).backgroundColor($r('app.color.accent'))
          .onClick(() => answer(true))
      }
      .width('100%')
    }
    .width('100%')
  }

  @Builder
  actions(d: WatchDevice) {
    if ((link.state as WatchState).admin === true && actionsOf(d).length > 0) {
      Flex({ wrap: FlexWrap.Wrap }) {
        ForEach(actionsOf(d), (a: string) => {
          Button(actLabel(a), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .fontSize(11).margin(2)
            .enabled(link.reachable && link.acting.length === 0)
            .onClick(() => {
              this.confirmAction = a;
              this.confirmDevice = d.id;
              this.confirmName = d.name;
            })
        }, (a: string) => a)
      }
      .width('100%')
    }
  }
  @Builder
  switchRow(label: string, note: string, on: boolean, enabled: boolean, change: (on: boolean) => void) {
    Row() {
      Column({ space: 2 }) {
        Text(label).fontSize(15).fontColor($r('app.color.text'))
        if (note.length > 0) {
          Text(note).fontSize(11).fontColor($r('app.color.secondary')).maxLines(2)
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor($r('app.color.accent'))
        .enabled(enabled)
        .onChange(change)
    }
    .width('100%')
  }

  @Builder
  deviceRow(d: WatchDevice) {
    Row({ space: 6 }) {
      Text(glyph(d.form)).fontSize(14)
      Text(d.phone ? `${d.name} · ${t('watch_phone')}` : d.name)
        .fontSize(14).fontColor($r('app.color.text')).maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis }).layoutWeight(1)
      Circle({ width: 8, height: 8 }).fill(d.online ? $r('app.color.online') : $r('app.color.offline'))
    }
    .width('100%')
    .accessibilityText(`${d.name}, ${d.online ? t('online') : t('offline')}`)
  }

  build() {
    Scroll() {
      Column({ space: 8 }) {
        Text($r('app.string.app_name')).fontSize(16).fontWeight(FontWeight.Medium).fontColor($r('app.color.accent'))
        if (link.makeKeyAsked) {
          this.question(t('make_admin'), t('sign'), (yes: boolean) => {
            link.answerMakeKey(yes);
          })
        }
        if (this.confirmAction.length > 0) {
          Text(t('sign_title')).fontSize(12).fontColor($r('app.color.accent'))
          this.question(askOf(this.confirmAction, this.confirmName), t('sign'), (yes: boolean) => {
            if (yes) {
              link.act(this.confirmAction, this.confirmDevice);
            }
            this.confirmAction = '';
          })
        }
        if (link.acting.length > 0) {
          LoadingProgress().width(24).height(24).color($r('app.color.accent'))
        }
        if (link.result.length > 0) {
          Text(link.result).fontSize(12).fontColor($r('app.color.secondary')).textAlign(TextAlign.Center)
        }
        if (link.state === undefined) {
          Text(link.reachable ? $r('app.string.devices') : $r('app.string.no_phone'))
            .fontSize(13).fontColor($r('app.color.secondary')).textAlign(TextAlign.Center)
        } else if (!(link.state as WatchState).group) {
          Text($r('app.string.no_group')).fontSize(13).fontColor($r('app.color.secondary')).textAlign(TextAlign.Center)
        } else {
          Text(t('online_count', (link.state as WatchState).online, (link.state as WatchState).total))
            .fontSize(13).fontColor($r('app.color.secondary'))
          this.switchRow(t('sync'), '', (link.state as WatchState).sync, link.reachable && !link.asking, (on: boolean) => {
            link.ask('sync', on);
          })
          this.switchRow(t('away'), awayLine((link.state as WatchState).away), (link.state as WatchState).away !== 'off',
            link.reachable && !link.asking, (on: boolean) => {
              link.ask('away', on);
            })
          if ((link.state as WatchState).admin === true) {
            Text(t('watch_admin')).fontSize(11).fontColor($r('app.color.secondary'))
          }
          if (link.failed) {
            Text($r('app.string.no_phone')).fontSize(12).fontColor($r('app.color.error'))
          }
          ForEach((link.state as WatchState).devices, (d: WatchDevice, i: number) => {
            if (d.collection.length > 0 && (i === 0 || (link.state as WatchState).devices[i - 1].collection !== d.collection)) {
              Text(d.collection).fontSize(12).fontColor($r('app.color.accent')).width('100%')
            }
            this.deviceRow(d)
            this.actions(d)
          }, (d: WatchDevice) => `${d.id}-${actionsOf(d).join(',')}`)
          if ((link.state as WatchState).events.length > 0) {
            Text($r('app.string.latest')).fontSize(12).fontColor($r('app.color.accent')).width('100%')
            ForEach((link.state as WatchState).events, (e: string) => {
              Text(e).fontSize(12).fontColor($r('app.color.text')).width('100%').maxLines(2)
            }, (e: string, i: number) => `${i}-${e}`)
          }
        }
        if (link.state !== undefined && !link.fresh) {
          Text(link.reachable ? $r('app.string.stale') : $r('app.string.no_phone'))
            .fontSize(11).fontColor($r('app.color.secondary')).textAlign(TextAlign.Center)
        }
      }
      // A round screen: room at the top and the bottom.
      .padding({ left: 24, right: 24, top: 32, bottom: 48 })
      .width('100%')
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
