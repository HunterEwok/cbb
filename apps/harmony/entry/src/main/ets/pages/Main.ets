// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Home (docs/apps.md, "Screens"): sync on and off, Everywhere (sync away
// from home), the paste button that sends what the user copied, what came
// last, the group's alerts and its devices as tiles or a list, in the
// user's order and collections. A tap opens a device, a long press arranges
// its tile. The Aurora app's MainPage, on ArkUI.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { fileIo, picker } from '@kit.CoreFileKit';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { glyph, line, mark, nameOf } from '../common/Devices';
import { app, Tile } from '../model/AppModel';
import { Admit } from '../model/Admit';
import { isInvitation } from '../model/Invite';
import { Alert, Device, Member } from '../model/Member';
import { BugCard } from '../components/BugCard';
import { BusyLine, ErrorText } from '../components/Common';

const LOST_PHONE_TIP: string = 'tip_lost_phone';

@Entry
@ComponentV2
struct Main {
  // The model's member, a field so that the monitors see its devices.
  @Local member: Member = app.member;
  @Local tiles: Tile[] = [];
  @Local stamp: number = 0;
  @Local error: string = '';
  @Local lostTipClosed: boolean = false;

  aboutToAppear(): void {
    this.lostTipClosed = app.tipClosed(LOST_PHONE_TIP);
    app.startMember();
    this.rearrange();
  }

  onPageShow(): void {
    this.rearrange();
    if (app.membership === undefined) {
      router.clear();
      router.replaceUrl({ url: 'pages/Start' });
    }
  }

  @Monitor('member.devices', 'member.view')
  devicesChanged(): void {
    this.rearrange();
  }

  rearrange(): void {
    if (app.membership !== undefined) {
      this.tiles = app.arranged(app.member.devices);
    }
  }

  onlineLine(): string {
    const online = app.member.devices.filter((d: Device) => d.online === true).length;
    return t('main_online', online, app.member.devices.length);
  }

  syncLine(): string {
    if (!app.member.paused) {
      return t('main_sync_on');
    }
    if (app.member.pausedUntil > 0) {
      return t('main_sync_off_until', new Date(app.member.pausedUntil).toLocaleTimeString());
    }
    return t('main_sync_off');
  }

  awayLine(): string {
    const m = app.member;
    if (!m.awayOn) {
      return t('away_off');
    }
    if (m.paused) {
      return t('away_paused');
    }
    if (m.awayStatus === 'home') {
      return t('away_home');
    }
    if (m.awayStatus === 'connecting') {
      return t('away_connecting');
    }
    if (m.awayStatus === 'connected') {
      return m.awayHub.length > 0 ? t('away_connected_hub', m.awayHub) : t('away_connected');
    }
    return t('away_waiting');
  }

  mutedLine(): string {
    if (app.member.mutedUntil > 0) {
      return t('main_muted_until', new Date(app.member.mutedUntil).toLocaleString());
    }
    return t('main_muted');
  }

  // Sync off for a while, from a long press on its switch.
  pauseMenu(): void {
    const minutes = [15, 60, 8 * 60, 0];
    this.getUIContext().showActionSheet({
      title: t('main_sync_off_title'),
      message: '',
      sheets: [
        { title: t('main_off_15'), action: () => { app.member.pause(minutes[0]); } },
        { title: t('main_off_hour'), action: () => { app.member.pause(minutes[1]); } },
        { title: t('main_off_8'), action: () => { app.member.pause(minutes[2]); } },
        { title: t('main_off_until'), action: () => { app.member.pause(minutes[3]); } }
      ]
    });
  }

  toggleAway(): void {
    if (app.member.awayOn) {
      app.member.setAway(false);
      return;
    }
    this.getUIContext().showAlertDialog({
      title: t('away_dialog_title'),
      message: t('away_dialog_text'),
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('away_turn_on'), action: () => { app.member.setAway(true); } }
    });
  }

  // Scans a code: a device's join code adds it, an invitation opens its page.
  async scanCode(): Promise<void> {
    const s = await scanQr(getContext(this) as common.UIAbilityContext);
    if (s.text === undefined) {
      if (s.failure !== undefined) {
        this.error = Errors.shown(s.failure);
      }
      return;
    }
    if (Admit.isJoinCode(s.text)) {
      router.pushUrl({ url: 'pages/AddDevice', params: { 'qr': s.text } as Record<string, Object> });
    } else if (isInvitation(s.text)) {
      this.error = t('main_invitation_in_group');
    } else {
      this.error = t('error_not_join_code');
    }
  }

  // Saves the files of the last copy where the user picks.
  async saveReceived(): Promise<void> {
    const folder = app.member.received;
    try {
      const names = fileIo.listFileSync(folder, { recursion: false });
      if (names.length === 0) {
        return;
      }
      const options = new picker.DocumentSaveOptions();
      options.newFileNames = names;
      const uris = await new picker.DocumentViewPicker(getContext(this)).save(options);
      for (let i = 0; i < uris.length && i < names.length; i++) {
        const to = fileIo.openSync(uris[i], fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.TRUNC);
        fileIo.copyFileSync(`${folder}/${names[i]}`, to.fd);
        fileIo.closeSync(to);
      }
      Errors.log(`main: saved ${uris.length} received files`);
    } catch (e) {
      this.error = Errors.shown(Errors.unexpected(t('error_save_files'), e as Object));
    }
  }

  openTile(tile: Tile): void {
    if (tile.kind === 'collection') {
      router.pushUrl({ url: 'pages/Collection', params: { 'collection': tile.id } as Record<string, Object> });
    } else if (tile.device !== undefined) {
      router.pushUrl({ url: 'pages/Device', params: { 'device': tile.device.id } as Record<string, Object> });
    }
  }

  arrangeTile(tile: Tile): void {
    const params: Record<string, Object> = tile.kind === 'collection' ? { 'collection': tile.id } :
      { 'device': tile.device?.id ?? '' };
    router.pushUrl({ url: 'pages/Arrange', params: params });
  }

  menu(): MenuElement[] {
    const items: MenuElement[] = [];
    if (app.isAdmin()) {
      items.push({ value: t('main_scan'), action: () => { this.scanCode(); } });
      items.push({ value: t('main_invite'), action: () => { router.pushUrl({ url: 'pages/Invite' }); } });
    }
    items.push({ value: t('collection_new'), action: () => { router.pushUrl({ url: 'pages/CollectionName' }); } });
    if (app.hasArrangement()) {
      items.push({ value: t('main_reset_order'), action: () => {
        app.arrange({ 'op': 'reset' } as Record<string, Object>);
      } });
    }
    items.push({ value: app.deviceList ? t('main_show_tiles') : t('main_show_list'), action: () => {
      app.setDeviceList(!app.deviceList);
    } });
    if (app.isRoot()) {
      items.push({ value: t('recovery_title'), action: () => { router.pushUrl({ url: 'pages/Recovery' }); } });
    }
    items.push({ value: t('settings_title'), action: () => { router.pushUrl({ url: 'pages/Settings' }); } });
    return items;
  }

  @Builder
  switchFace(label: string, on: boolean, enabled: boolean, act: () => void, hold: () => void) {
    Column({ space: 2 }) {
      Toggle({ type: ToggleType.Switch, isOn: on })
        .enabled(enabled)
        .selectedColor($r('app.color.accent'))
        .onChange(() => {
          act();
        })
        .gesture(LongPressGesture().onAction(() => {
          hold();
        }))
      Text(label).fontSize(11).fontColor($r('app.color.secondary'))
    }
  }

  @Builder
  alertCard(a: Alert) {
    Column({ space: 8 }) {
      Text(alertText(a)).fontColor(a.kind === 'newer' ? $r('app.color.accent') : $r('app.color.error')).fontSize(14)
      if (app.isRoot() && a.kind === 'two_histories') {
        Button(t('alert_void_both'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).onClick(() => {
          this.confirm(t('alert_void_both_confirm'), () => { app.resolve(a.records ?? []); });
        })
      }
      if (app.isRoot() && (a.kind === 'claims' || a.kind === 'claim_pending' || a.kind === 'claim_stopped')) {
        Button(t('alert_cancel_claim'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).onClick(() => {
          this.confirm(t('alert_cancel_claim_confirm'), () => { app.resolve(a.records ?? []); });
        })
      }
      if (app.isRoot() && a.kind === 'admins') {
        ForEach(a.devices ?? [], (id: string, i: number) => {
          Button(t('alert_remove', (a.names ?? [])[i] ?? id), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .onClick(() => {
              this.confirm(t('device_remove_confirm_final'), () => { app.manage('remove', id); });
            })
        }, (id: string) => id)
      }
      if (!app.isRoot() && ['two_histories', 'admins', 'claims', 'claim_pending', 'claim_stopped'].includes(a.kind)) {
        Text(t('alert_root_decides')).fontSize(13).fontColor($r('app.color.secondary'))
      }
    }
    .alignItems(HorizontalAlign.Start)
    .padding(12)
    .borderRadius(14)
    .backgroundColor($r('app.color.surface'))
    .width('100%')
  }

  confirm(message: string, yes: () => void): void {
    this.getUIContext().showAlertDialog({
      message: message,
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('confirm'), fontColor: $r('app.color.error'), action: yes }
    });
  }

  @Builder
  tile(item: Tile) {
    Column({ space: 4 }) {
      if (item.kind === 'collection') {
        Text('\u{1F5C2}').fontSize(30)
        Text(item.name).fontSize(14).fontColor($r('app.color.text')).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(t('collection_online', item.devices.filter((d: Device) => d.online === true || d.self === true).length, item.devices.length))
          .fontSize(11).fontColor($r('app.color.secondary'))
      } else if (item.device !== undefined) {
        Text(glyph(item.device)).fontSize(30).opacity(item.device.online === true || item.device.self === true ? 1 : 0.4)
        Text(nameOf(item.device)).fontSize(14).fontColor($r('app.color.text')).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(mark(item.device)).fontSize(11).fontColor($r('app.color.secondary')).maxLines(1)
      }
    }
    .padding(10)
    .borderRadius(20)
    .backgroundColor($r('app.color.surface'))
    .width('100%')
    .height(110)
    .justifyContent(FlexAlign.Center)
    .onClick(() => {
      this.openTile(item);
    })
    .gesture(LongPressGesture().onAction(() => {
      this.arrangeTile(item);
    }))
  }

  @Builder
  row(item: Tile) {
    Row({ space: 12 }) {
      Text(item.kind === 'collection' ? '\u{1F5C2}' : glyph(item.device as Device)).fontSize(24)
      Column({ space: 2 }) {
        Text(item.kind === 'collection' ? item.name : nameOf(item.device as Device)).fontColor($r('app.color.text'))
        Text(item.kind === 'collection' ? t('collection_count', item.devices.length) :
          [mark(item.device as Device), line(item.device as Device)].filter((s: string) => s.length > 0).join(' · '))
          .fontSize(12)
          .fontColor($r('app.color.secondary'))
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      if (item.kind === 'device' && item.device !== undefined && item.device.self !== true) {
        Circle().width(8).height(8).fill(item.device.online === true ? $r('app.color.online') : $r('app.color.offline'))
      }
    }
    .padding(12)
    .width('100%')
    .onClick(() => {
      this.openTile(item);
    })
    .gesture(LongPressGesture().onAction(() => {
      this.arrangeTile(item);
    }))
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.app_name')).fontSize(28).fontWeight(FontWeight.Bold).fontColor($r('app.color.text')).layoutWeight(1)
        Button({ type: ButtonType.Circle }) {
          Text('⋯').fontSize(24).fontColor($r('app.color.text'))
        }
        .width(44)
        .height(44)
        .backgroundColor(Color.Transparent)
        .accessibilityText($r('app.string.more'))
        .bindMenu(this.menu())
      }
      .padding({ left: 24, right: 12, top: 8 })
      .width('100%')

      Scroll() {
        Column({ space: 16 }) {
          // Where sync stands, its switch and Everywhere's.
          Row({ space: 12 }) {
            Column({ space: 2 }) {
              Text(this.onlineLine()).fontSize(17).fontColor($r('app.color.text'))
              Text(this.syncLine()).fontSize(13).fontColor($r('app.color.secondary'))
              Text(this.awayLine()).fontSize(13).fontColor($r('app.color.secondary'))
              ErrorText({ text: app.member.awayError })
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
            this.switchFace(t('main_switch_sync'), !app.member.paused, app.member.running, () => {
              if (app.member.paused) {
                app.member.resume();
              } else {
                app.member.pause(0);
              }
            }, () => {
              if (!app.member.paused) {
                this.pauseMenu();
              }
            })
            this.switchFace(t('main_switch_away'), app.member.awayOn, app.member.awayOn || !app.member.paused, () => {
              this.toggleAway();
            }, () => {})
          }
          .width('100%')

          if (app.member.muted) {
            Text(this.mutedLine()).fontSize(14).fontColor($r('app.color.error'))
          }

          // HarmonyOS lets an app read what was copied only through the
          // system's paste button: a tap sends it.
          Row({ space: 12 }) {
            PasteButton({ icon: PasteIconStyle.LINES, text: PasteDescription.PASTE, buttonType: ButtonType.Capsule })
              .enabled(app.member.running && !app.member.muted)
              .onClick((event: ClickEvent, result: PasteButtonOnClickResult) => {
                if (result === PasteButtonOnClickResult.SUCCESS) {
                  app.member.sendPasteboard();
                }
              })
            Text($r('app.string.main_send_note')).fontSize(13).fontColor($r('app.color.secondary')).layoutWeight(1)
          }
          .width('100%')

          if (app.member.last.length > 0) {
            Text(app.member.last).fontSize(15).fontColor($r('app.color.text')).maxLines(2)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          if (app.member.fetching) {
            BusyLine({ busy: true, label: $r('app.string.main_fetching') })
          }
          if (app.member.received.length > 0) {
            Button($r('app.string.main_save_received'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
              .onClick(() => {
                this.saveReceived();
              })
          }

          BugCard({ bugs: app.bugs })
          ForEach(app.member.alerts, (a: Alert) => {
            this.alertCard(a);
          }, (a: Alert) => `${a.kind}:${(a.records ?? []).join(',')}`)

          // "Lost phone?" on the group's only admin: how a second phone
          // becomes one. Closed once, it stays closed.
          if (!this.lostTipClosed && app.isAdmin() && app.member.running &&
            app.member.devices.filter((d: Device) => d.admin === true).length === 1) {
            Column({ space: 4 }) {
              Text($r('app.string.tip_lost_title')).fontColor($r('app.color.accent'))
              Text($r('app.string.tip_lost_text')).fontSize(13).fontColor($r('app.color.secondary'))
            }
            .alignItems(HorizontalAlign.Start)
            .padding(12)
            .borderRadius(14)
            .backgroundColor($r('app.color.surface'))
            .width('100%')
            .onClick(() => {
              app.closeTip(LOST_PHONE_TIP);
              this.lostTipClosed = true;
            })
          }

          if (this.tiles.length > 0) {
            Text($r('app.string.main_devices')).fontSize(15).fontWeight(FontWeight.Medium).fontColor($r('app.color.secondary'))
            if (app.deviceList) {
              Column() {
                ForEach(this.tiles, (item: Tile) => {
                  this.row(item);
                }, (item: Tile) => item.kind === 'collection' ? `c:${item.id}:${item.name}:${item.devices.length}` :
                  `d:${JSON.stringify(item.device)}`)
              }
              .borderRadius(14)
              .backgroundColor($r('app.color.surface'))
            } else {
              Grid() {
                ForEach(this.tiles, (item: Tile) => {
                  GridItem() {
                    this.tile(item);
                  }
                }, (item: Tile) => item.kind === 'collection' ? `c:${item.id}:${item.name}:${item.devices.length}` :
                  `d:${JSON.stringify(item.device)}`)
              }
              .columnsTemplate('1fr 1fr 1fr')
              .columnsGap(12)
              .rowsGap(12)
              .maxCount(1000)
              .layoutDirection(GridDirection.Row)
            }
          }

          BusyLine({ busy: app.busy })
          ErrorText({ text: app.member.error })
          ErrorText({ text: app.error })
          ErrorText({ text: this.error })
        }
        .padding({ left: 24, right: 24, bottom: 24 })
        .alignItems(HorizontalAlign.Start)
        .width('100%')
      }
      .layoutWeight(1)
      .align(Alignment.Top)
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}

// What an alert says (docs/core-api.md, the member's alerts).
function alertText(a: Alert): string {
  const who = (a.names ?? []).length > 0 ? (a.names ?? []).join(', ') : t('alert_unknown_devices');
  switch (a.kind) {
    case 'stopped':
      return t('alert_stopped');
    case 'secrets_stopped':
      return t('alert_secrets_stopped');
    case 'two_histories':
      return t('alert_two_histories', who);
    case 'admins':
      return t('alert_admins', who);
    case 'claims':
      return t('alert_claims', who);
    case 'claim_pending': {
      const hours = Math.ceil((a.left_ms ?? 0) / 3600000);
      return hours <= 0 ? t('alert_claim_pending', who) : t('alert_claim_pending_left', who, hours);
    }
    case 'claim_stopped':
      return t('alert_claim_stopped', who);
    case 'newer':
      return t('alert_newer', a.count ?? 0);
    default:
      return a.kind;
  }
}
