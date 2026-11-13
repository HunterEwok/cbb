// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Home (docs/apps.md, "Screens"): sync on and off, Everywhere (sync away
// from home), the paste button that sends what the user copied, what came
// last, the group's alerts and its devices as tiles or a list, in the
// user's order and collections. A tap opens a device, a long press arranges
// its tile. The Aurora app's MainPage, on ArkUI. A big screen (from 720 vp
// wide: a tablet, a foldable open) shows the devices on orbits around this
// phone, or as tiles or a list, and a device's details in a pane beside them
// (docs/apps.md, "Big screens"); a sidebar with the devices' sections (all,
// needs attention, each collection) and the parts of Settings, which stands
// from 1040 vp and slides in behind ☰ below; the keyboard's shortcuts, a
// right click's menu on a tile, and drag and drop: on a tile to paste on its
// device, beside the tiles to send to the group.

import { common } from '@kit.AbilityKit';
import { unifiedDataChannel, uniformTypeDescriptor } from '@kit.ArkData';
import { router } from '@kit.ArkUI';
import { KeyCode } from '@kit.InputKit';
import { fileIo, picker } from '@kit.CoreFileKit';
import { Errors } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { copyIn, Shared } from '../common/Share';
import { glyph, line, mark, nameOf } from '../common/Devices';
import { app, Tile } from '../model/AppModel';
import { Admit } from '../model/Admit';
import { isInvitation } from '../model/Invite';
import { Alert, Device, Member } from '../model/Member';
import { BugCard } from '../components/BugCard';
import { BusyLine, ErrorText } from '../components/Common';
import { DeviceDetail, takesPastes } from '../components/DeviceDetail';
import { Orbit } from '../components/Orbit';
import { SettingsBody } from '../components/SettingsBody';

const LOST_PHONE_TIP: string = 'tip_lost_phone';
// From how wide a screen is a big one, in vp.
const WIDE_VP: number = 720;
// From how wide the sidebar stands beside the devices and the details (its
// 280, 360 of devices, the details' 400), in vp; narrower it slides in.
const SIDEBAR_VP: number = 1040;
const SIDEBAR_WIDTH: number = 280;
// What may be dropped on a tile or beside the tiles.
const DROPS: uniformTypeDescriptor.UniformDataType[] = [uniformTypeDescriptor.UniformDataType.PLAIN_TEXT,
  uniformTypeDescriptor.UniformDataType.IMAGE, uniformTypeDescriptor.UniformDataType.FILE];

// The text and files of a drop, the files copied into the new folder dir.
function dropped(event: DragEvent, dir: string): Shared {
  const out = new Shared();
  const uris: string[] = [];
  try {
    for (const r of event.getData().getRecords()) {
      if (r instanceof unifiedDataChannel.PlainText) {
        out.text += r.textContent;
      } else if (r instanceof unifiedDataChannel.Image) {
        uris.push(r.imageUri);
      } else if (r instanceof unifiedDataChannel.File) {
        uris.push(r.uri);
      }
    }
  } catch (e) {
    Errors.log(`main: reading a drop: ${String(e)}`);
  }
  copyIn(uris, dir, out);
  return out;
}

// What a settings row of the sidebar says: 's:' and a part of
// SettingsBody, or 'p:' and a page of its own.
function settingsLabel(key: string): string {
  switch (key) {
    case 's:general':
      return t('settings_language');
    case 's:notifications':
      return t('settings_notifications');
    case 'p:recovery':
      return t('recovery_title');
    case 'p:hub':
      return t('hub_title');
    case 's:group':
      return t('settings_group');
    case 's:lab':
      return t('lab');
    case 's:why':
      return t('why_screen');
    default:
      return t('settings_about');
  }
}

@Entry
@ComponentV2
struct Main {
  // The model's member, a field so that the monitors see its devices.
  @Local member: Member = app.member;
  @Local tiles: Tile[] = [];
  @Local stamp: number = 0;
  @Local error: string = '';
  @Local lostTipClosed: boolean = false;
  @Local wide: boolean = false;
  // The device whose details a big screen shows beside the devices.
  @Local selected: string = '';
  // Whether the sidebar stands beside the devices, or has slid in.
  @Local sidebar: boolean = false;
  @Local drawer: boolean = false;
  // The sidebar's section: 'all', 'attention', 'c:' and a collection's ID,
  // or 's:' and a part of Settings.
  @Local section: string = 'all';

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
      if (!this.sections().includes(this.section)) {
        this.section = 'all';
      }
    }
  }

  attention(): Device[] {
    return app.member.devices.filter((d: Device) => d.frozen === true);
  }

  collections(): Tile[] {
    return this.tiles.filter((x: Tile) => x.kind === 'collection');
  }

  settingsRows(): string[] {
    const rows: string[] = ['s:general', 's:notifications'];
    if (app.isRoot()) {
      rows.push('p:recovery');
    }
    if (app.member.running) {
      rows.push('p:hub');
    }
    if (app.membership !== undefined) {
      rows.push('s:group');
    }
    rows.push('s:lab');
    if (app.membership !== undefined) {
      rows.push('s:why');
    }
    rows.push('s:about');
    return rows;
  }

  // The sidebar's rows in its order, which Ctrl+1 to 9 open.
  sections(): string[] {
    const s: string[] = ['all'];
    if (this.attention().length > 0) {
      s.push('attention');
    }
    for (const c of this.collections()) {
      s.push(`c:${c.id}`);
    }
    return s.concat(this.settingsRows());
  }

  // Opens a section; another one closes the details.
  choose(section: string): void {
    this.drawer = false;
    if (section === 'p:recovery') {
      router.pushUrl({ url: 'pages/Recovery' });
    } else if (section === 'p:hub') {
      router.pushUrl({ url: 'pages/Hub' });
    } else if (section !== this.section) {
      this.section = section;
      this.selected = '';
    }
  }

  sectionTitle(): string {
    if (this.section === 'attention') {
      return t('needs_attention');
    }
    if (this.section.startsWith('c:')) {
      return this.collections().find((c: Tile) => `c:${c.id}` === this.section)?.name ?? '';
    }
    if (this.section.startsWith('s:')) {
      return settingsLabel(this.section);
    }
    return t('app_name');
  }

  // The tiles of the section: all of them in the user's order, or the
  // devices that need attention or are in the collection.
  shownTiles(): Tile[] {
    if (!this.wide || this.section === 'all') {
      return this.tiles;
    }
    const devices = this.section === 'attention' ? this.attention() :
      (this.collections().find((c: Tile) => `c:${c.id}` === this.section)?.devices ?? []);
    return devices.map((d: Device) => {
      const x = new Tile();
      x.device = d;
      x.id = d.id;
      return x;
    });
  }

  // Whether this phone may paste on the device of a tile.
  pastesOn(item: Tile): boolean {
    const d = item.device;
    return d !== undefined && d.self !== true && app.isAdmin() && app.member.running && takesPastes(d);
  }

  // A right click on a tile: paste on its device and mute or unmute it for
  // an admin, besides arranging it.
  tileActions(item: Tile): void {
    const sheets: SheetInfo[] = [];
    const d = item.device;
    if (d !== undefined && this.pastesOn(item)) {
      sheets.push({ title: t('paste_on_it'), action: () => {
        router.pushUrl({ url: 'pages/Paste', params: { 'device': d.id } as Record<string, Object> });
      } });
    }
    if (d !== undefined && d.self !== true && app.isAdmin() && app.member.running) {
      sheets.push({ title: t('device_mute_hour'), action: () => { app.manage('mute', d.id, '', 60); } });
      sheets.push({ title: t('device_unmute'), action: () => { app.manage('unmute', d.id); } });
    }
    sheets.push({ title: t('arrange_title'), action: () => { this.arrangeTile(item); } });
    this.getUIContext().showActionSheet({ title: item.kind === 'collection' ? item.name : nameOf(d as Device), message: '', sheets: sheets });
  }

  // Text, a picture or files dropped on a tile: pasted on its device.
  async dropOn(item: Tile, event: DragEvent): Promise<void> {
    const d = item.device;
    if (d === undefined || !this.pastesOn(item)) {
      return;
    }
    const s = dropped(event, `${getContext(this).cacheDir}/drop-${Date.now()}`);
    if (s.files.length > 0) {
      await app.pasteMedia(d.id, s.files, s.types, false);
    } else if (s.text.length > 0) {
      await app.pasteOn(d.id, s.text, 'paste', false, false);
    }
  }

  // Dropped beside the tiles: to the group, as Share sends it.
  dropBeside(event: DragEvent): void {
    const s = dropped(event, `${getContext(this).cacheDir}/drop-${Date.now()}`);
    app.member.sendDropped(s.text, s.files, s.types);
  }

  // The arrows choose the device before or after the chosen one, as they stand.
  step(by: number): void {
    const ids = this.shownTiles().filter((x: Tile) => x.device !== undefined).map((x: Tile) => (x.device as Device).id);
    if (ids.length === 0) {
      return;
    }
    const at = ids.indexOf(this.selected);
    this.selected = at < 0 ? ids[by > 0 ? 0 : ids.length - 1] : ids[Math.min(Math.max(at + by, 0), ids.length - 1)];
  }

  // The keyboard on a big screen: Ctrl+1 to 9 the sidebar's rows, Ctrl+,
  // the settings, Ctrl+N adds a device, the arrows choose one, Esc closes
  // its details.
  key(e: KeyEvent): boolean {
    if (!this.wide || e.type !== KeyType.Down) {
      return false;
    }
    const ctrl = e.getModifierKeyState !== undefined && e.getModifierKeyState(['Ctrl']);
    if (ctrl && e.keyCode >= KeyCode.KEYCODE_1 && e.keyCode <= KeyCode.KEYCODE_9) {
      const s = this.sections();
      const i = e.keyCode - KeyCode.KEYCODE_1;
      if (i < s.length) {
        this.choose(s[i]);
      }
      return true;
    }
    if (ctrl && e.keyCode === KeyCode.KEYCODE_COMMA) {
      this.choose('s:general');
      return true;
    }
    if (ctrl && e.keyCode === KeyCode.KEYCODE_N && app.isAdmin()) {
      this.scanCode();
      return true;
    }
    if (ctrl || this.section.startsWith('s:')) {
      return false;
    }
    if (e.keyCode === KeyCode.KEYCODE_DPAD_RIGHT || e.keyCode === KeyCode.KEYCODE_DPAD_DOWN) {
      this.step(1);
      return true;
    }
    if (e.keyCode === KeyCode.KEYCODE_DPAD_LEFT || e.keyCode === KeyCode.KEYCODE_DPAD_UP) {
      this.step(-1);
      return true;
    }
    if (e.keyCode === KeyCode.KEYCODE_ESCAPE && (this.selected.length > 0 || this.drawer)) {
      this.selected = '';
      this.drawer = false;
      return true;
    }
    return false;
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
      this.openDevice(tile.device.id);
    }
  }

  openDevice(id: string): void {
    if (this.wide) {
      this.selected = id;
    } else {
      router.pushUrl({ url: 'pages/Device', params: { 'device': id } as Record<string, Object> });
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
    if (this.wide) {
      const layouts: string[][] = [['orbit', t('main_show_orbit')], ['tiles', t('main_show_tiles')], ['list', t('main_show_list')]];
      for (const l of layouts) {
        if (l[0] !== app.wideLayout) {
          items.push({ value: l[1], action: () => {
            app.setWideLayout(l[0]);
          } });
        }
      }
    } else {
      items.push({ value: app.deviceList ? t('main_show_tiles') : t('main_show_list'), action: () => {
        app.setDeviceList(!app.deviceList);
      } });
    }
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

    .border({ width: this.wide && item.device !== undefined && item.device.id === this.selected ? 2 : 0,
      color: $r('app.color.accent'), radius: 20 })
    .onMouse((e: MouseEvent) => {
      if (e.button === MouseButton.Right && e.action === MouseAction.Press) {
        this.tileActions(item);
      }
    })
    .allowDrop(this.pastesOn(item) ? DROPS : null)
    .onDrop((e: DragEvent) => {
      this.dropOn(item, e);
    })
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

    .border({ width: this.wide && item.device !== undefined && item.device.id === this.selected ? 2 : 0,
      color: $r('app.color.accent'), radius: 20 })
    .onMouse((e: MouseEvent) => {
      if (e.button === MouseButton.Right && e.action === MouseAction.Press) {
        this.tileActions(item);
      }
    })
    .allowDrop(this.pastesOn(item) ? DROPS : null)
    .onDrop((e: DragEvent) => {
      this.dropOn(item, e);
    })
  }

  @Builder
  header() {
    Row() {
      if (this.wide && !this.sidebar) {
        this.menuButton()
      }
      Text(this.wide ? this.sectionTitle() : t('app_name')).fontSize(28).fontWeight(FontWeight.Bold).fontColor($r('app.color.text'))
        .layoutWeight(1).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis })
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
  }

  // Where sync stands, the paste button, what came last, the alerts and the tip.
  @Builder
  top() {
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
  }

  // The devices as tiles or a list; columns, the tiles in a row.
  @Builder
  devices(list: boolean, columns: number) {
    if (this.shownTiles().length > 0) {
      Text($r('app.string.main_devices')).fontSize(15).fontWeight(FontWeight.Medium).fontColor($r('app.color.secondary'))
      if (list) {
        Column() {
          ForEach(this.shownTiles(), (item: Tile) => {
            this.row(item);
          }, (item: Tile) => item.kind === 'collection' ? `c:${item.id}:${item.name}:${item.devices.length}` :
            `d:${JSON.stringify(item.device)}`)
        }
        .borderRadius(14)
        .backgroundColor($r('app.color.surface'))
      } else {
        Grid() {
          ForEach(this.shownTiles(), (item: Tile) => {
            GridItem() {
              this.tile(item);
            }
          }, (item: Tile) => item.kind === 'collection' ? `c:${item.id}:${item.name}:${item.devices.length}` :
            `d:${JSON.stringify(item.device)}`)
        }
        .columnsTemplate(Array<string>(columns).fill('1fr').join(' '))
        .columnsGap(12)
        .rowsGap(12)
        .maxCount(1000)
        .layoutDirection(GridDirection.Row)
      }
    }
  }

  @Builder
  errors() {
    BusyLine({ busy: app.busy })
    ErrorText({ text: app.member.error })
    ErrorText({ text: app.error })
    ErrorText({ text: this.error })
  }

  // The page: on a phone's screen one column; on a big one the devices,
  // on orbits unless the user chose tiles or a list, and the details beside.
  @Builder
  home() {
    Column() {
      this.header()
      if (this.wide && app.wideLayout === 'orbit' && this.section === 'all') {
        Scroll() {
          Column({ space: 16 }) {
            this.top()
          }
          .padding({ left: 24, right: 24 })
          .alignItems(HorizontalAlign.Start)
          .width('100%')
        }
        .constraintSize({ maxHeight: '45%' })
        .align(Alignment.Top)
        Orbit({ devices: app.member.devices, selected: this.selected, select: (id: string) => {
          this.selected = id;
        } })
          .layoutWeight(1)
        Column({ space: 8 }) {
          this.errors()
        }
        .padding({ left: 24, right: 24, bottom: 16 })
        .alignItems(HorizontalAlign.Start)
        .width('100%')
      } else {
        Scroll() {
          Column({ space: 16 }) {
            this.top()
            this.devices(this.wide ? app.wideLayout === 'list' : app.deviceList, this.wide ? 4 : 3)
            this.errors()
          }
          .padding({ left: 24, right: 24, bottom: 24 })
          .alignItems(HorizontalAlign.Start)
          .width('100%')
        }
        .layoutWeight(1)
        .align(Alignment.Top)
        .allowDrop(this.wide && app.member.running ? DROPS : null)
        .onDrop((e: DragEvent) => {
          this.dropBeside(e);
        })
      }
    }
    .layoutWeight(1)
    .height('100%')
  }

  // ☰, which slides the sidebar in where it does not stand.
  @Builder
  menuButton() {
    Button({ type: ButtonType.Circle }) {
      Text('☰').fontSize(22).fontColor($r('app.color.text'))
    }
    .width(44)
    .height(44)
    .backgroundColor(Color.Transparent)
    .accessibilityText($r('app.string.menu'))
    .onClick(() => {
      this.drawer = true;
    })
  }

  @Builder
  sideTitle(title: string) {
    Text(title).fontSize(13).fontWeight(FontWeight.Medium).fontColor($r('app.color.secondary'))
      .padding({ left: 12, top: 16, bottom: 4 })
  }

  // A row of the sidebar; count -1 for none.
  @Builder
  sideRow(key: string, symbol: string, label: string, count: number, danger: boolean) {
    Row({ space: 10 }) {
      Text(symbol).fontSize(17).width(24).textAlign(TextAlign.Center)
        .fontColor(danger ? $r('app.color.error') : $r('app.color.text'))
      Text(label).fontColor(danger ? $r('app.color.error') : $r('app.color.text')).layoutWeight(1)
        .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis })
      if (count >= 0) {
        Text(`${count}`).fontSize(13).fontColor($r('app.color.secondary'))
      }
    }
    .padding({ left: 12, right: 12, top: 10, bottom: 10 })
    .borderRadius(10)
    .width('100%')
    .backgroundColor(this.section === key ? $r('app.color.surface') : Color.Transparent)
    .onClick(() => {
      this.choose(key);
    })
  }

  // The sidebar: the group's line, the devices' sections and the parts of
  // Settings, with a short line on the keys at its foot.
  @Builder
  sidebarContent() {
    Scroll() {
      Column({ space: 2 }) {
        Text(this.onlineLine()).fontSize(15).fontColor($r('app.color.text')).padding({ left: 12, top: 12 })
        Text(this.syncLine()).fontSize(12).fontColor($r('app.color.secondary')).padding({ left: 12 })
        this.sideTitle(t('main_devices'))
        this.sideRow('all', '▦', t('all_devices'), app.member.devices.length, false)
        if (this.attention().length > 0) {
          this.sideRow('attention', '!', t('needs_attention'), this.attention().length, true)
        }
        ForEach(this.collections(), (c: Tile) => {
          this.sideRow(`c:${c.id}`, '\u{1F5C2}', c.name, c.devices.length, false)
        }, (c: Tile) => `${c.id}:${c.name}:${c.devices.length}`)
        this.sideTitle(t('settings_title'))
        ForEach(this.settingsRows(), (key: string) => {
          this.sideRow(key, key.startsWith('p:') ? '›' : '', settingsLabel(key), -1, false)
        }, (key: string) => key)
        Text(t('shortcuts_hint')).fontSize(11).fontColor($r('app.color.secondary')).padding({ left: 12, right: 12, top: 16 })
      }
      .padding({ left: 8, right: 8, bottom: 16 })
      .alignItems(HorizontalAlign.Start)
      .width('100%')
    }
    .align(Alignment.Top)
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }

  // A part of Settings beside the sidebar.
  @Builder
  settingsPane() {
    Column() {
      Row() {
        if (!this.sidebar) {
          this.menuButton()
        }
        Text(this.sectionTitle()).fontSize(28).fontWeight(FontWeight.Bold).fontColor($r('app.color.text')).layoutWeight(1)
      }
      .padding({ left: 24, right: 12, top: 8 })
      .width('100%')
      Scroll() {
        Column() {
          SettingsBody({ part: this.section.substring(2) })
        }
        .padding(24)
        .width('100%')
      }
      .layoutWeight(1)
      .align(Alignment.Top)
    }
    .layoutWeight(1)
    .height('100%')
  }

  // The devices, or a part of Settings, and the chosen device's details beside.
  @Builder
  content() {
    Row() {
      if (this.wide && this.section.startsWith('s:')) {
        this.settingsPane()
      } else {
        this.home()
        if (this.wide && this.selected.length > 0) {
          Divider().vertical(true).color($r('app.color.grid'))
          DeviceDetail({ deviceId: this.selected, close: () => {
            this.selected = '';
          } })
            .width(400)
            .height('100%')
        }
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }

  build() {
    Stack() {
      if (this.wide) {
        SideBarContainer(this.sidebar ? SideBarContainerType.Embed : SideBarContainerType.Overlay) {
          this.sidebarContent()
          this.content()
        }
        .showSideBar(this.sidebar || this.drawer)
        .showControlButton(false)
        .sideBarWidth(SIDEBAR_WIDTH)
        .minSideBarWidth(SIDEBAR_WIDTH)
        .maxSideBarWidth(SIDEBAR_WIDTH)
        .divider({ strokeWidth: 1, color: $r('app.color.grid') })
        .onChange((shown: boolean) => {
          if (!this.sidebar) {
            this.drawer = shown;
          }
        })
      } else {
        this.content()
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
    .focusable(true)
    .defaultFocus(true)
    .onKeyEvent((e: KeyEvent) => {
      this.key(e);
    })
    .onAreaChange((_: Area, area: Area) => {
      const width = Number(area.width);
      const wide = width >= WIDE_VP;
      this.sidebar = width >= SIDEBAR_VP;
      if (wide !== this.wide) {
        this.wide = wide;
        if (!wide) {
          this.selected = '';
          this.section = 'all';
          this.drawer = false;
        }
      }
    })
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
