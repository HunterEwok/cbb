// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a Bluetooth LE keyboard (docs/apps.md, "The lab"), as the
// Aurora app's BleKeyboard and the Linux computer's internal/blekeyboard:
// the app serves the HID service of HID over GATT, and a TV, a tablet or a
// computer that pairs with the phone takes what it types as a keyboard's
// keys, with nothing installed there. The reports and the report map come
// from the core (cbb_core::keyboard, its keyboard call); the system asks the
// user about a pairing, since the HID characteristics are read encrypted.
//
// HarmonyOS names a characteristic by its UUID alone, so the HID service
// has one report characteristic, the input report: the report map's LED
// output then has no characteristic, which the hosts tried with BlueZ take
// (the LEDs are only shown, never needed).

import { access, ble, connection, constant } from '@kit.ConnectivityKit';
import { abilityAccessCtrl, common, PermissionRequestResult, Permissions } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { BusinessError } from '@kit.BasicServicesKit';
import { call } from '../core/Core';
import { fromBase64 } from '../core/Bytes';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';

export const MIN_RATE: number = 5;
export const MAX_RATE: number = 60;
export const MAX_CHARS: number = 4096;
export const LAYOUTS: string[] = ['us', 'ru'];
export const RATES: number[] = [10, 20, 40];

const PERMISSION: Permissions = 'ohos.permission.ACCESS_BLUETOOTH';

// A 16-bit UUID of the Bluetooth SIG as HarmonyOS writes it.
export function sig(short: string): string {
  return `0000${short.toUpperCase()}-0000-1000-8000-00805F9B34FB`;
}

const HID: string = sig('1812');
const BATTERY: string = sig('180f');
const INFO: string = sig('180a');
const REPORT: string = sig('2a4d');
const BOOT_INPUT: string = sig('2a22');
const BOOT_OUTPUT: string = sig('2a32');
const HID_INFO: string = sig('2a4a');
const REPORT_MAP: string = sig('2a4b');
const CONTROL: string = sig('2a4c');
const PROTOCOL: string = sig('2a4e');
const LEVEL: string = sig('2a19');
const PNP: string = sig('2a50');
const REPORT_REF: string = sig('2908');
const CCCD: string = sig('2902');

// What the core's keyboard call answers.
interface Typed {
  reports?: string[];
  untypeable?: string;
  map?: string;
}

// What typing a remote paste came to: reason empty when it started, or why
// not, in English for the sender; refused false when it failed rather than
// being refused.
export class RemoteTyping {
  reason: string = '';
  refused: boolean = true;
}

function bytes(hex: string): ArrayBuffer {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16);
  }
  return out.buffer;
}

function same(a: string, b: string): boolean {
  return a.toUpperCase() === b.toUpperCase();
}

@ObservedV2
export class Keyboard {
  // The user's switch, kept in the settings.
  @Trace on: boolean = false;
  // The host's layout: us or ru (cbb_core::keyboard).
  @Trace layout: string = 'us';
  // Characters a second.
  @Trace rate: number = 20;
  // off, starting, ready (serving, no host), connected, or failed (error
  // says why).
  @Trace state: string = 'off';
  @Trace error: string = '';
  // Whether the app may not use Bluetooth yet: the page offers to allow it.
  @Trace denied: boolean = false;
  @Trace typing: boolean = false;
  // What came of the last text: '' while typing or before any, 'typed', or
  // why it was not typed.
  @Trace typed: string = '';

  private prefs: preferences.Preferences | undefined = undefined;
  private context: common.UIAbilityContext | undefined = undefined;
  private server: ble.GattServer | undefined = undefined;
  private advertising: boolean = false;
  // The hosts connected, and those that listen to the input report.
  private connected: Set<string> = new Set<string>();
  private listening: Set<string> = new Set<string>();
  private map: ArrayBuffer = new ArrayBuffer(0);
  // 1 for the report protocol, 0 once a host asked for the boot one.
  private protocol: number = 1;
  private reports: ArrayBuffer[] = [];
  private next: number = 0;
  private timer: number = -1;

  init(prefs: preferences.Preferences, context: common.UIAbilityContext): void {
    this.prefs = prefs;
    this.context = context;
    this.on = prefs.getSync('keyboard_on', false) as boolean;
    const layout = prefs.getSync('keyboard_layout', 'us') as string;
    this.layout = LAYOUTS.includes(layout) ? layout : 'us';
    this.rate = Math.min(MAX_RATE, Math.max(MIN_RATE, prefs.getSync('keyboard_rate', 20) as number));
    if (this.on) {
      this.start(false);
    }
  }

  setOn(on: boolean): void {
    if (on === this.on) {
      return;
    }
    this.on = on;
    this.prefs?.putSync('keyboard_on', on);
    this.prefs?.flush();
    if (on) {
      this.start(true);
    } else {
      this.stop();
    }
  }

  setLayout(layout: string): void {
    this.layout = LAYOUTS.includes(layout) ? layout : 'us';
    this.prefs?.putSync('keyboard_layout', this.layout);
    this.prefs?.flush();
  }

  setRate(rate: number): void {
    this.rate = Math.min(MAX_RATE, Math.max(MIN_RATE, rate));
    this.prefs?.putSync('keyboard_rate', this.rate);
    this.prefs?.flush();
  }

  // Starts again after a failure, asking for Bluetooth when it was denied.
  retry(): void {
    this.stop();
    this.start(true);
  }

  // The name of the host typed on, or '' when none or unknown.
  host(): string {
    for (const id of this.listening) {
      try {
        return connection.getRemoteDeviceName(id);
      } catch (e) {
        return '';
      }
    }
    return '';
  }

  private fail(message: string, details: string): void {
    this.stop();
    this.error = Errors.shown(new Failure(message, details));
    this.state = 'failed';
  }

  // Serves the keyboard once the app may use Bluetooth and it is on; ask:
  // the user turned it on, so the system may ask about Bluetooth now.
  private async start(ask: boolean): Promise<void> {
    if (this.state !== 'off' && this.state !== 'failed') {
      return;
    }
    this.state = 'starting';
    this.error = '';
    this.denied = false;
    if (!(await this.allowed(ask))) {
      this.denied = true;
      this.fail(t('keyboard_no_permission'), `${PERMISSION} not granted`);
      return;
    }
    try {
      if (access.getState() !== access.BluetoothState.STATE_ON) {
        this.fail(t('keyboard_bluetooth_off'), `bluetooth state ${access.getState()}`);
        return;
      }
    } catch (e) {
      this.fail(t('keyboard_refused'), Errors.unexpected('', e as Object).details);
      return;
    }
    const k = call<Typed>('keyboard', { 'layout': 'us' } as Record<string, Object>);
    if (k.ok === undefined) {
      this.fail((k.failure as Failure).message, (k.failure as Failure).details);
      return;
    }
    this.map = fromBase64(k.ok.map);
    try {
      const server = ble.createGattServer();
      this.server = server;
      server.on('connectionStateChange', (s: ble.BLEConnectionChangeState) => this.changed(s));
      server.on('characteristicRead', (r: ble.CharacteristicReadRequest) => this.read(r));
      server.on('characteristicWrite', (r: ble.CharacteristicWriteRequest) => this.written(r));
      server.on('descriptorRead', (r: ble.DescriptorReadRequest) => this.readDescriptor(r));
      server.on('descriptorWrite', (r: ble.DescriptorWriteRequest) => this.writtenDescriptor(r));
      for (const s of this.services()) {
        server.addService(s);
      }
    } catch (e) {
      this.fail(t('keyboard_refused'), Errors.unexpected('', e as Object).details);
      return;
    }
    this.advertise();
    if (this.state === 'starting') {
      Errors.log('keyboard: serving HID over GATT');
      this.state = this.listening.size > 0 ? 'connected' : 'ready';
    }
  }

  private async allowed(ask: boolean): Promise<boolean> {
    const context = this.context;
    if (context === undefined) {
      return false;
    }
    const at = abilityAccessCtrl.createAtManager();
    try {
      const token = context.applicationInfo.accessTokenId;
      if (at.checkAccessTokenSync(token, PERMISSION) === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
        return true;
      }
      if (!ask) {
        return false;
      }
      const r: PermissionRequestResult = await at.requestPermissionsFromUser(context, [PERMISSION]);
      return r.authResults.length > 0 && r.authResults[0] === 0;
    } catch (e) {
      Errors.log(`keyboard: asking for Bluetooth: ${Errors.unexpected('', e as Object).details}`);
      return false;
    }
  }

  private characteristic(service: string, uuid: string, value: ArrayBuffer, props: ble.GattProperties,
    encrypted: boolean, report?: string): ble.BLECharacteristic {
    const descriptors: ble.BLEDescriptor[] = [];
    const perms: ble.GattPermissions = encrypted ?
      { readEncrypted: true, writeEncrypted: props.write === true || props.writeNoResponse === true } :
      { read: true, write: props.write === true || props.writeNoResponse === true };
    if (report !== undefined) {
      descriptors.push({
        serviceUuid: service, characteristicUuid: uuid, descriptorUuid: REPORT_REF, descriptorValue: bytes(report),
        permissions: { readEncrypted: true }
      });
    }
    if (props.notify === true) {
      descriptors.push({
        serviceUuid: service, characteristicUuid: uuid, descriptorUuid: CCCD, descriptorValue: bytes('0000'),
        permissions: { read: true, writeEncrypted: true }
      });
    }
    return {
      serviceUuid: service, characteristicUuid: uuid, characteristicValue: value, descriptors: descriptors,
      properties: props, permissions: perms
    };
  }

  // The services: HID over GATT's, the battery's and the device
  // information's, as the Aurora app's.
  private services(): ble.GattService[] {
    const input: ble.GattProperties = { read: true, notify: true };
    const output: ble.GattProperties = { read: true, write: true, writeNoResponse: true };
    const hid: ble.BLECharacteristic[] = [
      // Report ID 0, an input report.
      this.characteristic(HID, REPORT, new ArrayBuffer(8), input, true, '0001'),
      this.characteristic(HID, BOOT_INPUT, new ArrayBuffer(8), input, true),
      this.characteristic(HID, BOOT_OUTPUT, new ArrayBuffer(1), output, true),
      // HID 1.11, no country, normally connectable.
      this.characteristic(HID, HID_INFO, bytes('11010002'), { read: true }, true),
      this.characteristic(HID, REPORT_MAP, this.map, { read: true }, true),
      this.characteristic(HID, CONTROL, new ArrayBuffer(1), { writeNoResponse: true }, false),
      // The report protocol until a host asks for the boot one.
      this.characteristic(HID, PROTOCOL, bytes('01'), { read: true, writeNoResponse: true }, true),
    ];
    return [
      { serviceUuid: HID, isPrimary: true, characteristics: hid },
      {
        serviceUuid: BATTERY, isPrimary: true,
        characteristics: [this.characteristic(BATTERY, LEVEL, bytes('64'), { read: true, notify: true }, false)]
      },
      {
        // The vendor ID source (USB), the Linux Foundation's vendor ID, a
        // product and a version, as the computer's.
        serviceUuid: INFO, isPrimary: true,
        characteristics: [this.characteristic(INFO, PNP, bytes('026b1d46010001'), { read: true }, false)]
      },
    ];
  }

  // The value a read answers; the system pairs first for an encrypted one.
  private valueFor(uuid: string): ArrayBuffer {
    if (same(uuid, REPORT_MAP)) {
      return this.map;
    }
    if (same(uuid, HID_INFO)) {
      return bytes('11010002');
    }
    if (same(uuid, PROTOCOL)) {
      return bytes(this.protocol === 0 ? '00' : '01');
    }
    if (same(uuid, LEVEL)) {
      return bytes('64');
    }
    if (same(uuid, PNP)) {
      return bytes('026b1d46010001');
    }
    if (same(uuid, BOOT_OUTPUT)) {
      return new ArrayBuffer(1);
    }
    return new ArrayBuffer(8);
  }

  private respond(deviceId: string, transId: number, offset: number, value: ArrayBuffer): void {
    try {
      this.server?.sendResponse({
        deviceId: deviceId, transId: transId, status: 0, offset: offset,
        value: offset > 0 ? value.slice(offset) : value
      });
    } catch (e) {
      Errors.log(`keyboard: answering a read: ${Errors.unexpected('', e as Object).details}`);
    }
  }

  private read(r: ble.CharacteristicReadRequest): void {
    this.respond(r.deviceId, r.transId, r.offset, this.valueFor(r.characteristicUuid));
  }

  private written(r: ble.CharacteristicWriteRequest): void {
    if (same(r.characteristicUuid, PROTOCOL) && r.value.byteLength > 0) {
      this.protocol = new Uint8Array(r.value)[0];
    }
    if (r.needRsp) {
      this.respond(r.deviceId, r.transId, 0, new ArrayBuffer(0));
    }
  }

  private readDescriptor(r: ble.DescriptorReadRequest): void {
    let value = new ArrayBuffer(2);
    if (same(r.descriptorUuid, REPORT_REF)) {
      value = bytes('0001');
    } else if (same(r.descriptorUuid, CCCD)) {
      value = bytes(this.listening.has(r.deviceId) ? '0100' : '0000');
    }
    this.respond(r.deviceId, r.transId, r.offset, value);
  }

  private writtenDescriptor(r: ble.DescriptorWriteRequest): void {
    if (same(r.descriptorUuid, CCCD) &&
      (same(r.characteristicUuid, REPORT) || same(r.characteristicUuid, BOOT_INPUT))) {
      const on = r.value.byteLength > 0 && (new Uint8Array(r.value)[0] & 1) === 1;
      this.listen(r.deviceId, on);
    }
    if (r.needRsp) {
      this.respond(r.deviceId, r.transId, 0, new ArrayBuffer(0));
    }
  }

  private changed(s: ble.BLEConnectionChangeState): void {
    if (s.state === constant.ProfileConnectionState.STATE_CONNECTED) {
      this.connected.add(s.deviceId);
      Errors.log('keyboard: a host connected');
    } else if (s.state === constant.ProfileConnectionState.STATE_DISCONNECTED) {
      // A host that went away takes no more reports, whether or not it
      // said so.
      this.connected.delete(s.deviceId);
      this.listen(s.deviceId, false);
      Errors.log('keyboard: a host disconnected');
    }
  }

  private listen(deviceId: string, on: boolean): void {
    if (on) {
      this.listening.add(deviceId);
    } else {
      this.listening.delete(deviceId);
    }
    if (this.server !== undefined && (this.state === 'ready' || this.state === 'connected')) {
      this.state = this.listening.size > 0 ? 'connected' : 'ready';
    }
  }

  // Advertises the HID service, connectable, while the keyboard is on, so
  // that a new host finds the phone by its name and a paired one connects
  // again.
  private advertise(): void {
    try {
      ble.startAdvertising({ interval: 160, connectable: true },
        { serviceUuids: [HID], manufactureData: [], serviceData: [], includeDeviceName: true });
      this.advertising = true;
    } catch (e) {
      this.fail(t('keyboard_refused'), Errors.unexpected('advertising', e as Object).details);
    }
  }

  private stop(): void {
    this.finish('');
    if (this.advertising) {
      try {
        ble.stopAdvertising();
      } catch (e) {
        Errors.log(`keyboard: stopping the advertising: ${(e as BusinessError).message}`);
      }
      this.advertising = false;
    }
    if (this.server !== undefined) {
      try {
        this.server.off('connectionStateChange');
        this.server.off('characteristicRead');
        this.server.off('characteristicWrite');
        this.server.off('descriptorRead');
        this.server.off('descriptorWrite');
        for (const s of [HID, BATTERY, INFO]) {
          this.server.removeService(s);
        }
        this.server.close();
      } catch (e) {
        Errors.log(`keyboard: closing the server: ${(e as BusinessError).message}`);
      }
      this.server = undefined;
    }
    this.connected.clear();
    this.listening.clear();
    this.protocol = 1;
    this.state = 'off';
  }

  // The reports that type text in the host's layout, or the failure to
  // show; untypeable names at most eight characters it has no key for.
  private reportsFor(text: string): Typed | Failure {
    const k = call<Typed>('keyboard', { 'layout': this.layout, 'text': text } as Record<string, Object>);
    if (k.ok === undefined) {
      return k.failure as Failure;
    }
    const untypeable = Array.from(k.ok.untypeable ?? '').slice(0, 8).join(' ');
    return { reports: k.ok.reports ?? [], untypeable: untypeable } as Typed;
  }

  // Types text on the connected host; typed tells how it went.
  type(text: string): void {
    if (this.typing) {
      return;
    }
    if (this.listening.size === 0) {
      this.finish(t('keyboard_no_host'));
      return;
    }
    if (text.length === 0) {
      this.finish(t('paste_clipboard_empty'));
      return;
    }
    if (text.length > MAX_CHARS) {
      this.finish(t('keyboard_too_long', MAX_CHARS));
      return;
    }
    const r = this.reportsFor(text);
    if (r instanceof Failure) {
      this.finish(Errors.shown(r));
      return;
    }
    if ((r.untypeable ?? '').length > 0) {
      this.finish(t('keyboard_untypeable', r.untypeable ?? ''));
      return;
    }
    this.begin(r.reports ?? []);
  }

  // Types a remote paste's text on the connected host.
  typeRemote(text: string): RemoteTyping {
    const out = new RemoteTyping();
    if (!this.on) {
      out.reason = 'this phone types remote pastes on its Bluetooth keyboard, which is off; its user turns it on in the app\'s settings';
      return out;
    }
    if (text.length > MAX_CHARS) {
      out.reason = `the text is longer than the ${MAX_CHARS} characters a keyboard types`;
      return out;
    }
    if (this.listening.size === 0) {
      out.refused = false;
      out.reason = 'this phone\'s Bluetooth keyboard is not connected to a device';
      return out;
    }
    if (this.typing) {
      out.reason = 'this phone\'s Bluetooth keyboard is typing another text; send it again in a moment';
      return out;
    }
    const r = this.reportsFor(text);
    if (r instanceof Failure) {
      out.refused = false;
      out.reason = r.details.length > 0 ? r.details : r.message;
      return out;
    }
    if ((r.untypeable ?? '').length > 0) {
      out.reason = `the host's layout (${this.layout}) has no key for ${r.untypeable ?? ''}`;
      return out;
    }
    this.begin(r.reports ?? []);
    return out;
  }

  private begin(reports: string[]): void {
    this.reports = reports.map((r: string) => fromBase64(r));
    this.next = 0;
    this.typed = '';
    this.typing = true;
    // A report down and one up for each character.
    this.timer = setInterval(() => this.step(), Math.max(1, Math.floor(1000 / (2 * this.rate))));
  }

  private step(): void {
    if (this.next >= this.reports.length) {
      this.finish('typed');
      return;
    }
    const report = this.reports[this.next++];
    this.send(report).then((ok: boolean) => {
      if (!ok && this.typing) {
        this.send(new ArrayBuffer(8));
        this.finish(t('keyboard_went_away'));
      }
    });
  }

  private async send(report: ArrayBuffer): Promise<boolean> {
    const server = this.server;
    if (server === undefined || this.listening.size === 0) {
      return false;
    }
    // The boot keyboard's report when a host chose the boot protocol.
    const uuid = this.protocol === 0 ? BOOT_INPUT : REPORT;
    let sent = false;
    for (const id of this.listening) {
      try {
        await server.notifyCharacteristicChanged(id,
          { serviceUuid: HID, characteristicUuid: uuid, characteristicValue: report, confirm: false });
        sent = true;
      } catch (e) {
        Errors.log(`keyboard: a report: ${Errors.unexpected('', e as Object).details}`);
      }
    }
    return sent;
  }

  private finish(typed: string): void {
    if (this.timer !== -1) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    this.reports = [];
    this.typing = false;
    this.typed = typed;
  }
}
