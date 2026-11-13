// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The link between the phone and its watch through Wear Engine's P2P
// messages (docs/apps.md, "HarmonyOS watches"): finds the other device of
// the pair, listens to what its CBB says and sends to it. The only place
// that calls Wear Engine; the same file is in the phone's module and the
// watch's, which check.sh keeps the same.

import { common } from '@kit.AbilityKit';
import { wearEngine } from '@kit.WearEngine';
import { Errors } from '../core/Errors';
import { BUNDLE, FINGERPRINT } from './WatchState';

export class Wear {
  // Whether the other device is connected with CBB on it.
  reachable: boolean = false;
  private client: wearEngine.P2pClient | undefined = undefined;
  private devices: wearEngine.DeviceClient | undefined = undefined;
  private peer: string = '';
  private receiver: ((m: wearEngine.P2pMessage) => void) | undefined = undefined;
  private param: wearEngine.P2pAppParam = { remoteApp: { bundleName: BUNDLE, fingerprint: FINGERPRINT } };

  // Connects to the first connected device of the category (the watch on
  // the phone, the phone on the watch) and hands its messages to got;
  // false when there is none or it has no CBB.
  async connect(context: common.Context, watch: boolean, got: (data: Uint8Array) => void): Promise<boolean> {
    try {
      this.client = this.client ?? wearEngine.getP2pClient(context);
      this.devices = this.devices ?? wearEngine.getDeviceClient(context);
      const want = watch ? wearEngine.DeviceCategory.WATCH : wearEngine.DeviceCategory.PHONE;
      const found = (await this.devices.getConnectedDevices()).find((d: wearEngine.Device) => d.category === want);
      if (found === undefined) {
        await this.close();
        return false;
      }
      if (found.randomId === this.peer && this.reachable) {
        return true;
      }
      await this.close();
      if (!(await this.client.isRemoteAppInstalled(found.randomId, BUNDLE))) {
        Errors.log('wear: the other device has no CBB');
        return false;
      }
      const receiver = (m: wearEngine.P2pMessage) => got(m.content);
      await this.client.registerMessageReceiver(found.randomId, this.param, receiver);
      this.receiver = receiver;
      this.peer = found.randomId;
      this.reachable = true;
      Errors.log(`wear: linked with ${found.model}`);
      return true;
    } catch (e) {
      Errors.log(`wear: ${Errors.unexpected('', e as Object).details}`);
      this.reachable = false;
      return false;
    }
  }

  async send(data: Uint8Array): Promise<boolean> {
    if (this.client === undefined || !this.reachable) {
      return false;
    }
    try {
      const r = await this.client.sendMessage(this.peer, this.param, { content: data });
      return r.code === wearEngine.P2pResultCode.SUCCESS;
    } catch (e) {
      Errors.log(`wear: sending: ${Errors.unexpected('', e as Object).details}`);
      this.reachable = false;
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.client !== undefined && this.receiver !== undefined) {
      try {
        await this.client.unregisterMessageReceiver(this.receiver);
      } catch (e) {
        Errors.log(`wear: closing: ${Errors.unexpected('', e as Object).details}`);
      }
    }
    this.receiver = undefined;
    this.peer = '';
    this.reachable = false;
  }
}
