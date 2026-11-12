// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
// What the app uses of the HarmonyOS SDK's Wear Engine Kit, which
// OpenHarmony's SDK lacks: declarations for check.sh only, never built into
// the app, after the kit's guide for HarmonyOS 5 (the device client and the
// P2P client); the app calls them only in model/Wear.ets.
import common from '@ohos.app.ability.common';
import { Callback } from '@ohos.base';
declare namespace wearEngine {
  enum DeviceCategory { PHONE = 0, WATCH = 1, BAND = 2 }
  interface Device {
    randomId: string;
    name: string;
    model: string;
    category: DeviceCategory;
  }
  interface DeviceClient {
    getConnectedDevices(): Promise<Device[]>;
  }
  interface AppInfo { bundleName: string; fingerprint: string; }
  interface P2pAppParam { remoteApp: AppInfo; }
  interface P2pMessage { content: Uint8Array; }
  enum P2pResultCode { SUCCESS = 0 }
  interface P2pResult { code: P2pResultCode; }
  interface P2pClient {
    isRemoteAppInstalled(deviceRandomId: string, remoteBundleName: string): Promise<boolean>;
    startRemoteApp(deviceRandomId: string, remoteApp: AppInfo): Promise<P2pResult>;
    sendMessage(deviceRandomId: string, appParam: P2pAppParam, message: P2pMessage): Promise<P2pResult>;
    registerMessageReceiver(deviceRandomId: string, appParam: P2pAppParam, callback: Callback<P2pMessage>): Promise<void>;
    unregisterMessageReceiver(callback: Callback<P2pMessage>): Promise<void>;
  }
  function getDeviceClient(context: common.Context): DeviceClient;
  function getP2pClient(context: common.Context): P2pClient;
}
export { wearEngine };
