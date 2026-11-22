// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
// What the app uses of the HarmonyOS SDK's Wear Engine Kit, which
// OpenHarmony's SDK lacks: declarations for check.sh only, never built into
// the app, kept in step with the declarations of HarmonyOS SDK 6.1.1 (API
// 24), which DevEco Studio's compiler checks against (the device client and
// the P2P client); the app calls them only in common/Wear.ets.
import common from '@ohos.app.ability.common';
import { Callback } from '@ohos.base';
declare namespace wearEngine {
  enum DeviceCategory { DEFAULT = 1, WATCH = 2, BAND = 3, OTHER_DEVICES = 255 }
  interface Device {
    randomId: string;
    category?: DeviceCategory;
    name?: string;
    model?: string;
    isSmartWatch?: boolean;
  }
  interface DeviceClient {
    getConnectedDevices(): Promise<Device[]>;
  }
  interface AppInfo { bundleName: string; fingerprint: string; }
  interface P2pAppParam { remoteApp: AppInfo; transformLocalAppInfo?: boolean; }
  interface P2pMessage { content: Uint8Array; }
  enum P2pResultCode {
    REMOTE_APP_NOT_INSTALLED = 200,
    REMOTE_APP_NOT_RUNNING = 201,
    REMOTE_APP_RUNNING = 202,
    UNKNOWN_ERROR = 203,
    COMMUNICATION_FAILURE = 206,
    COMMUNICATION_SUCCESS = 207
  }
  interface P2pResult { code?: number; progress?: number; }
  interface P2pClient {
    isRemoteAppInstalled(deviceRandomId: string, remoteBundleName: string): Promise<boolean>;
    sendMessage(deviceRandomId: string, appParam: P2pAppParam, message: P2pMessage): Promise<P2pResult>;
    registerMessageReceiver(deviceRandomId: string, appParam: P2pAppParam, callback: Callback<P2pMessage>): Promise<void>;
    unregisterMessageReceiver(deviceRandomId: string, appParam: P2pAppParam, callback: Callback<P2pMessage>): Promise<void>;
  }
  function getDeviceClient(context: common.Context): DeviceClient;
  function getP2pClient(context: common.Context): P2pClient;
}
export { wearEngine };
