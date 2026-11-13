// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
// What the app uses of the HarmonyOS SDK's Scan Kit, which OpenHarmony's SDK
// lacks: declarations for check.sh only, never built into the app.
import common from '@ohos.app.ability.common';
declare namespace scanCore {
  enum ScanType { FORMAT_UNKNOWN = 0, QR_CODE = 11 }
}
declare namespace scanBarcode {
  interface ScanOptions { scanTypes?: Array<scanCore.ScanType>; enableMultiMode?: boolean; enableAlbum?: boolean; }
  interface ScanResult { scanType: scanCore.ScanType; originalValue: string; }
  function startScanForResult(context: common.Context, options?: ScanOptions): Promise<ScanResult>;
}
export { scanCore, scanBarcode };
