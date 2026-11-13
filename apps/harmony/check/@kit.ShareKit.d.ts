// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
// What the app uses of the HarmonyOS SDK's Share Kit, which OpenHarmony's SDK
// lacks: declarations for check.sh only, never built into the app.
import common from '@ohos.app.ability.common';
import Want from '@ohos.app.ability.Want';
declare namespace systemShare {
  interface SharedRecord { utd: string; content?: string; uri?: string; title?: string; }
  class SharedData {
    constructor(record: SharedRecord);
    addRecord(record: SharedRecord): void;
    getRecords(): Array<SharedRecord>;
  }
  enum SharePreviewMode { DEFAULT = 0, DETAIL = 1 }
  enum SelectionMode { SINGLE = 0, BATCH = 1 }
  interface ShareControllerOptions { previewMode?: SharePreviewMode; selectionMode?: SelectionMode; }
  class ShareController {
    constructor(data: SharedData);
    show(context: common.UIAbilityContext, options: ShareControllerOptions): Promise<void>;
  }
  function getSharedData(want: Want): Promise<SharedData>;
}
export { systemShare };
