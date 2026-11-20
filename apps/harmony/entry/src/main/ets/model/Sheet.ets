// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the Share menu's sheet shows (pages/ShareSheet.ets): sending, sent,
// or the failure with its details in debug mode.

@ObservedV2
export class Sheet {
  // sending, sent or failed.
  @Trace phase: string = 'sending';
  @Trace message: string = '';
  close: () => void = () => {};
}

export const sheet: Sheet = new Sheet();
