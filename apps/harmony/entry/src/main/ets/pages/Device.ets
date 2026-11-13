// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A device of the group on its own page (components/DeviceDetail.ets); a big
// screen shows the same details beside Home's devices.

import { router } from '@kit.ArkUI';
import { DeviceDetail } from '../components/DeviceDetail';

@Entry
@ComponentV2
struct Device {
  @Local deviceId: string = '';

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    this.deviceId = params !== undefined && params['device'] !== undefined ? String(params['device']) : '';
  }

  build() {
    Column() {
      DeviceDetail({ deviceId: this.deviceId, close: () => {
        router.back();
      } })
    }
    .width('100%')
    .height('100%')
  }
}
