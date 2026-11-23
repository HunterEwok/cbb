// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The lab (docs/apps.md, "The lab"): the Bluetooth keyboard's UUIDs.

import { describe, expect, it } from '@ohos/hypium';
import { sig } from '../../../main/ets/model/Keyboard';

export default function labTest() {
  describe('lab', () => {
    it('names_the_hid_service', 0, () => {
      expect(sig('1812')).assertEqual('00001812-0000-1000-8000-00805F9B34FB');
      expect(sig('2a4d')).assertEqual('00002A4D-0000-1000-8000-00805F9B34FB');
    });
  });
}
