// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the phone and its HarmonyOS watch say to each other: the state fits
// one message, and an ask reads back as it went.

import { describe, expect, it } from '@ohos/hypium';
import { decodeAsk, decodeState, encode, fit, MAX_MESSAGE, WatchDevice, WatchState } from '../../../main/ets/common/WatchState';

function state(devices: number, events: number): WatchState {
  const ds: WatchDevice[] = [];
  for (let i = 0; i < devices; i++) {
    ds.push({ id: `device-${i}`, name: `A computer with a long name ${i}`, form: 'computer', online: i % 2 === 0, collection: '', phone: i === 0 });
  }
  const es: string[] = [];
  for (let i = 0; i < events; i++) {
    es.push(`An event that says what happened in the group ${i}`);
  }
  return { type: 'state', group: true, devices: ds, more: 0, online: 1, total: devices, sync: true, away: 'home', events: es };
}

export default function watchTest() {
  describe('watch', () => {
    it('keeps_a_small_state_whole', 0, () => {
      const s = decodeState(fit(state(3, 2)));
      expect(s !== undefined).assertTrue();
      expect((s as WatchState).devices.length).assertEqual(3);
      expect((s as WatchState).events.length).assertEqual(2);
      expect((s as WatchState).more).assertEqual(0);
    });

    it('fits_a_large_state_in_one_message', 0, () => {
      const data = fit(state(40, 5));
      expect(data.length <= MAX_MESSAGE).assertTrue();
      const s = decodeState(data) as WatchState;
      expect(s.events.length).assertEqual(0);
      expect(s.devices.length + s.more).assertEqual(40);
      expect(s.total).assertEqual(40);
    });

    it('reads_the_asks', 0, () => {
      const a = decodeAsk(encode({ type: 'away', on: false }));
      expect(a !== undefined && a.type === 'away' && !a.on).assertTrue();
      expect(decodeAsk(encode({ type: 'paste', on: true })) === undefined).assertTrue();
      expect(decodeState(encode({ type: 'sync', on: true })) === undefined).assertTrue();
    });
  });
}
