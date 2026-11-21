// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The lab (docs/apps.md, "The lab"): the Bluetooth keyboard's UUIDs, and
// the remote paste receiver's limits, log and answers.

import { describe, expect, it } from '@ohos/hypium';
import { sig } from '../../../main/ets/model/Keyboard';
import { appended, BURST, CheckedPaste, Limiter, LOG_SIZE, Paste, PasteEntry } from '../../../main/ets/model/Paste';

function entry(n: number): PasteEntry {
  const e: PasteEntry = { time_ms: n, by: 'pc', bytes: 1, enter: false, status: 'done' };
  return e;
}

function paste(type: string, text: string, sender?: string): CheckedPaste {
  const c: CheckedPaste = {
    command: { type: type, by: sender ?? 'pc', text: text }, verified: true, sender: sender ?? 'pc', clean: text
  };
  return c;
}

export default function labTest() {
  describe('lab', () => {
    it('names_the_hid_service', 0, () => {
      expect(sig('1812')).assertEqual('00001812-0000-1000-8000-00805F9B34FB');
      expect(sig('2a4d')).assertEqual('00002A4D-0000-1000-8000-00805F9B34FB');
    });

    it('limits_each_sender', 0, () => {
      const l = new Limiter();
      expect(l.allow('pc', 0)).assertTrue();
      expect(l.allow('pc', 500)).assertFalse();
      expect(l.allow('laptop', 500)).assertTrue();
      let allowed = 1;
      for (let t = 1000; t < 60000; t += 1000) {
        if (l.allow('pc', t)) {
          allowed++;
        }
      }
      expect(allowed).assertEqual(BURST);
      // A minute after the first, one more goes.
      expect(l.allow('pc', 60000)).assertTrue();
    });

    it('keeps_the_last_pastes', 0, () => {
      let log: PasteEntry[] = [];
      for (let i = 0; i < LOG_SIZE + 5; i++) {
        log = appended(log, entry(i));
      }
      expect(log.length).assertEqual(LOG_SIZE);
      expect(log[0].time_ms).assertEqual(5);
    });

    it('answers_pastes', 0, () => {
      const p = new Paste();
      const off = p.carryOut(paste('paste', 'hello'), 'pc');
      expect(off.status).assertEqual('refused');
      expect(off.reason.includes('remote paste is off')).assertTrue();
      p.on = true;
      expect(p.carryOut(paste('paste', 'a\nb'), 'pc').reason.includes('line break')).assertTrue();
      expect(p.carryOut(paste('paste', 'hello'), 'pc').reason.includes('too many pastes')).assertTrue();
      // No keyboard: the paste failed rather than being refused.
      expect(p.carryOut(paste('paste', 'hello', 'laptop'), 'laptop').status).assertEqual('failed');
      expect(p.carryOut(paste('paste-off', ''), 'pc').status).assertEqual('done');
      expect(p.on).assertFalse();
      expect(p.log.length).assertEqual(4);
    });
  });
}
