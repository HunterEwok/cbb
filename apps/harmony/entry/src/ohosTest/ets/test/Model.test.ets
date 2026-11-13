// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The app's own logic around the core: what is the home network, the moves
// of the tiles, the group's events between two looks, the words of "Why it
// does not sync", base64, and that the linked core answers.

import { describe, expect, it } from '@ohos/hypium';
import { versionLine } from '../../../main/ets/core/Core';
import { fromBase64, shortLine, toBase64 } from '../../../main/ets/core/Bytes';
import { move } from '../../../main/ets/common/Arrange';
import { whyAction, whyDetail, whyTitle } from '../../../main/ets/common/Why';
import { Tile } from '../../../main/ets/model/AppModel';
import { between, GroupEvent, Seen } from '../../../main/ets/model/Events';
import { Device } from '../../../main/ets/model/Member';
import { isHome, netAddress } from '../../../main/ets/model/Net';

function tile(id: string): Tile {
  const d: Device = { id: id, name: id };
  const x = new Tile();
  x.device = d;
  return x;
}

function seen(name: string, admin: boolean, frozen: boolean, root: boolean): Seen {
  const s: Seen = { name: name, admin: admin, frozen: frozen, root: root };
  return s;
}

export default function modelTest() {
  describe('model', () => {
    it('knows_the_home_network', 0, () => {
      expect(isHome('192.168.1.5')).assertTrue();
      expect(isHome('10.0.0.1')).assertTrue();
      expect(isHome('172.16.4.4')).assertTrue();
      expect(isHome('172.32.4.4')).assertFalse();
      expect(isHome('8.8.8.8')).assertFalse();
      expect(isHome('fd00::1')).assertTrue();
      expect(isHome('::ffff:192.168.0.2')).assertTrue();
      expect(isHome('2001:db8::1')).assertFalse();
      expect(isHome('not an address')).assertFalse();
    });

    it('reads_addresses', 0, () => {
      expect(netAddress('192.168.1.5:8764')?.port).assertEqual(8764);
      expect(netAddress('[fd00::1]:8764')?.address).assertEqual('fd00::1');
      expect(netAddress('no port')).assertUndefined();
    });

    it('moves_tiles', 0, () => {
      const level = [tile('a'), tile('b'), tile('c')];
      expect(move(level, 0, 'start')).assertUndefined();
      expect(move(level, 2, 'end')).assertUndefined();
      expect(JSON.stringify(move(level, 2, 'start'))).assertEqual('{"op":"move","item":{"device":"c"},"before":{"device":"a"}}');
      expect(JSON.stringify(move(level, 0, 'later'))).assertEqual('{"op":"move","item":{"device":"a"},"before":{"device":"c"}}');
      expect(JSON.stringify(move(level, 1, 'later'))).assertEqual('{"op":"move","item":{"device":"b"}}');
    });

    it('tells_the_events_between_two_looks', 0, () => {
      const old = new Map<string, Seen>();
      old.set('1', seen('Mac', false, false, false));
      old.set('2', seen('Pi', false, false, false));
      old.set('3', seen('Phone', true, false, false));
      const now = new Map<string, Seen>();
      now.set('1', seen('Mac', true, false, false));
      now.set('3', seen('Phone', true, true, true));
      now.set('4', seen('Laptop', false, false, false));
      const kinds = between(old, now).map((e: GroupEvent) => e.kind);
      // By name, removals last: Laptop joined, Mac an admin, Phone took over
      // and was frozen, Pi removed.
      expect(kinds.join(',')).assertEqual('devices,admins,takeover,frozen,devices');
    });

    it('says_why_it_does_not_sync', 0, () => {
      expect(whyTitle({ code: 'something_new' })).assertEqual('something_new');
      expect(whyAction({ code: 'something_new' })).assertEqual('');
      expect(whyAction({ code: 'update', value: '0.7.0' })).assertEqual('');
      expect(whyAction({ code: 'sync_off' }).length > 0).assertTrue();
      expect(whyDetail({ code: 'alone', detail: 'no peer' })).assertEqual('alone: no peer');
    });

    it('keeps_bytes_in_base64', 0, () => {
      const b = new Uint8Array([0, 1, 254, 255]);
      expect(toBase64(b)).assertEqual('AAH+/w==');
      expect(new Uint8Array(fromBase64('AAH+/w==')).join(',')).assertEqual('0,1,254,255');
      expect(shortLine('a\n b   c', 100)).assertEqual('a b c');
    });

    it('links_the_core', 0, () => {
      expect(versionLine().length > 0).assertTrue();
    });
  });
}
