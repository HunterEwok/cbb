// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The changes of the tiles' arrangement (docs/apps.md, "Collections and the
// order of the tiles") as operations of the core's arrange call, for the
// tiles AppModel.arranged gives; the Aurora app's arrange.js.

import { Tile } from '../model/AppModel';

// How an operation names the tile.
export function ref(tile: Tile): Record<string, Object> {
  const r: Record<string, Object> = {};
  if (tile.kind === 'device' && tile.device !== undefined) {
    r['device'] = tile.device.id;
  } else {
    r['collection'] = tile.id;
  }
  return r;
}

// The move of level[index] to "start", "earlier", "later" or "end" of its
// level, or undefined when it is there already.
export function move(level: Tile[], index: number, to: string): Record<string, Object> | undefined {
  const op: Record<string, Object> = { 'op': 'move', 'item': ref(level[index]) };
  const last = level.length - 1;
  if (to === 'start') {
    if (index === 0) {
      return undefined;
    }
    op['before'] = ref(level[0]);
  } else if (to === 'earlier') {
    if (index === 0) {
      return undefined;
    }
    op['before'] = ref(level[index - 1]);
  } else if (to === 'later') {
    if (index === last) {
      return undefined;
    }
    if (index + 2 < level.length) {
      op['before'] = ref(level[index + 2]);
    }
  } else if (index === last) {
    return undefined;
  }
  return op;
}

// A collection's devices as tiles of its level.
export function tilesOf(c: Tile): Tile[] {
  return c.devices.map((d) => {
    const tile = new Tile();
    tile.device = d;
    return tile;
  });
}
