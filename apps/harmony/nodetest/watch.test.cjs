// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The watch's link to its phone (wearable/src/main/ets/model/Link.ets) under
// Node, with shim.cjs standing in for the watch (run.sh): a fake Wear keeps
// what the watch sends, fake preferences what it keeps, and the admin key
// signs with a stand-in, so the test sees what the watch agrees to sign.
'use strict';
const assert = require('node:assert');
const path = require('node:path');
const { describe, it, beforeEach } = require('node:test');
const { out } = require('./shim.cjs');

const model = path.join(out, 'wearable/src/main/ets/model');
const adminKey = require(path.join(model, 'AdminKey.js'));
const { Link } = require(path.join(model, 'Link.js'));

const signed = [];
adminKey.sign = async (body) => {
  signed.push(Buffer.from(body).toString('utf8'));
  return 'SIG';
};
adminKey.makeKey = async () => 'KEY';

const json = (o) => new Uint8Array(Buffer.from(JSON.stringify(o)));
const ADMITTED = { type: 'admitted', device: 'watch-1', group: 'g1', signer: 'h1' };

function prefs(kept = {}) {
  const m = new Map(Object.entries(kept));
  return {
    m,
    getSync: (k, d) => (m.has(k) ? m.get(k) : d),
    putSync: (k, v) => m.set(k, v),
    flush: () => {},
  };
}

// A link with a fake wear; sent holds what the watch sent, decoded.
function linked(kept) {
  const link = new Link();
  const sent = [];
  const wear = { up: true, send: async (d) => { sent.push(JSON.parse(Buffer.from(d).toString('utf8'))); return wear.up; }, close: () => {} };
  link.wear = wear;
  const p = prefs(kept);
  link.init(p);
  return { link, sent, wear, p, got: (o) => link.got(json(o)) };
}

// Shows body to the watch in parts of size bytes and waits for its answer.
async function show(l, body, size = 1000) {
  const bytes = Buffer.from(JSON.stringify(body));
  const parts = [];
  for (let i = 0; i < bytes.length; i += size) parts.push(bytes.subarray(i, i + size).toString('base64'));
  for (let i = 0; i < parts.length; i++) l.got({ type: 'sign', part: i, parts: parts.length, data: parts[i] });
  await new Promise((r) => setImmediate(r));
  return l.sent.at(-1);
}

describe('watch link', () => {
  beforeEach(() => { signed.length = 0; });

  it('keeps the phone\'s state and shows it after a restart', () => {
    const l = linked();
    const state = { type: 'state', group: true, devices: [], more: 0, online: 1, total: 2, sync: true, away: 'off', events: [], admin: false, signs: false };
    l.got(state);
    assert.deepStrictEqual(l.link.state, state);
    assert.strictEqual(l.link.fresh, true);
    const again = linked(Object.fromEntries(l.p.m));
    assert.deepStrictEqual(again.link.state, state);
    assert.strictEqual(linked({ watch_state: '{' }).link.state, undefined);
  });

  it('becomes an admin only with the whole note, and keeps it', async () => {
    const l = linked();
    l.got({ type: 'admitted', device: 'watch-1', group: 'g1' });
    await l.link.act('freeze', 'phone-2');
    assert.strictEqual(l.sent.length, 0, 'acts before it is an admin');
    l.got(ADMITTED);
    const again = linked(Object.fromEntries(l.p.m));
    await again.link.act('freeze', 'phone-2');
    assert.deepStrictEqual(again.sent, [{ type: 'act', on: true, action: 'freeze', device: 'phone-2' }]);
    assert.strictEqual(again.link.acting, 'phone-2');
    again.got({ type: 'done', ok: true });
    assert.strictEqual(again.link.acting, '');
    assert.strictEqual(linked({ watch_admitted: 'no' }).link.admitted, undefined);
  });

  it('signs the command the wearer confirmed, in parts too', async () => {
    const l = linked();
    l.got(ADMITTED);
    await l.link.act('freeze', 'phone-2');
    const cmd = { type: 'freeze', group: 'g1', by: 'watch-1', to: 'phone-2', pad: 'x'.repeat(1500) };
    assert.deepStrictEqual(await show(l, cmd, 600), { type: 'signed', on: true, sig: 'SIG' });
    assert.strictEqual(signed.length, 1);
    assert.deepStrictEqual(JSON.parse(signed[0]), cmd);
    l.got({ type: 'done', ok: true });
    assert.strictEqual(l.link.result, 'done');
  });

  it('signs the record of a removal by its signer', async () => {
    const l = linked();
    l.got(ADMITTED);
    await l.link.act('remove', 'phone-2');
    assert.deepStrictEqual(await show(l, { type: 'revoke', group: 'g1', signer: 'h1' }), { type: 'signed', on: true, sig: 'SIG' });
    l.got({ type: 'done', ok: true });
  });

  it('refuses all else', async () => {
    const no = { type: 'signed', on: false, sig: '' };
    const l = linked();
    l.got(ADMITTED);
    assert.deepStrictEqual(await show(l, { type: 'freeze', group: 'g1', by: 'watch-1', to: 'phone-2' }), no, 'no action waits');
    await l.link.act('freeze', 'phone-2');
    for (const body of [
      { type: 'freeze', group: 'g2', by: 'watch-1', to: 'phone-2' },
      { type: 'revoke', group: 'g1', by: 'watch-1', to: 'phone-2' },
      { type: 'freeze', group: 'g1', by: 'watch-1', to: 'phone-3' },
      { type: 'freeze', group: 'g1', by: 'watch-9', to: 'phone-2' },
      { type: 'freeze', group: 'g1', signer: 'h9' },
    ]) {
      assert.deepStrictEqual(await show(l, body), no, JSON.stringify(body));
    }
    l.got({ type: 'sign', part: 0, parts: 1, data: Buffer.from('not json').toString('base64') });
    await new Promise((r) => setImmediate(r));
    assert.deepStrictEqual(l.sent.at(-1), no, 'garbage');
    assert.strictEqual(signed.length, 0);
    l.got({ type: 'done', ok: true });
  });

  it('ends an action the phone does not take, or did not do', async () => {
    const l = linked();
    l.got(ADMITTED);
    l.wear.up = false;
    await l.link.act('freeze', 'phone-2');
    assert.strictEqual(l.link.acting, '');
    assert.strictEqual(l.link.result, 'no_answer');
    l.wear.up = true;
    await l.link.act('freeze', 'phone-2');
    l.got({ type: 'done', ok: false, message: 'gone' });
    assert.strictEqual(l.link.result, 'not_done_because gone');
  });

  it('makes its admin key when the root asks and the wearer agrees', async () => {
    const l = linked();
    l.got({ type: 'make_key' });
    assert.strictEqual(l.link.makeKeyAsked, true);
    await l.link.answerMakeKey(true);
    assert.strictEqual(l.link.makeKeyAsked, false);
    await l.link.answerMakeKey(false);
    assert.deepStrictEqual(l.sent, [{ type: 'key', on: true, key: 'KEY' }, { type: 'key', on: false, key: '' }]);
  });

  it('asks the phone to turn sync on and tells when it cannot', async () => {
    const l = linked();
    await l.link.ask('sync', true);
    assert.strictEqual(l.link.asking, true);
    assert.deepStrictEqual(l.sent, [{ type: 'sync', on: true }]);
    l.wear.up = false;
    await l.link.ask('away', false);
    assert.strictEqual(l.link.failed, true);
    assert.strictEqual(l.link.asking, false);
  });
});
