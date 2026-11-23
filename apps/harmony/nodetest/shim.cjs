// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What stands in for the phone when the app's ArkTS runs under Node, as
// build.cjs built it into CBB_TEST_OUT (run.sh): Hypium's describe, it and
// expect; ArkUI's decorators; the kits, as objects that do nothing, except
// @kit.ArkTS's util, which Node's own Buffer and TextEncoder play; and
// libcbb_napi.so's abi and call, which go to the real core through
// core-call (CBB_CORE_CALL). Anything else of the native module throws.
'use strict';
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const Module = require('node:module');
const test = require('node:test');

globalThis.Trace = () => {};
globalThis.ObservedV2 = (c) => c;

function nothing() {
  const p = new Proxy(function () {}, {
    get: (_, k) => (k === 'then' ? undefined : k === Symbol.toPrimitive ? () => '' : p),
    apply: () => p,
    construct: () => p,
  });
  return p;
}

const util = {
  Base64Helper: class {
    encodeToStringSync(data) { return Buffer.from(data).toString('base64'); }
    decodeSync(text) { return new Uint8Array(Buffer.from(text, 'base64')); }
  },
  TextEncoder: class { encodeInto(s) { return new TextEncoder().encode(s); } },
  TextDecoder: { create: () => ({ decodeToString: (d) => new TextDecoder().decode(d) }) },
};

const core = process.env.CBB_CORE_CALL;
const napi = new Proxy({
  abi: () => Number(execFileSync(core, ['abi'], { encoding: 'utf8' })),
  call: (request) => execFileSync(core, { input: request, encoding: 'utf8' }),
}, {
  get: (t, k) => {
    if (k in t) return t[k];
    if (k === '__esModule' || k === 'then') return undefined;
    if (k === 'default') return napi;
    return () => { throw new Error(`libcbb_napi.so's ${String(k)} runs only on a phone`); };
  },
});

const hypium = {
  describe: (name, fn) => test.describe(name, fn),
  it: (name, _level, fn) => test.it(name, fn),
  expect: (got) => ({
    assertEqual: (want) => assert.strictEqual(got, want),
    assertTrue: () => assert.strictEqual(got, true),
    assertFalse: () => assert.strictEqual(got, false),
    assertUndefined: () => assert.strictEqual(got, undefined),
  }),
};

const load = Module._load;
Module._load = function (request, ...rest) {
  if (request === '@ohos/hypium') return hypium;
  if (request === 'BuildProfile') return { __esModule: true, default: { DEBUG: true } };
  if (request === 'libcbb_napi.so') return napi;
  if (request === '@kit.ArkTS') return { util };
  if (request.startsWith('@kit.') || request.startsWith('@ohos.')) return new Proxy({}, { get: (_, k) => (k === '__esModule' ? false : nothing()) });
  return load.call(this, request, ...rest);
};

module.exports = { out: process.env.CBB_TEST_OUT };
