// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Previewer's stand-in for libcbb_napi.so (mock-config.json5): it speaks
// the core's ABI and answers every request with an error, so the pages
// show as on a phone with no key and no group, and the error details say
// why. Never part of a build for a phone.

const ABI: number = 1;
const NO_CORE: string = '{"abi":1,"error":{"code":1,"name":"previewer","message":"The Previewer has no core.",' +
  '"details":"previewer: libcbb_napi.so is a stand-in"}}';

interface Made {
  handle: Object | null;
  answer: string;
}

function made(): Promise<Made> {
  return Promise.resolve<Made>({ handle: null, answer: NO_CORE });
}

function answer(): Promise<string> {
  return Promise.resolve<string>(NO_CORE);
}

function none(): Promise<void> {
  return Promise.resolve();
}

const mock: Record<string, Object> = {
  'abi': (): number => ABI,
  'call': (): string => NO_CORE,
  'setAuth': (): void => {},
  'keyEnsure': answer,
  'keyForget': answer,
  'groupNew': answer,
  'setCard': (): void => {},
  'setWatch': (): void => {},
  'piv': answer,
  'qrRead': (): string => NO_CORE,
  'memberStart': made,
  'memberCall': answer,
  'memberManage': answer,
  'memberManageWatch': answer,
  'memberStop': none,
  'inviteNew': made,
  'inviteNext': answer,
  'inviteAnswer': (): void => {},
  'inviteFree': none,
  'windowNew': made,
  'windowNext': answer,
  'windowFree': none,
  'joinerNew': made,
  'joinerNext': answer,
  'joinerFree': none,
};

export default mock;
