// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// libcbb_napi.so (src/main/cpp/napi_init.cpp): the Rust core's C functions
// (ffi/include/cbb_core.h, docs/core-api.md) and the keys in HUKS. Requests
// and answers are the core's JSON; every function that may block or sign
// answers a Promise and runs off the main thread.

// A member, a joiner, an admission or an invitation, given back to free it.
export interface Handle {}

// A handle and the core's answer: handle is null when the core refused, and
// answer then holds its error.
export interface Made {
  handle: Handle | null;
  answer: string;
}

// Which key signs: the member key (no prompt) or the admin key (the user's
// face, fingerprint or PIN before each signature).
export type Which = 'member' | 'admin';

export const abi: () => number;
export const call: (request: string) => string;

// The app's function that turns HUKS's challenge into the auth token of
// User Authentication Kit, rejecting when the user declines.
export const setAuth: (auth: (challenge: ArrayBuffer) => Promise<ArrayBuffer>) => void;
export const keyEnsure: (which: Which) => Promise<string>;
export const keyForget: () => Promise<string>;

export const groupNew: (request: string) => Promise<string>;
export const restore: (request: string) => Promise<string>;
// The YubiKey on the phone's NFC: the app's function sends an APDU to the
// IsoDep tag and answers the card's answer, its status word last; piv runs a
// step of cbb_piv on it.
export const setCard: (transmit: (apdu: ArrayBuffer) => Promise<ArrayBuffer>) => void;
// The watch that memberManageWatch has sign: it is shown the body and
// answers its signature, DER.
export const setWatch: (sign: (body: ArrayBuffer) => Promise<ArrayBuffer>) => void;
export const piv: (request: string) => Promise<string>;
export const qrRead: (gray: ArrayBuffer, width: number, height: number, stride: number) => string;

export const memberStart: (request: string, onEvent: (event: string) => void) => Promise<Made>;
export const memberCall: (member: Handle, request: string) => Promise<string>;
export const memberManage: (member: Handle, request: string, which: Which) => Promise<string>;
export const memberManageCard: (member: Handle, request: string) => Promise<string>;
export const memberManageWatch: (member: Handle, request: string) => Promise<string>;
export const memberServers: (member: Handle, index: string) => Promise<string>;
export const memberStop: (member: Handle) => Promise<void>;

export const joinNew: (request: string) => Promise<Made>;
export const joinAccept: (join: Handle) => Promise<string>;
export const joinFeed: (join: Handle, data: ArrayBuffer, nowMs: number) => Promise<string>;
export const joinFinish: (join: Handle, saved: boolean) => Promise<string>;
export const joinAnnounce: (join: Handle, port: number) => boolean;
export const joinAnswered: (join: Handle) => boolean;
export const joinFree: (join: Handle) => Promise<void>;

export const admitNew: (member: Handle, request: string, which: Which) => Promise<Made>;
export const admitDial: (admit: Handle) => Promise<string>;
export const admitFeed: (admit: Handle, data: ArrayBuffer, nowMs: number) => Promise<string>;
export const admitFree: (admit: Handle) => Promise<void>;

export const inviteNew: (member: Handle, request: string, which: Which) => Promise<Made>;
export const inviteNext: (invite: Handle, version: number, timeoutMs: number) => Promise<string>;
export const inviteAnswer: (invite: Handle, yes: boolean) => void;
export const inviteFree: (invite: Handle) => Promise<void>;

export const tunnel: (request: string) => Promise<string>;
export const tunnelRegister: (request: string) => Promise<string>;
export const tunnelRelay: (request: string, onEvent: (event: string) => void) => Promise<string>;
