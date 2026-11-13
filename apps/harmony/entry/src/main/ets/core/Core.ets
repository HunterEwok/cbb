// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Rust core's one entry point (docs/core-api.md) through libcbb_napi.so:
// requests and answers are JSON, {"abi","ok"} or {"abi","error"}.

import cbb from 'libcbb_napi.so';
import { Errors, Failure } from './Errors';

// The request and answer shapes this app speaks (core/src/api.rs, ABI).
export const ABI: number = 1;

const BROKEN: string = 'This build of CBB is broken.';

export interface CoreError {
  code: number;
  name: string;
  message: string;
  details?: string;
}

interface Answer {
  abi?: number;
  ok?: Object;
  error?: CoreError;
}

// What a call answers: ok, or the failure to show.
export class Result<T> {
  ok?: T;
  failure?: Failure;

  static of<T>(ok: T): Result<T> {
    const r = new Result<T>();
    r.ok = ok;
    return r;
  }

  static failed<T>(f: Failure): Result<T> {
    const r = new Result<T>();
    r.failure = f;
    return r;
  }
}

// Reads an answer of the core, or of one of its handles, for what.
export function read<T>(text: string, what: string): Result<T> {
  if (text.length === 0) {
    return Result.failed<T>(new Failure(BROKEN, `${what}: no answer`));
  }
  let a: Answer;
  try {
    a = JSON.parse(text) as Answer;
  } catch (e) {
    return Result.failed<T>(new Failure(BROKEN, `${what}: the answer does not read: ${String(e)}`));
  }
  if (a.error !== undefined) {
    const e = a.error;
    let details = `${what}: ${e.name} (code ${e.code})`;
    if (e.details !== undefined && e.details.length > 0) {
      details += `\n${e.details}`;
    }
    return Result.failed<T>(new Failure(e.message.length > 0 ? e.message : BROKEN, details));
  }
  if (a.ok === undefined) {
    return Result.failed<T>(new Failure(BROKEN, `${what}: the answer has neither ok nor error`));
  }
  return Result.of<T>(a.ok as T);
}

// Asks the core: {"abi","op","args"}; the ABI is checked first, as the
// other apps do.
export function call<T>(op: string, args?: Object): Result<T> {
  const got = cbb.abi();
  if (got !== ABI) {
    return Result.failed<T>(new Failure(BROKEN, `core: the linked core speaks ABI ${got}, not ${ABI}`));
  }
  const request: Record<string, Object> = { 'abi': ABI, 'op': op };
  if (args !== undefined) {
    request['args'] = args;
  }
  return read<T>(cbb.call(JSON.stringify(request)), `core: ${op}`);
}

interface Version {
  core: string;
  abi: number;
  source?: string;
}

// "core 0.6.0, abi 1, source <commit>", for the log and the settings.
export function versionLine(): string {
  const v = call<Version>('version');
  if (v.ok === undefined) {
    return Errors.shown(v.failure as Failure);
  }
  const source = v.ok.source !== undefined && v.ok.source.length > 0 ? v.ok.source : 'unknown';
  return `core ${v.ok.core}, abi ${v.ok.abi}, source ${source}`;
}
