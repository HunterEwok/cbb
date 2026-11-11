// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's place in its group, as the core's join and new group answer
// it, kept in member.json in the app's files, readable by the app alone;
// and the secret of its key for sealed messages, in seal.key.

import { fileIo } from '@kit.CoreFileKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';
import { Failure } from './Errors';

const FILE_VERSION: number = 1;
const SAVE_FAILED: string = 'The phone could not save the group.';

// A join's fields (ffi: join.rs, joined; new_group), base64 as the core gives them.
export interface Joined {
  device: string;
  cert: string;
  issuer?: string;
  admin_ca?: string;
  group_ca: string;
  roots: string[];
  records: string;
  root?: boolean;
  claim?: string;
}

interface Stored {
  v: number;
  member: Joined;
}

export class Membership {
  member: Joined;

  constructor(member: Joined) {
    this.member = member;
  }

  isRoot(): boolean {
    return this.member.root === true;
  }

  // The first eight bytes of SHA-256 over the group CA, in hex, as the other
  // apps name the group in the log.
  groupTag(): string {
    const md = cryptoFramework.createMd('SHA256');
    md.updateSync({ data: new util.Base64Helper().decodeSync(this.member.group_ca) });
    const sum = md.digestSync().data;
    let hex = '';
    for (let i = 0; i < 8; i++) {
      hex += sum[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  save(dir: string): Failure | undefined {
    const stored: Stored = { v: FILE_VERSION, member: this.member };
    return writeFile(dir, 'member.json', JSON.stringify(stored));
  }

  static load(dir: string): Membership | Failure | undefined {
    const path = `${dir}/member.json`;
    if (!fileIo.accessSync(path)) {
      return undefined;
    }
    try {
      const stored = JSON.parse(fileIo.readTextSync(path)) as Stored;
      if (stored.v !== FILE_VERSION || stored.member === undefined || stored.member.device === undefined) {
        return new Failure('The phone could not read its group.', `membership: member.json is version ${stored.v}`);
      }
      return new Membership(stored.member);
    } catch (e) {
      return new Failure('The phone could not read its group.', `membership: member.json: ${String(e)}`);
    }
  }

  static remove(dir: string): Failure | undefined {
    try {
      const path = `${dir}/member.json`;
      if (fileIo.accessSync(path)) {
        fileIo.unlinkSync(path);
      }
      return undefined;
    } catch (e) {
      return new Failure('The phone could not leave the group.', `membership: ${String(e)}`);
    }
  }
}

// Writes the file whole or not at all: to a temporary name, then renamed.
function writeFile(dir: string, name: string, text: string | ArrayBuffer): Failure | undefined {
  const tmp = `${dir}/${name}.tmp`;
  try {
    const f = fileIo.openSync(tmp, fileIo.OpenMode.CREATE | fileIo.OpenMode.TRUNC | fileIo.OpenMode.WRITE_ONLY);
    fileIo.writeSync(f.fd, text);
    fileIo.fsyncSync(f.fd);
    fileIo.closeSync(f);
    fileIo.renameSync(tmp, `${dir}/${name}`);
    return undefined;
  } catch (e) {
    return new Failure(SAVE_FAILED, `membership: ${name}: ${String(e)}`);
  }
}

// The 32-byte secret of the phone's key for sealed messages, made the first
// time, base64; or the failure.
export function sealSecret(dir: string): string | Failure {
  const path = `${dir}/seal.key`;
  const b64 = new util.Base64Helper();
  try {
    if (fileIo.accessSync(path)) {
      const f = fileIo.openSync(path, fileIo.OpenMode.READ_ONLY);
      const buf = new ArrayBuffer(64);
      const n = fileIo.readSync(f.fd, buf);
      fileIo.closeSync(f);
      if (n === 32) {
        return b64.encodeToStringSync(new Uint8Array(buf, 0, 32));
      }
    }
    const secret = cryptoFramework.createRandom().generateRandomSync(32).data;
    const failure = writeFile(dir, 'seal.key', secret.buffer.slice(secret.byteOffset, secret.byteOffset + 32) as ArrayBuffer);
    if (failure !== undefined) {
      return failure;
    }
    return b64.encodeToStringSync(secret);
  } catch (e) {
    return new Failure('The phone could not make its keys.', `membership: seal.key: ${String(e)}`);
  }
}
