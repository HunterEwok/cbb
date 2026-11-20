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
  // A group of 0.6 (docs/apps.md, "Screens"): its ID in hex, and whether
  // its records make this phone an admin, as the member's devices say. The
  // member keeps the group's set itself (group.cbor), with no certificates.
  group06?: string;
  admin06?: boolean;
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

  isV06(): boolean {
    return this.member.group06 !== undefined && this.member.group06.length > 0;
  }

  // An admin: through its admin CA, as the group's root, which issues with
  // the root key itself, or as its records say on 0.6.
  isAdmin(): boolean {
    return this.isRoot() || (this.member.admin_ca !== undefined && this.member.admin_ca.length > 0) ||
      (this.isV06() && this.member.admin06 === true);
  }

  // The first eight bytes of the group ID on 0.6, else of SHA-256 over the
  // group CA, in hex, as the other apps name the group in the log.
  groupTag(): string {
    if (this.isV06()) {
      return (this.member.group06 as string).substring(0, 16);
    }
    const md = cryptoFramework.createMd('SHA256');
    md.updateSync({ data: new util.Base64Helper().decodeSync(this.member.group_ca) });
    const sum = md.digestSync().data;
    let hex = '';
    for (let i = 0; i < 8; i++) {
      hex += sum[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  // Saves it: the records first (records.json, which the member reads and
  // keeps up to date once it runs), then member.json, each written whole.
  save(dir: string): Failure | undefined {
    if (this.isV06()) {
      return this.saveIdentity(dir);
    }
    const records = new util.Base64Helper().decodeSync(this.member.records);
    const failure = writeFile(dir, 'records.json', records.buffer.slice(records.byteOffset, records.byteOffset + records.byteLength) as ArrayBuffer);
    return failure ?? this.saveIdentity(dir);
  }

  // Saves member.json alone: the member keeps the records itself once it runs.
  saveIdentity(dir: string): Failure | undefined {
    const member: Joined = {
      device: this.member.device,
      cert: this.member.cert,
      issuer: this.member.issuer,
      admin_ca: this.member.admin_ca,
      group_ca: this.member.group_ca,
      roots: this.member.roots,
      records: '',
      root: this.member.root,
      claim: this.member.claim,
      group06: this.member.group06,
      admin06: this.member.admin06
    };
    const stored: Stored = { v: FILE_VERSION, member: member };
    return writeFile(dir, 'member.json', JSON.stringify(stored));
  }

  // A copy, for a change that is kept only once it is saved.
  copy(): Membership {
    const j: Joined = {
      device: this.member.device,
      cert: this.member.cert,
      issuer: this.member.issuer,
      admin_ca: this.member.admin_ca,
      group_ca: this.member.group_ca,
      roots: this.member.roots.slice(),
      records: this.member.records,
      root: this.member.root,
      claim: this.member.claim,
      group06: this.member.group06,
      admin06: this.member.admin06
    };
    return new Membership(j);
  }

  // A group of 0.6 that this phone made or joined, as the device device.
  static of06(device: string, group: string, root: boolean): Membership {
    return new Membership({ device: device, cert: '', group_ca: '', roots: [], records: '', root: root, group06: group });
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

  // Leaves the group on this phone: deletes member.json, the records and the
  // set of 0.6.
  // The key for sealed messages stays, as the member keeps it for the run.
  static remove(dir: string): Failure | undefined {
    try {
      for (const name of ['member.json', 'records.json', 'group.cbor', 'local.json']) {
        const path = `${dir}/${name}`;
        if (fileIo.accessSync(path)) {
          fileIo.unlinkSync(path);
        }
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
