// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's place in its group of 0.6, as the core's join and new group
// answer it, kept in member.json in the app's files, readable by the app
// alone. The member keeps the group's set itself (group.cbor, D-126).

import { fileIo } from '@kit.CoreFileKit';
import { Failure } from './Errors';

const FILE_VERSION: number = 1;
const SAVE_FAILED: string = 'The phone could not save the group.';

// What member.json keeps: the device ID, whether this phone holds the
// group's root, the group's ID in hex and whether its records make this
// phone an admin, as the member's devices say. A file without group06 was
// written by a group from before 0.6, which this version no longer runs.
export interface Joined {
  device: string;
  root?: boolean;
  group06?: string;
  admin06?: boolean;
}

interface Stored {
  v: number;
  member: Joined;
}

// The app's own files of the group.
const APP_FILES: string[] = ['member.json', 'seal.key', 'server-keys.txt'];

// The member's files of the group, as member/src/leave.rs lists them
// (GROUP_FILES): keep the two lists alike.
const GROUP_FILES: string[] = [
  'identity.json', 'seal.json', 'tunnel.json', 'entries.json', 'attest-status.json', 'content', 'networks.json',
  'credentials.json', 'server-keys.json', 'pastes.json', 'actions-log.json', 'mute.json', 'signed.json', 'before-0.6',
  'local.json', 'offered.json', 'keys.json', 'epochs.json', 'statements.json', 'commands.cbor', 'marks.cbor',
  'signed-records.json', 'push.cbor', 'push-previous.cbor', 'server-credentials.cbor', 'period-key', 'server-secret',
  'hub-forwarders.json', 'invite-guest', 'records.json', 'group.cbor'
];

export class Membership {
  member: Joined;

  constructor(member: Joined) {
    this.member = member;
  }

  isRoot(): boolean {
    return this.member.root === true;
  }

  // A group from before 0.6 (D-126): the app shows that a new group is
  // needed, and only Leave, the person's choice, deletes its files.
  isBefore06(): boolean {
    return this.member.group06 === undefined || this.member.group06.length === 0;
  }

  // An admin: the group's root, or a phone the records make an admin.
  isAdmin(): boolean {
    return !this.isBefore06() && (this.isRoot() || this.member.admin06 === true);
  }

  // The first eight bytes of the group ID in hex, as the other apps name
  // the group in the log.
  groupTag(): string {
    return (this.member.group06 ?? '').substring(0, 16);
  }

  // Saves member.json, written whole: the member keeps the set itself.
  save(dir: string): Failure | undefined {
    const member: Joined = {
      device: this.member.device,
      root: this.member.root,
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
      root: this.member.root,
      group06: this.member.group06,
      admin06: this.member.admin06
    };
    return new Membership(j);
  }

  // A group of 0.6 that this phone made or joined, as the device device.
  static of06(device: string, group: string, root: boolean): Membership {
    return new Membership({ device: device, root: root, group06: group });
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

  // Leaves the group on this phone: deletes member.json and every file the
  // member keeps of its group, the list of member/src/leave.rs
  // (GROUP_FILES), with what a group from before 0.6 kept beside them (the
  // key for its sealed messages, its servers' keys).
  static remove(dir: string): Failure | undefined {
    try {
      for (const name of APP_FILES.concat(GROUP_FILES)) {
        const path = `${dir}/${name}`;
        if (!fileIo.accessSync(path)) {
          continue;
        }
        if (fileIo.statSync(path).isDirectory()) {
          fileIo.rmdirSync(path);
        } else {
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
