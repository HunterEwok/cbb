// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// One send from the Share menu (docs/apps.md, "HarmonyOS"), as the iPhone's
// share extension does it: the phone's member in the core, in a folder of
// its own beside the app's (whose member may run), finds the group's
// computers on the home network and hands them the text, or the images or
// files, once one is connected, then stops. Nothing of it stays.

import cbb, { Handle } from 'libcbb_napi.so';
import { fileIo } from '@kit.CoreFileKit';
import { read } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure } from '../core/Keys';
import { Membership, sealSecret } from '../core/Membership';
import { OS, osVersion, STORE } from '../core/Phone';
import { t } from '../core/Text';
import { Shared } from '../common/Share';
import { IMAGE_TYPES, MAX_SEND_BYTES } from './Member';

// How long it waits for a computer, and for the computers to fetch files.
const WAIT_MS: number = 8000;
const FETCH_MS: number = 60000;

interface Started {
  device?: string;
}

interface Peers {
  peers?: Object[];
}

interface CopyMade {
  copy?: CopyId;
}

interface CopyId {
  id?: string;
}

interface Served {
  served?: number;
  size?: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

async function call<T>(h: Handle, op: string, args: Object): Promise<T | Failure> {
  const r = read<T>(await cbb.memberCall(h, JSON.stringify({ 'op': op, 'args': args } as Record<string, Object>)),
    `share: ${op}`);
  return r.ok !== undefined ? r.ok : r.failure as Failure;
}

// The parts of a media copy of files, as the app's member makes them; a
// failure when none is readable or they are too large together.
function partsOf(s: Shared): Record<string, Object>[] | Failure {
  const parts: Record<string, Object>[] = [];
  let total = 0;
  for (let i = 0; i < s.files.length; i++) {
    try {
      total += fileIo.statSync(s.files[i]).size;
    } catch (e) {
      continue;
    }
    const name = s.files[i].substring(s.files[i].lastIndexOf('/') + 1);
    if (s.files.length === 1 && IMAGE_TYPES.includes(s.types[i])) {
      parts.push({ 'type': s.types[i], 'file': s.files[i] } as Record<string, Object>);
    } else {
      parts.push({ 'path': name, 'file': s.files[i] } as Record<string, Object>);
    }
  }
  if (parts.length === 0) {
    return new Failure(t('error_share_nothing'), 'share: no readable file');
  }
  if (total > MAX_SEND_BYTES) {
    return new Failure(t('error_share_too_large'), `share: ${total} bytes`);
  }
  return parts;
}

function removeDir(dir: string): void {
  try {
    if (fileIo.accessSync(dir)) {
      fileIo.rmdirSync(dir);
    }
  } catch (e) {
    Errors.log(`share: removing ${dir}: ${String(e)}`);
  }
}

// Sends what was shared from the app's folder filesDir as the phone named
// name; undefined once a computer took it, else the failure to show.
export async function sendOnce(filesDir: string, s: Shared, name: string): Promise<Failure | undefined> {
  const m = Membership.load(filesDir);
  if (m === undefined) {
    return new Failure(t('share_no_group'), 'share: no member.json');
  }
  if (m instanceof Failure) {
    return m;
  }
  let parts: Record<string, Object>[] = [];
  if (s.files.length > 0) {
    const p = partsOf(s);
    if (p instanceof Failure) {
      return p;
    }
    parts = p;
  } else if (s.text.trim().length === 0) {
    return new Failure(t('error_share_nothing'), 'share: no text');
  }
  const secret = sealSecret(filesDir);
  if (secret instanceof Failure) {
    return secret;
  }
  const key = await ensure('member');
  if (key.ok === undefined) {
    return key.failure as Failure;
  }
  // A folder of its own with the group's records: the app's member keeps
  // the other, and may run.
  const dir = `${filesDir}/share-member`;
  removeDir(dir);
  try {
    fileIo.mkdirSync(dir, true);
    fileIo.copyFileSync(`${filesDir}/records.json`, `${dir}/records.json`);
  } catch (e) {
    return Errors.unexpected('share: the folder', e as Object);
  }
  const j = m.member;
  const request: Record<string, Object> = {
    'dir': dir, 'name': name, 'os': OS, 'os_version': osVersion(), 'key_store': STORE,
    'version': AppStorage.get<string>('version') ?? '', 'device': j.device, 'public': key.ok.public,
    'seal': secret, 'cert': j.cert, 'group_ca': j.group_ca, 'roots': j.roots
  };
  if (j.issuer !== undefined && j.issuer.length > 0) {
    request['issuer'] = j.issuer;
  }
  const made = await cbb.memberStart(JSON.stringify(request), (e: string) => {});
  const answer = read<Started>(made.answer, 'share: member');
  const h = made.handle;
  if (h === null) {
    removeDir(dir);
    return answer.failure ?? new Failure(t('share_failed'), 'share: no member');
  }
  try {
    return await sendWith(h, s, parts);
  } finally {
    await cbb.memberStop(h);
    removeDir(dir);
  }
}

async function sendWith(h: Handle, s: Shared, parts: Record<string, Object>[]): Promise<Failure | undefined> {
  const end = Date.now() + WAIT_MS;
  let online = false;
  while (!online && Date.now() < end) {
    const p = await call<Peers>(h, 'peers', {} as Record<string, Object>);
    online = !(p instanceof Failure) && (p.peers ?? []).length > 0;
    if (!online) {
      await sleep(300);
    }
  }
  if (!online) {
    return new Failure(t('share_no_computers'), 'share: no computer connected');
  }
  if (parts.length === 0) {
    const sent = await call<Object>(h, 'copy', { 'text': s.text } as Record<string, Object>);
    if (sent instanceof Failure) {
      return sent;
    }
    // The copy goes out on the connections; give them a moment.
    await sleep(1000);
    return undefined;
  }
  const made = await call<CopyMade>(h, 'copy_media', { 'parts': parts } as Record<string, Object>);
  if (made instanceof Failure) {
    return made;
  }
  const id = made.copy?.id ?? '';
  // The computers fetch the copy's sealed blob from this phone.
  const until = Date.now() + FETCH_MS;
  while (Date.now() < until) {
    const sv = await call<Served>(h, 'served', { 'id': id } as Record<string, Object>);
    if (sv instanceof Failure || (sv.size ?? 0) === 0 || (sv.served ?? 0) >= (sv.size ?? 0)) {
      await sleep(500);
      return undefined;
    }
    await sleep(200);
  }
  return new Failure(t('share_not_fetched'), 'share: not fetched in time');
}
