// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What another app shared to CBB (the system's share sheet, Share Kit), or
// the user picked to paste on another device: a text, or images and files
// copied into the app's cache, where the core reads them to send.

import { Want } from '@kit.AbilityKit';
import { fileIo } from '@kit.CoreFileKit';
import { systemShare } from '@kit.ShareKit';
import { uniformTypeDescriptor } from '@kit.ArkData';
import { Errors } from '../core/Errors';

export class Shared {
  text: string = '';
  files: string[] = [];
  types: string[] = [];
}

function mimeOf(name: string): string {
  const ext = name.substring(name.lastIndexOf('.') + 1).toLowerCase();
  if (ext === 'png') {
    return 'image/png';
  }
  if (ext === 'jpg' || ext === 'jpeg') {
    return 'image/jpeg';
  }
  if (ext === 'gif') {
    return 'image/gif';
  }
  return 'application/octet-stream';
}

// Copies the files at uris (shared, or picked with the system's picker)
// into the new folder dir, where the core reads them; what it cannot read
// goes to the log.
export function copyIn(uris: string[], dir: string, out: Shared): void {
  if (uris.length > 0) {
    fileIo.mkdirSync(dir, true);
  }
  for (const uri of uris) {
    const name = decodeURIComponent(uri.substring(uri.lastIndexOf('/') + 1)) || `file-${out.files.length + 1}`;
    const to = `${dir}/${name}`;
    try {
      const from = fileIo.openSync(uri, fileIo.OpenMode.READ_ONLY);
      fileIo.copyFileSync(from.fd, to);
      fileIo.closeSync(from);
      out.files.push(to);
      out.types.push(mimeOf(name));
    } catch (e) {
      Errors.log(`share: could not read ${name}: ${String(e)}`);
    }
  }
}

// Reads the shared data of want, or undefined when it shares nothing.
export async function sharedOf(want: Want, cacheDir: string): Promise<Shared | undefined> {
  if (want.action !== 'ohos.want.action.sendData') {
    return undefined;
  }
  const out = new Shared();
  const data = await systemShare.getSharedData(want);
  const dir = `${cacheDir}/shared-${Date.now()}`;
  const uris: string[] = [];
  for (const r of data.getRecords()) {
    if (r.content !== undefined && r.content.length > 0 &&
      (r.utd === uniformTypeDescriptor.UniformDataType.PLAIN_TEXT || r.utd === uniformTypeDescriptor.UniformDataType.TEXT ||
        r.utd === uniformTypeDescriptor.UniformDataType.HYPERLINK)) {
      out.text = out.text.length > 0 ? `${out.text}\n${r.content}` : r.content;
      continue;
    }
    if (r.uri !== undefined && r.uri.length > 0) {
      uris.push(r.uri);
    }
  }
  copyIn(uris, dir, out);
  return out;
}
