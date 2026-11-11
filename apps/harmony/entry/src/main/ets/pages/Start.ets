// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Start, the same on every phone (docs/apps.md, "Start"): no group yet.
// This first version makes a new group; joining a computer's group, an
// invitation and restoring from the recovery sheet come next.

import { router } from '@kit.ArkUI';
import cbb from 'libcbb_napi.so';
import { call, read } from '../core/Core';
import { Errors, Failure } from '../core/Errors';
import { ensure, Key } from '../core/Keys';
import { Joined, Membership, sealSecret } from '../core/Membership';
import { OS, phoneName, STORE } from '../core/Phone';

interface SealKey {
  key: string;
}

@Entry
@Component
struct Start {
  @State busy: boolean = false;
  @State error: string = '';

  async makeGroup(): Promise<void> {
    this.busy = true;
    this.error = '';
    const failure = await this.newGroup();
    this.busy = false;
    if (failure !== undefined) {
      this.error = Errors.shown(failure);
      return;
    }
    router.replaceUrl({ url: 'pages/Group' });
  }

  // The admin key stands as the group's root key; the core makes the group
  // and signs with it, each signature after the user's consent.
  async newGroup(): Promise<Failure | undefined> {
    const dir = AppStorage.get<string>('filesDir') as string;
    const secret = sealSecret(dir);
    if (secret instanceof Failure) {
      return secret;
    }
    const seal = call<SealKey>('seal_public', { 'secret': secret } as Record<string, Object>);
    if (seal.ok === undefined) {
      return seal.failure;
    }
    const member = await ensure('member');
    if (member.ok === undefined) {
      return member.failure;
    }
    const root = await ensure('admin');
    if (root.ok === undefined) {
      return root.failure;
    }
    const request: Record<string, Object> = {
      'name': phoneName(),
      'os': OS,
      'store': STORE,
      'public': (member.ok as Key).public,
      'root_public': (root.ok as Key).public,
      'seal': seal.ok.key
    };
    const group = read<Joined>(await cbb.groupNew(JSON.stringify(request)), 'group');
    if (group.ok === undefined) {
      return group.failure;
    }
    const m = new Membership(group.ok);
    m.member.root = true;
    const saved = m.save(dir);
    if (saved !== undefined) {
      return saved;
    }
    Errors.log(`group: made ${m.groupTag()} as its root`);
    return undefined;
  }

  build() {
    Column({ space: 16 }) {
      Text($r('app.string.start_title')).fontSize(34).fontWeight(FontWeight.Bold)
      Text($r('app.string.start_lead')).fontSize(17).opacity(0.7)
      Blank().height(24)
      Button($r('app.string.start_new_group'))
        .width('100%')
        .enabled(!this.busy)
        .onClick(() => {
          this.makeGroup();
        })
      Text($r('app.string.start_new_group_note')).fontSize(14).opacity(0.6)
      if (this.busy) {
        Row({ space: 8 }) {
          LoadingProgress().width(24).height(24)
          Text($r('app.string.busy'))
        }
      }
      if (this.error.length > 0) {
        Text(this.error).fontColor(Color.Red).fontSize(14).copyOption(CopyOptions.LocalDevice)
      }
    }
    .padding(24)
    .alignItems(HorizontalAlign.Start)
    .width('100%')
    .height('100%')
  }
}
