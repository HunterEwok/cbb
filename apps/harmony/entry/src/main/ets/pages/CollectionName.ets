// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Naming a new collection (of one device, or empty) or renaming one. A name
// has at most 64 bytes (docs/apps.md); the core refuses a longer one.

import { router } from '@kit.ArkUI';
import { app } from '../model/AppModel';
import { ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct CollectionName {
  @Local collection: string = '';
  @Local device: string = '';
  @Local name: string = '';

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, Object> | undefined;
    if (params !== undefined) {
      this.collection = params['collection'] !== undefined ? String(params['collection']) : '';
      this.device = params['device'] !== undefined ? String(params['device']) : '';
      this.name = params['name'] !== undefined ? String(params['name']) : '';
    }
  }

  save(): void {
    const name = this.name.trim();
    if (name.length === 0) {
      return;
    }
    const op: Record<string, Object> = this.collection.length === 0 ?
      { 'op': 'new', 'name': name, 'devices': this.device.length > 0 ? [this.device] : ([] as string[]) } :
      { 'op': 'rename', 'collection': this.collection, 'name': name };
    if (app.arrange(op)) {
      router.back();
    }
  }

  build() {
    Column({ space: 16 }) {
      PageTitle({ title: this.collection.length === 0 ? $r('app.string.collection_new') : $r('app.string.arrange_rename'),
        back: () => {
          router.back();
        } })
      TextInput({ text: this.name, placeholder: $r('app.string.collection_name_hint') })
        .maxLength(64)
        .defaultFocus(true)
        .onChange((v: string) => {
          this.name = v;
        })
        .onSubmit(() => {
          this.save();
        })
      Button($r('app.string.done'), { type: ButtonType.Capsule })
        .width('100%')
        .enabled(this.name.trim().length > 0)
        .onClick(() => {
          this.save();
        })
      ErrorText({ text: app.error })
    }
    .padding(24)
    .alignItems(HorizontalAlign.Start)
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
