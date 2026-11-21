// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group of 0.6 (docs/apps.md, "Screens"): Scan Kit reads the QR
// code a phone of the group shows in its Add a device, or the person types
// the six digits shown under it and the phone finds that window at home;
// the phone then proves the digits, and nobody is asked.

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { app } from '../model/AppModel';
import { Joiner, WINDOW_QR } from '../model/Pairing06';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';

@Entry
@ComponentV2
struct JoinWindow {
  // The model's joiner, a field so that the monitor sees its state.
  @Local joining: Joiner = app.joiner;
  @Local hint: string = '';
  @Local typed: string = '';
  // The last text dialed, for Try again.
  private last: string = '';

  aboutToDisappear(): void {
    if (app.joiner.state !== 'done') {
      app.joiner.stop();
    }
  }

  @Monitor('joining.state')
  joined(): void {
    if (app.joiner.state === 'done') {
      router.clear();
      router.replaceUrl({ url: 'pages/Main' });
    }
  }

  async dial(text: string): Promise<void> {
    this.hint = '';
    const digits = text.replace(/\s/g, '');
    if (!/^[0-9]{6}$/.test(digits) && !text.trim().startsWith(WINDOW_QR)) {
      this.hint = Errors.shown(new Failure(t('not_a_window_code'), 'joiner: neither six digits nor a text that starts with cbb://pair?'));
      return;
    }
    this.last = text;
    await app.joiner.stop();
    app.joinByWindow(text);
  }

  async scan(): Promise<void> {
    const s = await scanQr(getContext(this) as common.UIAbilityContext);
    if (s.text !== undefined) {
      this.dial(s.text);
    } else if (s.failure !== undefined) {
      this.hint = Errors.shown(s.failure);
    }
  }

  build() {
    Scroll() {
      Column({ space: 16 }) {
        PageTitle({ title: $r('app.string.start_join'), back: () => {
          router.back();
        } })
        if (app.joiner.state === 'done') {
          Text($r('app.string.join_joined')).fontColor($r('app.color.text'))
        }
        if (app.joiner.state === 'dialing') {
          BusyLine({ busy: true, label: $r('app.string.join_looking') })
        }
        if (app.joiner.state === 'idle' || app.joiner.state === 'failed') {
          Text($r('app.string.join_window_hint')).fontColor($r('app.color.text'))
          Button($r('app.string.scan'), { type: ButtonType.Capsule })
            .width('100%')
            .onClick(() => {
              this.scan();
            })
          TextInput({ placeholder: $r('app.string.join_digits'), text: this.typed })
            .fontFamily('monospace')
            .onChange((v: string) => {
              this.typed = v;
            })
            .onSubmit(() => {
              this.dial(this.typed);
            })
          Button($r('app.string.start_join'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(this.typed.trim().length > 0)
            .onClick(() => {
              this.dial(this.typed);
            })
        }
        ErrorText({ text: this.hint })
        ErrorText({ text: app.joiner.error })
        if (app.joiner.state === 'failed') {
          Button($r('app.string.try_again'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(this.last.length > 0)
            .onClick(() => {
              this.dial(this.last);
            })
        }
      }
      .padding(24)
      .alignItems(HorizontalAlign.Start)
      .width('100%')
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.background'))
  }
}
