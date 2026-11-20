// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group of 0.6 (docs/apps.md, "Screens"): the phone looks for the
// one pairing window a phone of the group announces at home (its Add a
// device), or Scan Kit reads the window's QR code, and the code both screens
// show waits for the person's "they match".

import { common } from '@kit.AbilityKit';
import { router } from '@kit.ArkUI';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';
import { scanQr } from '../common/Scan';
import { app } from '../model/AppModel';
import { Joiner, WINDOW_QR } from '../model/Pairing06';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { CodeQuestion } from '../components/CodeQuestion';

@Entry
@ComponentV2
struct JoinWindow {
  // The model's joiner, a field so that the monitor sees its state.
  @Local joining: Joiner = app.joiner;
  @Local hint: string = '';

  aboutToAppear(): void {
    app.joinByWindow('');
  }

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
    if (text.length > 0 && !text.trim().startsWith(WINDOW_QR)) {
      this.hint = Errors.shown(new Failure(t('not_a_window_code'), 'joiner: the text does not start with cbb://pair?'));
      return;
    }
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
        if (app.joiner.state === 'joining') {
          CodeQuestion({
            who: t('join_asks', app.joiner.memberName),
            code: app.joiner.code,
            answered: (yes: boolean) => {
              app.joiner.answer(yes);
            }
          })
        }
        if (app.joiner.state === 'done') {
          Text($r('app.string.join_joined')).fontColor($r('app.color.text'))
        }
        if (app.joiner.state === 'dialing' || app.joiner.state === 'idle') {
          BusyLine({ busy: true, label: $r('app.string.join_looking') })
        }
        if (app.joiner.state === 'dialing' || app.joiner.state === 'idle' || app.joiner.state === 'failed') {
          Text($r('app.string.join_window_hint')).fontColor($r('app.color.text'))
          Button($r('app.string.scan'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .onClick(() => {
              this.scan();
            })
        }
        ErrorText({ text: this.hint })
        ErrorText({ text: app.joiner.error })
        if (app.joiner.state === 'failed') {
          Button($r('app.string.try_again'), { type: ButtonType.Capsule }).width('100%').onClick(() => {
            this.dial('');
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
