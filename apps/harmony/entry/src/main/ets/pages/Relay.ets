// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group's blind relay, as the iPhone's and Android's (docs/apps.md,
// "Away from home"): where the devices meet when the group has no hub, a
// computer, a router or a board; the root sets it once the user read what
// a relay learns, and the others see where it stands.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, EMPHASIZED_BUTTON, ErrorText, NORMAL_BUTTON, PageTitle } from '../components/Common';

// A server's key: the pin of its public key, 44 characters of base64.
const KEY_LENGTH: number = 44;

@Entry
@ComponentV2
struct Relay {
  @Local relay: string = '';
  @Local relayKey: string = '';
  @Local busy: boolean = false;
  @Local error: string = '';

  aboutToAppear(): void {
    // The relay is the group's, as the member meets it.
    this.relay = app.member.relayAt;
    this.relayKey = '';
    app.show('');
  }

  // An address with its port and a key, or both empty.
  pair(address: string, key: string): boolean {
    const a = address.trim();
    const k = key.trim();
    if (a.length === 0 && k.length === 0) {
      return true;
    }
    return a.includes(':') && k.length === KEY_LENGTH;
  }

  relayLine(): string {
    if (app.member.relayAt.length === 0) {
      return t('relay_off');
    }
    if (!app.member.running || app.member.paused) {
      return t('relay_paused');
    }
    if (!app.member.relayConnected) {
      return t('relay_connecting');
    }
    return app.member.relayOnline === 0 ? t('relay_alone') : t('relay_with', app.member.relayOnline);
  }

  meet(): void {
    if (!this.pair(this.relay, this.relayKey)) {
      this.error = t('relay_bad');
      return;
    }
    this.error = '';
    if (this.relay.trim().length === 0) {
      this.leave();
      return;
    }
    this.getUIContext().showAlertDialog({
      title: t('relay_ask_title'),
      message: t('relay_ask_body'),
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('relay_meet'), action: async () => {
        this.busy = true;
        await app.setRelay(this.relay.trim(), this.relayKey.trim());
        this.busy = false;
      } }
    });
  }

  async leave(): Promise<void> {
    this.busy = true;
    if (await app.setRelay('', '')) {
      this.relay = '';
      this.relayKey = '';
    }
    this.busy = false;
  }

  @Builder
  section(title: string) {
    Text(title).fontSize(15).fontWeight(FontWeight.Medium).fontColor($r('app.color.accent')).margin({ top: 8 })
  }

  @Builder
  note(text: string) {
    Text(text).fontSize(12).fontColor($r('app.color.secondary'))
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: $r('app.string.relay_title'), back: () => {
          router.back();
        } })

        // The root's key renews the group's server credentials when the app
        // opens; until it does, the relay and the hubs' forwarders take nobody.
        if (app.member.periodOverdue) {
          ErrorText({ text: t('period_overdue') })
        }
        // The relay is the group's, which only the root sets.
        if (!app.isRoot()) {
          this.note(t('relay_by_root'))
          Text(this.relayLine()).fontSize(13).fontColor($r('app.color.secondary'))
          ErrorText({ text: app.member.relayError })
        } else {
          this.note(t('relay_body'))
          TextInput({ placeholder: $r('app.string.relay_address'), text: this.relay })
            .onChange((v: string) => {
              this.relay = v;
            })
          TextInput({ placeholder: $r('app.string.relay_key'), text: this.relayKey })
            .maxLength(KEY_LENGTH)
            .onChange((v: string) => {
              this.relayKey = v;
            })
          Text(this.relayLine()).fontSize(13).fontColor($r('app.color.secondary'))
          ErrorText({ text: app.member.relayError })
          Row({ space: 8 }) {
            Button($r('app.string.relay_meet'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.EMPHASIZED }).attributeModifier(EMPHASIZED_BUTTON)
              .layoutWeight(1)
              .enabled(!this.busy && !app.busy && app.member.running)
              .onClick(() => {
                this.meet();
              })
            if (app.member.relayAt.length > 0) {
              Button($r('app.string.relay_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL }).attributeModifier(NORMAL_BUTTON)
                .layoutWeight(1)
                .enabled(!this.busy && !app.busy)
                .onClick(() => {
                  this.leave();
                })
            }
          }
          .width('100%')
        }

        BusyLine({ busy: this.busy || app.busy })
        ErrorText({ text: app.error })
        ErrorText({ text: this.error })
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
