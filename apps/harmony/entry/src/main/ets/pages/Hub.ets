// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Sync away from home without a computer, as the iPhone's and Android's
// (docs/apps.md, "Away from home"): this phone as the group's hub, reached
// from afar through the project's forwarder or the user's own, its tunnel
// hidden for strict networks; and, for a group without a hub, the devices
// meeting at a blind relay, once the user read what a relay learns.

import { router } from '@kit.ArkUI';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';

// A server's key: the pin of its public key, 44 characters of base64.
const KEY_LENGTH: number = 44;

@Entry
@ComponentV2
struct Hub {
  @Local forwarder: string = '';
  @Local forwarderKey: string = '';
  @Local strictVpn: boolean = false;
  @Local strictWeb: boolean = false;
  @Local relay: string = '';
  @Local relayKey: string = '';
  @Local busy: boolean = false;
  @Local error: string = '';

  aboutToAppear(): void {
    this.forwarder = app.hubForwarder();
    this.forwarderKey = app.hubKey();
    const disguise = app.hubDisguise();
    this.strictWeb = disguise === 'vless';
    this.strictVpn = disguise !== 'plain';
    this.relay = app.relayAddress();
    this.relayKey = app.relayKey();
    app.show('');
  }

  disguise(): string {
    return this.strictWeb ? 'vless' : this.strictVpn ? 'obfuscate' : 'plain';
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

  hubLine(): string {
    switch (app.member.hubStatus) {
      case 'home':
        return t('hub_home_only');
      case 'registering':
        return t('hub_registering');
      case 'registered':
        return t('hub_registered');
      case 'failed':
        return t('hub_failed');
      case 'off':
        return t('hub_off');
      default:
        return t('hub_on_home');
    }
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

  async hub(on: boolean, anyway: boolean): Promise<void> {
    if (on && !this.pair(this.forwarder, this.forwarderKey)) {
      this.error = t('hub_bad_forwarder');
      return;
    }
    this.error = '';
    this.busy = true;
    await app.setHub(on, this.forwarder.trim(), this.forwarderKey.trim(), this.disguise(), anyway);
    this.busy = false;
  }

  // Stopping the group's only hub leaves the devices away from home
  // without one: the core refuses, and the user decides.
  async hubOff(): Promise<void> {
    this.busy = true;
    const failure = await app.setHub(false, '', '', '', false);
    this.busy = false;
    if (!app.onlyHub(failure)) {
      return;
    }
    this.getUIContext().showAlertDialog({
      message: t('hub_stop_only'),
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: t('hub_stop'), fontColor: $r('app.color.error'), action: () => {
        this.hub(false, true);
      } }
    });
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

  @Builder
  switchRow(label: string, on: boolean, change: (on: boolean) => void) {
    Row() {
      Text(label).fontColor($r('app.color.text')).layoutWeight(1)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor($r('app.color.accent'))
        .enabled(!this.busy && !app.busy)
        .onChange(change)
    }
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: $r('app.string.hub_title'), back: () => {
          router.back();
        } })

        if (app.isAdmin()) {
          this.note(t('hub_body'))
          this.switchRow(t('hub_switch'), app.member.hubOn, (on: boolean) => {
            if (on) {
              this.hub(true, false);
            } else {
              this.hubOff();
            }
          })
          Text(this.hubLine()).fontSize(13).fontColor($r('app.color.secondary'))
          ErrorText({ text: app.member.hubError })

          this.section(t('hub_forwarder'))
          this.note(t('hub_forwarder_project'))
          TextInput({ placeholder: $r('app.string.hub_forwarder_address'), text: this.forwarder })
            .onChange((v: string) => {
              this.forwarder = v;
            })
          TextInput({ placeholder: $r('app.string.hub_forwarder_key'), text: this.forwarderKey })
            .maxLength(KEY_LENGTH)
            .onChange((v: string) => {
              this.forwarderKey = v;
            })
          this.note(t('hub_forwarder_back'))

          this.section(t('hub_disguise'))
          this.note(t('hub_disguise_body'))
          this.switchRow(t('hub_strict_vpn'), this.strictVpn, (on: boolean) => {
            this.strictVpn = on;
            if (!on) {
              this.strictWeb = false;
            }
          })
          this.switchRow(t('hub_strict_web'), this.strictWeb, (on: boolean) => {
            this.strictWeb = on;
            if (on) {
              this.strictVpn = true;
            }
          })
          Button($r('app.string.hub_forwarder_save'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .enabled(!this.busy && !app.busy && app.member.running)
            .onClick(() => {
              this.hub(true, false);
            })
        }

        this.section(t('relay_title'))
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
          Button($r('app.string.relay_meet'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.EMPHASIZED })
            .layoutWeight(1)
            .enabled(!this.busy && !app.busy && app.member.running)
            .onClick(() => {
              this.meet();
            })
          if (app.member.relayAt.length > 0) {
            Button($r('app.string.relay_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
              .layoutWeight(1)
              .enabled(!this.busy && !app.busy)
              .onClick(() => {
                this.leave();
              })
          }
        }
        .width('100%')

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
