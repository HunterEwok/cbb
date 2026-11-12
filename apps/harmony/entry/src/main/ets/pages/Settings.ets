// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Settings: the language, the error details, the notifications, the
// advanced settings with the lab, this phone as the hub or at a relay, the root's settings of the group (how long a claim waits, which keys an admin
// may keep, the watch as an admin), leaving the group, and what this app and its core are.

import { router } from '@kit.ArkUI';
import { i18n } from '@kit.LocalizationKit';
import { versionLine } from '../core/Core';
import { Errors } from '../core/Errors';
import { osVersion } from '../core/Phone';
import { t } from '../core/Text';
import { app } from '../model/AppModel';
import { EVENT_KINDS } from '../model/Events';
import { watch } from '../model/Watch';
import { BusyLine, ErrorText, PageTitle } from '../components/Common';
import { WhySection } from '../components/WhySection';

// The languages of the apps (docs/apps.md, Languages), '' for the phone's.
const LANGUAGES: string[] = ['', 'en', 'zh-Hans', 'es', 'ru', 'ar', 'sw', 'he', 'hi'];
const DELAY_HOURS: number[] = [0, 1, 24, 72, 168];
const KEY_LEVELS: string[] = ['proven', 'hardware', 'files'];

@Entry
@ComponentV2
struct Settings {
  @Local language: string = '';
  @Local core: string = '';
  @Local notify: boolean[] = [];
  @Local error: string = '';

  aboutToAppear(): void {
    try {
      const preferred = i18n.System.getAppPreferredLanguage();
      this.language = LANGUAGES.includes(preferred) ? preferred : '';
    } catch (e) {
      this.language = '';
    }
    this.core = versionLine();
    this.notify = EVENT_KINDS.map((k: string) => app.events.isOn(k));
  }

  languageName(code: string): string {
    if (code.length === 0) {
      return t('settings_language_phone');
    }
    try {
      return i18n.System.getDisplayLanguage(code, code, true);
    } catch (e) {
      return code;
    }
  }

  setLanguage(code: string): void {
    try {
      i18n.System.setAppPreferredLanguage(code.length > 0 ? code : 'default');
      this.language = code;
      Errors.log(`settings: language ${code.length > 0 ? code : 'of the phone'}`);
    } catch (e) {
      this.error = Errors.shown(Errors.unexpected(t('error_language'), e as Object));
    }
  }

  keyboardState(): string {
    if (!app.keyboard.on) {
      return t('lab_off');
    }
    if (app.keyboard.state === 'connected') {
      return t('lab_connected');
    }
    return app.keyboard.state === 'failed' ? t('lab_failed') : t('lab_on');
  }

  confirm(message: string, button: string, yes: () => void): void {
    this.getUIContext().showAlertDialog({
      message: message,
      primaryButton: { value: t('cancel'), action: () => {} },
      secondaryButton: { value: button, fontColor: $r('app.color.error'), action: yes }
    });
  }

  async leave(): Promise<void> {
    if (await app.leave()) {
      router.clear();
      router.replaceUrl({ url: 'pages/Start' });
    }
  }

  @Builder
  section(title: string) {
    Text(title).fontSize(15).fontWeight(FontWeight.Medium).fontColor($r('app.color.accent')).margin({ top: 8 })
  }

  @Builder
  switchRow(label: string, note: string, on: boolean, change: (on: boolean) => void) {
    Row() {
      Column({ space: 2 }) {
        Text(label).fontColor($r('app.color.text'))
        if (note.length > 0) {
          Text(note).fontSize(12).fontColor($r('app.color.secondary'))
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      Toggle({ type: ToggleType.Switch, isOn: on })
        .selectedColor($r('app.color.accent'))
        .onChange(change)
    }
    .width('100%')
  }

  @Builder
  detail(label: string, value: string) {
    Row({ space: 8 }) {
      Text(label).fontSize(13).fontColor($r('app.color.secondary')).width('35%')
      Text(value).fontSize(13).fontColor($r('app.color.text')).layoutWeight(1).copyOption(CopyOptions.LocalDevice)
    }
    .width('100%')
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        PageTitle({ title: $r('app.string.settings_title'), back: () => {
          router.back();
        } })

        Row() {
          Text($r('app.string.settings_language')).fontColor($r('app.color.text')).layoutWeight(1)
          Select(LANGUAGES.map((c: string) => {
            const option: SelectOption = { value: this.languageName(c) };
            return option;
          }))
            .selected(Math.max(LANGUAGES.indexOf(this.language), 0))
            .value(this.languageName(this.language))
            .onSelect((index: number) => {
              this.setLanguage(LANGUAGES[index]);
            })
        }
        .width('100%')

        this.switchRow(t('settings_error_details'), t('settings_error_details_note'), app.errorDetails, (on: boolean) => {
          app.setErrorDetails(on);
        })

        this.section(t('settings_notifications'))
        ForEach(EVENT_KINDS, (kind: string, i: number) => {
          this.switchRow(t(`notify_kind_${kind}`), '', this.notify[i] === true, (on: boolean) => {
            app.events.setOn(kind, on);
            const next = this.notify.slice();
            next[i] = on;
            this.notify = next;
          })
        }, (kind: string) => kind)

        this.switchRow(t('advanced_settings'), '', app.advanced, (on: boolean) => {
          app.setAdvanced(on);
        })
        if (app.membership !== undefined && app.advanced) {
          WhySection({ why: app.member.why, details: app.errorDetails })
        }
        // The lab: what works but is no promise of 1.0 (docs/apps.md, "The lab").
        if (app.advanced) {
          this.section(t('lab'))
          Row() {
            Text($r('app.string.keyboard_switch')).fontColor($r('app.color.text')).layoutWeight(1)
            Text(this.keyboardState()).fontColor($r('app.color.secondary'))
          }
          .width('100%')
          .onClick(() => {
            router.pushUrl({ url: 'pages/Keyboard' });
          })
        }

        if (app.membership !== undefined) {
          this.section(t('settings_group'))
          if (app.member.running) {
            Row() {
              Text($r('app.string.hub_title')).fontColor($r('app.color.text')).layoutWeight(1)
              Text(app.member.hubOn ? t('hub_switch') : app.member.relayAt.length > 0 ? t('relay_title') : '')
                .fontSize(13).fontColor($r('app.color.secondary'))
            }
            .width('100%')
            .onClick(() => {
              router.pushUrl({ url: 'pages/Hub' });
            })
          }
          if (app.isRoot() && app.member.running) {
            Row() {
              Text($r('app.string.settings_delay')).fontColor($r('app.color.text')).layoutWeight(1)
              Select([
                { value: t('settings_delay_0') } as SelectOption, { value: t('settings_delay_1h') } as SelectOption,
                { value: t('settings_delay_1d') } as SelectOption, { value: t('settings_delay_3d') } as SelectOption,
                { value: t('settings_delay_7d') } as SelectOption
              ])
                .selected(Math.max(DELAY_HOURS.indexOf(Math.round((app.member.rootView.delay_ms ?? 0) / 3600000)), 0))
                .value([t('settings_delay_0'), t('settings_delay_1h'), t('settings_delay_1d'), t('settings_delay_3d'),
                  t('settings_delay_7d')][Math.max(DELAY_HOURS.indexOf(Math.round((app.member.rootView.delay_ms ?? 0) / 3600000)), 0)])
                .onSelect((index: number) => {
                  if (DELAY_HOURS[index] * 3600000 !== app.member.rootView.delay_ms) {
                    app.setTakeoverDelay(DELAY_HOURS[index]);
                  }
                })
            }
            .width('100%')
            Row() {
              Column({ space: 2 }) {
                Text($r('app.string.settings_key_level')).fontColor($r('app.color.text'))
                if (app.belowLevel.length > 0) {
                  Text($r('app.string.settings_key_level_below')).fontSize(12).fontColor($r('app.color.error'))
                }
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)
              Select([
                { value: t('settings_level_proven') } as SelectOption, { value: t('settings_level_hardware') } as SelectOption,
                { value: t('settings_level_files') } as SelectOption
              ])
                .selected(Math.max(KEY_LEVELS.indexOf(app.member.rootView.key_level ?? 'hardware'), 0))
                .value([t('settings_level_proven'), t('settings_level_hardware'),
                  t('settings_level_files')][Math.max(KEY_LEVELS.indexOf(app.member.rootView.key_level ?? 'hardware'), 0)])
                .onSelect((index: number) => {
                  if (KEY_LEVELS[index] !== app.member.rootView.key_level) {
                    app.setGroupKeyLevel(KEY_LEVELS[index]);
                  }
                })
            }
            .width('100%')
            Row() {
              Text($r('app.string.recovery_title')).fontColor($r('app.color.text')).layoutWeight(1)
              Text(app.member.rootView.recovery === true ? t('recovery_made') : t('recovery_no')).fontColor($r('app.color.secondary'))
            }
            .width('100%')
            .onClick(() => {
              router.pushUrl({ url: 'pages/Recovery' });
            })
            // The watch as an admin (model/Watch.ets): shown while a watch
            // with CBB is connected, or once it is an admin.
            if (watch.linked || watch.admin) {
              Column({ space: 6 }) {
                Text($r('app.string.watch_admin_title')).fontColor($r('app.color.text'))
                Text(watch.admin ? $r('app.string.watch_made_admin') : $r('app.string.watch_admin_body'))
                  .fontSize(12).fontColor($r('app.color.secondary'))
                if (!watch.admin) {
                  Button($r('app.string.watch_make_admin'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
                    .enabled(!watch.making && !app.busy)
                    .onClick(() => {
                      watch.makeAdmin();
                    })
                  BusyLine({ busy: watch.making })
                }
              }
              .alignItems(HorizontalAlign.Start)
              .width('100%')
            }
          }
          Button($r('app.string.settings_leave'), { type: ButtonType.Capsule, buttonStyle: ButtonStyleMode.NORMAL })
            .width('100%')
            .fontColor($r('app.color.error'))
            .enabled(!app.busy)
            .onClick(() => {
              this.confirm(app.isRoot() ? t('settings_leave_root_confirm') : t('settings_leave_confirm'), t('settings_leave'), () => {
                this.leave();
              });
            })
        }

        this.section(t('settings_about'))
        this.detail(t('settings_version'), AppStorage.get<string>('version') ?? '')
        this.detail(t('settings_core'), this.core)
        this.detail(t('settings_system'), osVersion())
        this.detail(t('settings_key'), t('settings_key_tee'))
        if (app.membership !== undefined) {
          this.detail(t('settings_group_tag'), app.membership.groupTag())
          this.detail(t('settings_device'), app.membership.member.device)
        }
        BusyLine({ busy: app.busy })
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
