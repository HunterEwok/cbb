// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Words for a device of the member's devices op (docs/core-api.md), shared
// by the main page's tiles and list and the device's page, as the Aurora
// app's devices.js.

import { t } from '../core/Text';
import { Device } from '../model/Member';

// The name of its system, "device" for firmware without one.
export function system(d: Device): string {
  switch (d.os ?? '') {
    case 'linux':
      return 'Linux';
    case 'windows':
      return 'Windows';
    case 'macos':
      return 'macOS';
    case 'ios':
      return 'iOS';
    case 'android':
      return 'Android';
    case 'aurora':
      return 'Aurora OS';
    case 'sailfish':
      return 'Sailfish OS';
    case 'harmonyos':
      return 'HarmonyOS';
    case 'watchos':
      return 'watchOS';
    case 'wearos':
      return 'Wear OS';
    case '':
      return '';
    default:
      return t('device_system_other');
  }
}

// Whether it is a member with the capability c: admin, dials or hub.
export function can(d: Device, c: string): boolean {
  return d.role === 'member' && (d.caps ?? []).includes(c);
}

// Its kind, from its role and system.
export function kind(d: Device): string {
  if (d.role === 'phone') {
    return t('device_kind_phone');
  }
  if (d.role === 'watch') {
    return t('device_kind_watch');
  }
  if (d.os === 'none') {
    return t('device_kind_board');
  }
  return t('device_kind_computer');
}

// Its form, as the watch draws it: phone, watch, board or computer.
export function form(d: Device): string {
  if (d.role === 'phone' || d.role === 'watch') {
    return d.role;
  }
  return d.os === 'none' ? 'board' : 'computer';
}

// A glyph for its tile.
export function glyph(d: Device): string {
  if (d.role === 'phone') {
    return '\u{1F4F1}';
  }
  if (d.role === 'watch') {
    return '⌚';
  }
  if (d.os === 'none') {
    return '\u{1F50C}';
  }
  return '\u{1F4BB}';
}

// Its mark: this phone, the root, an admin, frozen, or none.
export function mark(d: Device): string {
  if (d.self === true) {
    return t('device_mark_self');
  }
  if (d.frozen === true) {
    return t('device_mark_frozen');
  }
  if (d.root === true) {
    return t('device_mark_root');
  }
  if (d.admin === true) {
    return t('device_mark_admin');
  }
  return '';
}

// Its place in the group, for its page.
export function role(d: Device): string {
  if (d.frozen === true) {
    return t('device_role_frozen');
  }
  if (d.root === true && d.admin === true) {
    return t('device_role_root_admin');
  }
  if (d.root === true) {
    return t('device_role_root');
  }
  if (d.admin === true) {
    return t('device_role_admin');
  }
  if (d.listed !== true) {
    return t('device_role_unlisted');
  }
  return t('device_role_member');
}

export function status(d: Device): string {
  if (d.self === true) {
    return t('device_status_self');
  }
  return d.online === true ? t('device_status_online') : t('device_status_offline');
}

// One line for its card: its system and its CBB version.
export function line(d: Device): string {
  const v = d.version !== undefined && d.version.length > 0 ? `CBB ${d.version}` : '';
  return [system(d), v].filter((s: string) => s.length > 0).join(' · ');
}

// Its name, or the start of its ID when it has none.
export function nameOf(d: Device): string {
  return d.name.length > 0 ? d.name : d.id.substring(0, 8);
}

