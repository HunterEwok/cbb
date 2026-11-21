// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// "Why it does not sync" (docs/apps.md): the core decides the reasons, the
// app only says each code in its words, as the other phones do.

import { t } from '../core/Text';
import { Why } from '../model/Member';

// The codes with a title and an action of their own.
const TITLED: string[] = ['not_in_group', 'removed', 'taken_over', 'frozen', 'cert_expired', 'cert_ending', 'stopped',
  'secrets_stopped', 'sync_off', 'only_device', 'away_off', 'new_network', 'no_hub', 'tunnel_blocked', 'hub_unreachable',
  'alone', 'relay_down', 'hub_waiting', 'muted', 'forwarder_down', 'entries_stale', 'newer', 'unreached',
  'devices_offline', 'devices_sync_off', 'devices_muted', 'update'];
const NO_ACTION: string[] = ['secrets_stopped', 'devices_offline', 'devices_sync_off', 'devices_muted', 'update'];

// What is wrong.
export function whyTitle(r: Why): string {
  if (!TITLED.includes(r.code)) {
    return r.code;
  }
  const until = r.until_ms ?? 0;
  const date = until > 0 ? new Date(until).toLocaleString() : '';
  const names = (r.devices ?? []).join(', ');
  switch (r.code) {
    case 'taken_over':
    case 'tunnel_blocked':
    case 'hub_unreachable':
      return t(`why_${r.code}_t`, r.device ?? '');
    case 'cert_expired':
    case 'cert_ending':
      return t(`why_${r.code}_t`, date);
    case 'sync_off':
    case 'muted':
      return until > 0 ? t(`why_${r.code}_until_t`, date) : t(`why_${r.code}_t`);
    case 'unreached':
    case 'devices_offline':
    case 'devices_sync_off':
    case 'devices_muted':
      return t(`why_${r.code}_t`, names);
    case 'update':
      return t('why_update_t', r.value ?? '');
    default:
      return t(`why_${r.code}_t`);
  }
}

// What to do, '' when there is nothing to do.
export function whyAction(r: Why): string {
  if (!TITLED.includes(r.code) || NO_ACTION.includes(r.code)) {
    return '';
  }
  return r.code === 'taken_over' ? t('why_taken_over_d', r.device ?? '') : t(`why_${r.code}_d`);
}

// The code and the core's detail, for the error details.
export function whyDetail(r: Why): string {
  return [r.code, r.detail ?? ''].filter((s: string) => s.length > 0).join(': ');
}
