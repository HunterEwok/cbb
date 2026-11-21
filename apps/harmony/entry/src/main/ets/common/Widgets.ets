// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the home-screen widget "Sync clipboard" shows (Form Kit,
// entryformability/EntryFormAbility.ets, widget/pages/SyncCard.ets): whether
// the phone has a group, whether sync is on and how many devices are online,
// kept in the preferences "widget" with the widgets' IDs. The app writes the
// state and pushes it to each widget; the form ability, in a process of its
// own, adds and removes the IDs and gives a new widget the state.

import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { formBindingData, formProvider } from '@kit.FormKit';
import { Errors } from '../core/Errors';

const STORE: string = 'widget';

export interface WidgetState {
  group: boolean;
  syncOn: boolean;
  online: number;
}

// The store as on disk: the other process may have changed it.
function store(context: common.Context): preferences.Preferences {
  preferences.removePreferencesFromCacheSync(context, { name: STORE });
  return preferences.getPreferencesSync(context, { name: STORE });
}

export function widgetIds(context: common.Context): string[] {
  return store(context).getSync('ids', []) as string[];
}

export function addWidget(context: common.Context, id: string): void {
  const s = store(context);
  const ids = s.getSync('ids', []) as string[];
  if (!ids.includes(id)) {
    ids.push(id);
    s.putSync('ids', ids);
    s.flushSync();
  }
}

export function removeWidget(context: common.Context, id: string): void {
  const s = store(context);
  const ids = (s.getSync('ids', []) as string[]).filter((x: string) => x !== id);
  s.putSync('ids', ids);
  s.flushSync();
}

// The state as the widget's data.
export function widgetData(context: common.Context): formBindingData.FormBindingData {
  const s = store(context);
  const data: Record<string, Object> = {
    'group': s.getSync('group', false) as boolean,
    'syncOn': s.getSync('syncOn', true) as boolean,
    'online': s.getSync('online', 0) as number
  };
  return formBindingData.createFormBindingData(data);
}

// Keeps the state and shows it on every widget.
export function showOnWidgets(context: common.Context, state: WidgetState): void {
  const s = store(context);
  s.putSync('group', state.group);
  s.putSync('syncOn', state.syncOn);
  s.putSync('online', state.online);
  s.flushSync();
  const data = widgetData(context);
  for (const id of s.getSync('ids', []) as string[]) {
    formProvider.updateForm(id, data).catch((e: Error) => {
      Errors.log(`widget: ${id} not updated: ${e.message}`);
    });
  }
}
