// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The home-screen widget "Sync clipboard" (common/Widgets.ets): its taps open
// the app with an action (EntryAbility, quick actions), so this ability only
// keeps the widgets' IDs and gives each the state the app wrote last.

import { formBindingData, FormExtensionAbility, formInfo } from '@kit.FormKit';
import { Want } from '@kit.AbilityKit';
import { addWidget, removeWidget, widgetData } from '../common/Widgets';

export default class EntryFormAbility extends FormExtensionAbility {
  onAddForm(want: Want): formBindingData.FormBindingData {
    const id = want.parameters?.[formInfo.FormParam.IDENTITY_KEY];
    if (typeof id === 'string') {
      addWidget(this.context, id);
    }
    return widgetData(this.context);
  }

  onUpdateForm(formId: string): void {
    // The app pushes each change; nothing to fetch here.
  }

  onRemoveForm(formId: string): void {
    removeWidget(this.context, formId);
  }

  onAcquireFormState(want: Want): formInfo.FormState {
    return formInfo.FormState.READY;
  }
}
