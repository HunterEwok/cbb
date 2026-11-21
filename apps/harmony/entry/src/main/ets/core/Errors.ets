// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// How the app shows a failure (docs/apps.md, "Errors"): the core's short
// message for the user and, under it in debug mode, the real error, its type,
// code and causes. Debug mode follows the build, and the setting "Show error
// details" turns it on in a release build too. Every shown failure goes to
// the log with its details either way.

import { hilog } from '@kit.PerformanceAnalysisKit';
import { preferences } from '@kit.ArkData';
import BuildProfile from 'BuildProfile';

const DOMAIN: number = 0x0cbb;
const TAG: string = 'cbb';
const SHOW_DETAILS: string = 'show_details';

export class Failure {
  message: string;
  details: string;

  constructor(message: string, details: string) {
    this.message = message;
    this.details = details;
  }
}

export class Errors {
  private static prefs: preferences.Preferences | undefined = undefined;

  // Reads the setting; called once as the app starts.
  static init(prefs: preferences.Preferences): void {
    Errors.prefs = prefs;
  }

  // Whether failures show their details: on in a debug build, and in a
  // release build when the user turned it on.
  static showDetails(): boolean {
    if (BuildProfile.DEBUG) {
      return true;
    }
    return Errors.prefs !== undefined && Errors.prefs.getSync(SHOW_DETAILS, false) as boolean;
  }

  static async setShowDetails(on: boolean): Promise<void> {
    if (Errors.prefs === undefined) {
      return;
    }
    Errors.prefs.putSync(SHOW_DETAILS, on);
    await Errors.prefs.flush();
  }

  static log(line: string): void {
    hilog.info(DOMAIN, TAG, '%{public}s', line);
  }

  // The text a page shows for f, logged with its details.
  static shown(f: Failure): string {
    Errors.log(`shown: ${f.message} | ${f.details}`);
    if (Errors.showDetails() && f.details.length > 0) {
      return `${f.message}\n\n${f.details}`;
    }
    return f.message;
  }

  // A failure for an exception the app did not expect: its own words are
  // the details, never hidden.
  static unexpected(message: string, e: Object): Failure {
    const err = e as Error;
    const name = err.name !== undefined ? err.name : 'Error';
    const code = (e as Record<string, Object>)['code'];
    return new Failure(message, `${name}${code !== undefined ? ` ${code}` : ''}: ${err.message !== undefined ? err.message : String(e)}`);
  }
}
