// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Reading a QR code with Scan Kit's own scanner, which asks for the camera
// itself: the text, or undefined when the user closed it or the scanner
// failed, which goes to the log (and under the page's error in debug mode).

import { common } from '@kit.AbilityKit';
import { scanBarcode, scanCore } from '@kit.ScanKit';
import { Errors, Failure } from '../core/Errors';
import { t } from '../core/Text';

export class Scanned {
  text?: string;
  failure?: Failure;
}

export async function scanQr(context: common.Context): Promise<Scanned> {
  const out = new Scanned();
  const options: scanBarcode.ScanOptions = {
    scanTypes: [scanCore.ScanType.QR_CODE],
    enableMultiMode: false,
    enableAlbum: true
  };
  try {
    const result = await scanBarcode.startScanForResult(context, options);
    out.text = result.originalValue.trim();
  } catch (e) {
    const f = Errors.unexpected(t('error_scan'), e as Object);
    Errors.log(`scan: ${f.details}`);
    if (Errors.showDetails()) {
      out.failure = f;
    }
  }
  return out;
}
