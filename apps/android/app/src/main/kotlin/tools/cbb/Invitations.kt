// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * The file of a remote invitation, which the user shares with whoever
 * joins from afar: cbb.cbbinvite, one line, as cbb pair -invite
 * reads it. It lives in the app's cache while the invitation is open and
 * goes when it ends; it is a secret until it is used.
 */
object Invitations {
    private const val DIR = "invites"
    const val NAME = "cbb.cbbinvite"

    fun write(context: Context, text: String): File {
        val dir = File(context.cacheDir, DIR).apply { mkdirs() }
        return File(dir, NAME).apply { writeText(text + "\n") }
    }

    fun delete(file: File) {
        file.delete()
    }

    /** The share sheet for the file, through the app's FileProvider. */
    fun share(context: Context, file: File): Intent {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", file)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return Intent.createChooser(send, null)
    }
}
