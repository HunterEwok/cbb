// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import tools.cbb.kit.Content
import tools.cbb.kit.Media
import tools.cbb.kit.Member
import tools.cbb.kit.CoreMember
import tools.cbb.kit.Core
import tools.cbb.kit.Blob
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

/**
 * Files between the phone and the group (docs/design.md, "Images and
 * files"): what the user shares with the app goes to the computers, and
 * the files a computer copied are saved in Downloads, in a folder
 * "CBB", when the button fetches them. Android apps rarely
 * put files on the clipboard, so neither side uses it for files.
 */
object Files {
    /** Where saved files go, under Downloads. */
    const val FOLDER = "CBB"

    /** What the user shared: one image, which goes as an image, or files. */
    sealed class Shared {
        class Image(val image: Images.Copied) : Shared()

        class Many(val files: List<Pair<String, ByteArray>>) : Shared()
    }

    /**
     * Reads what another app shared, at most Images.MAX_COPY together; a
     * single image goes as an image, so a computer can paste it.
     */
    fun read(context: Context, uris: List<Uri>): Shared {
        val cr = context.contentResolver
        if (uris.size == 1) {
            val type = runCatching { cr.getType(uris[0]) }.getOrNull()
            if (type != null && type.startsWith("image/")) {
                cr.openInputStream(uris[0])?.let { Images.read(type, it) }?.let { return Shared.Image(it) }
            }
        }
        var total = 0L
        val files = uris.map { uri ->
            val name = runCatching {
                cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                    if (c.moveToFirst()) c.getString(0) else null
                }
            }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
            val bytes = (cr.openInputStream(uri) ?: throw IOException("$name could not be opened")).use { s ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(64 shl 10)
                while (true) {
                    val n = s.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (total + out.size() > Images.MAX_COPY) throw Content.TooLarge(total + out.size(), Images.MAX_COPY)
                }
                out.toByteArray()
            }
            total += bytes.size
            name to bytes
        }
        return Shared.Many(files)
    }

    /**
     * Fetches every file of e from the computers and saves it in
     * Downloads/CBB, with its folders; it returns how many it
     * saved. A name taken there gets a number from Android.
     */
    /** The folder in the cache the node opens a fetched copy into, emptied after each. */
    const val FETCHED = "fetched"

    /**
     * Fetches the images or files of the copy e through the node into a new
     * folder of the cache and returns its parts there, each checked against
     * its hash. It throws when the copy is over the limit, is not sealed to
     * this phone, or no connected device has it whole.
     */
    fun fetch(context: Context, node: CoreMember, e: CoreMember.Copy): List<CoreMember.Fetched> {
        val m = e.media ?: throw IllegalArgumentException("the copy holds no images or files")
        if (m.size > Images.MAX_COPY) throw Content.TooLarge(m.size, Images.MAX_COPY)
        if (e.unread) throw Content.Unread()
        val out = File(File(context.cacheDir, FETCHED).apply { deleteRecursively(); mkdirs() }, e.id)
        return try {
            node.fetch(e.id, Blob.sizeOf(Images.MAX_COPY), out)
        } catch (x: Core.Refusal) {
            throw LiveGroup.Unavailable(x.message, x)
        }
    }

    fun save(context: Context, node: CoreMember, e: CoreMember.Copy, m: Media.Manifest): Int {
        val cr = context.contentResolver
        var saved = 0
        // The copy's sealed blob holds the bytes of all its files, fetched
        // and opened before any is saved.
        val parts = try {
            fetch(context, node, e)
        } catch (x: Exception) {
            File(context.cacheDir, FETCHED).deleteRecursively()
            throw x
        }
        for (p in parts) {
            if (p.dir) continue
            val path = p.path ?: continue
            val f = p.file
            try {
                val name = path.substringAfterLast('/')
                val dir = path.substringBeforeLast('/', "")
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.RELATIVE_PATH, listOf(Environment.DIRECTORY_DOWNLOADS, FOLDER, dir).filter { it.isNotEmpty() }.joinToString("/"))
                    MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase())
                        ?.let { put(MediaStore.Downloads.MIME_TYPE, it) }
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: throw IOException("Downloads took no file")
                try {
                    (cr.openOutputStream(uri) ?: throw IOException("Downloads took no file")).use { out -> f.inputStream().use { it.copyTo(out) } }
                    cr.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
                } catch (x: Exception) {
                    cr.delete(uri, null, null)
                    throw x
                }
                saved++
            } finally {
                f.delete()
            }
        }
        File(context.cacheDir, FETCHED).deleteRecursively()
        return saved
    }
}
