// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.ContentResolver
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
 * "CBB", when the button fetches them; one image or video goes to the
 * gallery's album "CBB" (Pictures/CBB or Movies/CBB) instead, as
 * Telegram and WhatsApp put what they receive, and as the Aurora app does. Android apps rarely
 * put files on the clipboard, so neither side uses it for files.
 */
object Files {
    /** Where saved files go, under Downloads, Pictures and Movies. */
    const val FOLDER = "CBB"

    /** What [save] did: how many files it saved, and whether the one it saved went to the gallery. */
    data class Saved(val count: Int, val gallery: Boolean)

    /** The MIME type of a file by its name's extension, or null. */
    private fun typeOf(name: String): String? = MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase())

    /** Whether a file of type goes to the gallery: an image or a video. */
    fun forGallery(type: String?): Boolean = type != null && (type.startsWith("image/") || type.startsWith("video/"))

    /**
     * Puts f, an image or a video of type, in the gallery's album "CBB"
     * (Pictures/CBB or Movies/CBB) under name; a name taken there gets a
     * number from Android.
     */
    fun toGallery(context: Context, f: File, name: String, type: String) {
        val video = type.startsWith("video/")
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, type)
            put(MediaStore.MediaColumns.RELATIVE_PATH, (if (video) Environment.DIRECTORY_MOVIES else Environment.DIRECTORY_PICTURES) + "/" + FOLDER)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val collection = if (video) MediaStore.Video.Media.EXTERNAL_CONTENT_URI else MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        insert(context, collection, values, f, "the gallery")
    }

    /** Writes f to a new item of collection with values, pending until it is whole; where names the place in errors. */
    private fun insert(context: Context, collection: Uri, values: ContentValues, f: File, where: String) {
        val cr = context.contentResolver
        val uri = cr.insert(collection, values) ?: throw IOException("$where took no file")
        try {
            (cr.openOutputStream(uri) ?: throw IOException("$where took no file")).use { out -> f.inputStream().use { it.copyTo(out) } }
            cr.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
        } catch (x: Exception) {
            cr.delete(uri, null, null)
            throw x
        }
    }

    /** What the user shared: one image, which goes as an image, or files. */
    sealed class Shared {
        class Image(val image: Images.Copied) : Shared()

        class Many(val files: List<Pair<String, ByteArray>>) : Shared()
    }

    /**
     * Whether uri is one another app hands over through its own provider,
     * which grants the read: content:// only. This app reads a URI with its
     * own rights, so a file:// URI, or one of this app's own providers,
     * could name the app's own files (the group's, its settings) and send
     * them to the group.
     */
    fun foreign(context: Context, uri: Uri): Boolean {
        if (!uri.scheme.equals(ContentResolver.SCHEME_CONTENT, ignoreCase = true)) return false
        val own = context.packageName
        // An authority may carry the user it is for, as "10@authority",
        // and a provider may list several, separated by ';'.
        val authorities = uri.authority?.substringAfter('@')?.split(';') ?: return false
        return authorities.none { it.isEmpty() || it == own || it.startsWith("$own.") }
    }

    /**
     * Reads what another app shared, at most Images.MAX_COPY together; a
     * single image goes as an image, so a computer can paste it. Only what
     * the sharing app's provider hands over is read (foreign).
     */
    fun read(context: Context, uris: List<Uri>): Shared {
        val cr = context.contentResolver
        uris.firstOrNull { !foreign(context, it) }?.let { throw IOException("not a file another app shares: ${it.scheme}://${it.authority}") }
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

    /**
     * Fetches every file of e from the computers and saves it in
     * Downloads/CBB, with its folders, or one image or video in the
     * gallery's album "CBB". A name taken there gets a number from Android.
     */
    fun save(context: Context, node: CoreMember, e: CoreMember.Copy, m: Media.Manifest): Saved {
        var saved = 0
        // The copy's sealed blob holds the bytes of all its files, fetched
        // and opened before any is saved.
        val parts = try {
            fetch(context, node, e)
        } catch (x: Exception) {
            File(context.cacheDir, FETCHED).deleteRecursively()
            throw x
        }
        val files = parts.filter { !it.dir && it.path != null }
        val one = files.singleOrNull()
        val oneType = one?.let { it.type?.takeIf(::forGallery) ?: typeOf(it.path!!) }
        val gallery = one != null && forGallery(oneType)
        for (p in files) {
            val path = p.path!!
            val f = p.file
            try {
                val name = path.substringAfterLast('/')
                if (gallery) {
                    toGallery(context, f, name, oneType!!)
                } else {
                    val dir = path.substringBeforeLast('/', "")
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.RELATIVE_PATH, listOf(Environment.DIRECTORY_DOWNLOADS, FOLDER, dir).filter { it.isNotEmpty() }.joinToString("/"))
                        typeOf(name)?.let { put(MediaStore.Downloads.MIME_TYPE, it) }
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                    insert(context, MediaStore.Downloads.EXTERNAL_CONTENT_URI, values, f, "Downloads")
                }
                saved++
            } finally {
                f.delete()
            }
        }
        File(context.cacheDir, FETCHED).deleteRecursively()
        return Saved(saved, gallery)
    }
}
