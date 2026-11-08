// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.graphics.BitmapFactory
import tools.cbb.kit.Content
import tools.cbb.kit.Media
import tools.cbb.kit.Member
import tools.cbb.kit.CoreMember
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/**
 * Images between the phone's clipboard and the group (docs/design.md,
 * "Images and files"): a received image is fetched whole into the app's
 * cache and put on the clipboard through the app's FileProvider; one the
 * phone copied goes as PNG or JPEG.
 */
object Images {
    /** The largest image the phone fetches or sends, as the computers' default limit at home. */
    const val MAX_COPY = 100L shl 20

    /** How many received images the cache keeps: the clipboard may still point at the one before. */
    private const val KEEP = 3

    const val DIR = "received"

    private val TYPES = listOf("image/gif", "image/png", "image/jpeg")

    /** The image part of a media event, GIF before PNG before JPEG, or null for files and other data. */
    fun part(m: Media.Manifest?): Media.Part? {
        if (m == null || m.isFiles) return null
        return TYPES.firstNotNullOfOrNull { t -> m.parts.firstOrNull { it.type == t && it.sha256 != null } }
    }

    /** What the button compares for an image: its hash, which no text equals. */
    fun key(sha256: ByteArray): String = "\u0000image:" + sha256.joinToString("") { "%02x".format(it) }

    /**
     * Fetches the image part of e into the cache, once, and returns its
     * file; it keeps the last few and removes the older ones. It throws
     * when no computer has it, it is too large or does not match.
     */
    fun fetch(context: Context, node: CoreMember, e: CoreMember.Copy, part: Media.Part): File {
        val dir = File(context.cacheDir, DIR).apply { mkdirs() }
        val f = File(dir, "copy-${e.id}.${extension(part.type.orEmpty())}")
        if (f.length() == part.size && f.exists()) return f
        val tmp = File(dir, f.name + ".part")
        try {
            val got = Files.fetch(context, node, e).firstOrNull { !it.dir && it.type == part.type && it.size == part.size }
                ?: throw LiveGroup.Unavailable("the copy came without its image")
            if (!got.file.renameTo(tmp) && !runCatching { got.file.copyTo(tmp, overwrite = true) }.isSuccess) throw IOException("the image could not be saved")
            if (!tmp.renameTo(f)) throw IOException("the image could not be saved")
        } finally {
            tmp.delete()
            File(context.cacheDir, Files.FETCHED).deleteRecursively()
        }
        dir.listFiles()?.filter { it != f && !it.name.endsWith(".part") }?.sortedByDescending { it.lastModified() }?.drop(KEEP - 1)?.forEach { it.delete() }
        return f
    }

    /** The file extension of an image type the group carries. */
    fun extension(type: String): String = when (type) {
        "image/png" -> "png"
        "image/gif" -> "gif"
        else -> "jpg"
    }

    /** The image type of a file extension that extension gives. */
    fun type(extension: String): String = when (extension) {
        "png" -> "image/png"
        "gif" -> "image/gif"
        else -> "image/jpeg"
    }

    /** An image the phone copied, as the group carries it. */
    class Copied(val type: String, val bytes: ByteArray) {
        val key: String get() = Images.key(MessageDigest.getInstance("SHA-256").digest(bytes))
    }

    /**
     * The image of type in stream, as PNG, JPEG or GIF (animated too):
     * other formats (WebP, HEIC) are converted to PNG. Null when it is too
     * large or not an image.
     */
    fun read(type: String, stream: InputStream): Copied? {
        val bytes = stream.use { s ->
            val out = ByteArrayOutputStream()
            val buf = ByteArray(64 shl 10)
            while (true) {
                val n = s.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > MAX_COPY) return null
            }
            out.toByteArray()
        }
        if (type in TYPES) return Copied(type, bytes)
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null
        val png = ByteArrayOutputStream()
        bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, png)
        bitmap.recycle()
        return Copied("image/png", png.toByteArray()).takeIf { it.bytes.size <= MAX_COPY }
    }
}
