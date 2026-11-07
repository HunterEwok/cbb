// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.Closeable
import java.security.MessageDigest

/**
 * The images and files a member holds whole, which it serves to its peers
 * (docs/protocol.md, section 4, "Content"), as Go's node.Content: only the
 * sealed blobs of copies, never the parts in the open.
 */
interface ContentStore {
    /** The blob whose SHA-256 is sum, or null when this phone does not hold all of it. The node closes it. */
    fun open(sum: ByteArray): ContentSource?

    /**
     * Seals the parts of m, which the store holds, into the blob of a new
     * copy under a new key, and keeps the blob to serve it; null when m holds
     * no bytes (docs/protocol.md, section 4, "The blob").
     */
    fun sealBlob(m: Media.Manifest): Pair<ByteArray, Blob>? {
        if (m.size != 0L) throw Content.NoParts()
        return null
    }
}

/** One part a ContentStore opened. */
interface ContentSource : Closeable {
    val size: Long

    /** Reads length bytes from offset, which are all there. */
    fun read(offset: Long, length: Int): ByteArray

    override fun close() {}
}

/**
 * A ContentStore in memory, for the phone's own copies: it keeps the parts
 * and the blobs it was given last, at most twice maxBytes together, for the
 * blob of each copy, and serves only the blobs.
 */
class MemoryContent(private val maxBytes: Long = Media.MAX_MEDIA) : ContentStore {
    private val parts = LinkedHashMap<String, ByteArray>()
    private val blobs = HashSet<String>()

    /** Keeps the bytes of a part, or of a sealed blob, dropping the oldest beyond twice maxBytes; it returns its SHA-256. */
    fun put(bytes: ByteArray, blob: Boolean = false): ByteArray = synchronized(this) {
        val sum = sha256(bytes)
        val key = sum.toHex()
        parts.remove(key)
        parts[key] = bytes
        if (blob) blobs.add(key) else blobs.remove(key)
        var total = parts.values.sumOf { it.size.toLong() }
        val it = parts.entries.iterator()
        while (total > 2 * maxBytes && parts.size > 1 && it.hasNext()) {
            val e = it.next()
            if (e.key == key) continue
            total -= e.value.size
            blobs.remove(e.key)
            it.remove()
        }
        sum
    }

    /** The bytes of a part or a blob it keeps. */
    fun bytes(sum: ByteArray): ByteArray? = synchronized(this) { parts[sum.toHex()] }

    override fun sealBlob(m: Media.Manifest): Pair<ByteArray, Blob>? {
        if (m.size == 0L) return null
        val data = m.parts.filter { !it.dir && it.size > 0 }.map { p ->
            val b = p.sha256?.let { bytes(it) }
            if (b == null || b.size.toLong() != p.size) throw Content.NoParts()
            b
        }
        val key = Blob.newKey()
        val (blob, sealed) = Blob.seal(key, data)
        put(sealed, blob = true)
        return key to blob
    }

    override fun open(sum: ByteArray): ContentSource? = synchronized(this) {
        parts[sum.toHex()]?.takeIf { sum.toHex() in blobs }?.let { b ->
            object : ContentSource {
                override val size = b.size.toLong()
                override fun read(offset: Long, length: Int) = b.copyOfRange(offset.toInt(), offset.toInt() + length)
            }
        }
    }

    companion object {
        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    }
}

/** Fetching the content of media events from the connected members. */
object Content {
    /**
     * The manifest of clipboard data: one part per type, such as an image
     * as "image/png" or "image/jpeg", whose bytes store keeps to serve them.
     */
    fun manifest(store: MemoryContent, data: List<Pair<String, ByteArray>>): Media.Manifest {
        val parts = data.map { (type, bytes) -> Media.Part(type = type, size = bytes.size.toLong(), sha256 = store.put(bytes)) }
        return Media.Manifest(parts.sumOf { it.size }, parts)
    }

    /**
     * The manifest of files the user shared, side by side without folders,
     * whose bytes store keeps to serve them: each name made one every system
     * takes (Media.cleanName), and a name taken already, in any case, given
     * " (2)" and so on before its extension.
     */
    fun files(store: MemoryContent, files: List<Pair<String, ByteArray>>): Media.Manifest {
        val taken = HashSet<String>()
        val parts = files.map { (given, bytes) ->
            val clean = Media.cleanName(given)
            var name = clean
            var n = 2
            while (!taken.add(name.lowercase())) {
                val dot = clean.lastIndexOf('.').takeIf { it > 0 } ?: clean.length
                name = Media.cleanName(clean.substring(0, dot) + " ($n)" + clean.substring(dot))
                n++
            }
            Media.Part(path = name, size = bytes.size.toLong(), sha256 = store.put(bytes))
        }
        return Media.Manifest(parts.sumOf { it.size }, parts)
    }

    class TooLarge(val size: Long, val limit: Long) : Exception("the copy is $size bytes, more than the limit of $limit")

    /** The copy is not sealed to this phone, or names no blob. */
    class Unread : Exception("the copy is not sealed to this phone")

    /** The store does not hold the parts of a copy to seal. */
    class NoParts : Exception("the parts of the copy are no longer on this phone")

    /** The blob or a part does not match its hash, or does not open. */
    class Mismatch : Exception("the copy's content does not match")
}
