// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

/**
 * The sealed blob of a copy's images and files (docs/format.md, section 10.2,
 * "The blob"): the core seals and opens it; the app needs only its size, to
 * bound a fetch.
 */
object Blob {
    /** A blob's segment before sealing, and after. */
    const val SEGMENT = 64 shl 10
    const val SEALED_SEGMENT = SEGMENT + 16L

    /** The size of the sealed blob of n bytes of parts. */
    fun sizeOf(n: Long): Long = (n + SEGMENT - 1) / SEGMENT * SEALED_SEGMENT
}
