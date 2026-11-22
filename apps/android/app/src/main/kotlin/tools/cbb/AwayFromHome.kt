// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Sync away from home as the screens show it. On a group of 0.6 the Live
 * member runs it (AwayOn06); a phone of a group of 0.5 syncs at home only
 * (D-123).
 */
object AwayFromHome {
    /** What the screens show. */
    enum class Status { OFF, WAITING_FOR_HUB, AT_HOME, CONNECTING, CONNECTED }
}

/**
 * A small file encrypted with an AES key in the Keystore, under alias,
 * that never leaves it and needs no unlock, so the phone syncs in the
 * background as at home.
 */
class SealedFile(private val file: File, private val alias: String) {
    /** The file's contents, or null when there is none. */
    fun read(): ByteArray? {
        if (!file.exists()) return null
        val b = file.readBytes()
        if (b.size < IV) return null
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, IV))
        return c.doFinal(b, IV, b.size - IV)
    }

    fun write(data: ByteArray) {
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(file.path + ".tmp")
        // The phone's first secret may come before its group's folder exists.
        file.parentFile?.mkdirs()
        tmp.writeBytes(c.iv + c.doFinal(data))
        if (!tmp.renameTo(file)) throw IOException("cannot replace $file")
    }

    /** Deletes the file and its key. */
    fun delete() {
        file.delete()
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        g.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return g.generateKey()
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val CIPHER = "AES/GCM/NoPadding"
        private const val IV = 12
    }
}
