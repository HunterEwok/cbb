// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class QrAnalyzerTest {
    /** A QR code drawn into a luminance plane with padded rows, as a camera gives it. */
    private fun frame(text: String, width: Int, height: Int, rowStride: Int): ByteArray {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height)
        val y = ByteArray(rowStride * height) { 0x40 }
        for (r in 0 until height) for (c in 0 until width) y[r * rowStride + c] = if (m[c, r]) 0x10 else 0xe0.toByte()
        return y
    }

    @Test
    fun readsAJoinCode() {
        val text = "cbb://join?v=1&a=192.168.0.10:8764&f=abc&c=123456"
        val a = QrAnalyzer {}
        assertEquals(text, a.decode(frame(text, 320, 240, 384), 384, 320, 240))
        assertNull(a.decode(ByteArray(384 * 240) { 0x80.toByte() }, 384, 320, 240))
    }
}
