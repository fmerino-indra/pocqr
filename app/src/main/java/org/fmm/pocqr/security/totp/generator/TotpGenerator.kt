package org.fmm.pocqr.security.totp.generator

import java.nio.ByteBuffer
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object TotpGenerator {
    private const val TIME_STEP_SECONDS = 60L // Mismo tiempo que el generador
    private const val TOTP_DIGITS = 6 // Debe ser el mismo que el generador

    /**
     * Genera un código TOTP.
     * @param seedBase64 La semilla TOTP codificada en Base64.
     * @param timeInMillis El tiempo actual en milisegundos (System.currentTimeMillis()).
     * @return El código TOTP generado como String.
     */
    fun generateTotp(seedBase64: String, timeInMillis: Long): String {
        val seedBytes = Base64.getDecoder().decode(seedBase64)
        val timeStep = timeInMillis / TimeUnit.SECONDS.toMillis(TIME_STEP_SECONDS) // Contador de tiempo

        val key = SecretKeySpec(seedBytes, "HmacSHA1")
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(key)

        // El contador de tiempo debe ser un valor de 8 bytes
        val data = ByteBuffer.allocate(8).putLong(timeStep).array()
        val hash = mac.doFinal(data)

        // RFC 4226 (HOTP) truncation
        val offset = hash[hash.size - 1].toInt() and 0xf
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)

        val otp = binary % Math.pow(10.0, TOTP_DIGITS.toDouble()).toInt()

        // Formatear a 6 dígitos con ceros iniciales si es necesario
        return String.format("%0${TOTP_DIGITS}d", otp)
    }

}