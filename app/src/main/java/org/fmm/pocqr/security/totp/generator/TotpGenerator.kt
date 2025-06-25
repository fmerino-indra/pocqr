package org.fmm.pocqr.security.totp.generator

import android.util.Base64
import org.fmm.pocqr.security.crypto.util.EncryptionUtil
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Generates TOTP Seed and TOTPs
 */
object TotpGenerator {
    private const val SEED_SIZE = 20 // 20 bytes for HMAC-SHA1 (160 bits)
    private const val TIME_STEP_SECONDS = 60L
    private const val TOTP_DIGITS = 6
    private const val TOLERANCE_STEPS = 1 // Tolerancia en pasos (no en segundos) Si == 1,
    // significa: 1 paso antes y 1 paso después (total 3 ventanas)

    /**
     * Genera un código TOTP.
     * @param seedBase64 La semilla TOTP codificada en Base64.
     * @param timeInMillis El tiempo actual en milisegundos (System.currentTimeMillis()).
     * @return El código TOTP generado como String.
     */
    fun generateTotp(seedBase64: String, timeInMillis: Long): String {
        val seedBytes: ByteArray = Base64.decode(seedBase64, Base64.DEFAULT)
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
    fun generateTotpSeed(): String {
        val seedSize = SEED_SIZE
        val random = SecureRandom()
        val seedBytes = ByteArray(seedSize)
        random.nextBytes(seedBytes)
        // Codificar la semilla a Base 64 para facilitar su manejo
        return EncryptionUtil.encodeB64(seedBytes)
//        return EncryptionUtil.encodeAndClean(seedBytes)
    }
    fun validateTotp(seedBase64: String, totpToValidate: String, timeInMillis: Long): Boolean {
        val currentStep = timeInMillis / TimeUnit.SECONDS.toMillis(TIME_STEP_SECONDS)

        // Iterate through allowed time "windows" (tolerance)
        for (i in -TOLERANCE_STEPS .. TOLERANCE_STEPS) {
            val validTotp = generateTotp(
                seedBase64,
                (currentStep + i)* TimeUnit.SECONDS.toMillis(TIME_STEP_SECONDS)
            )
            if (validTotp == totpToValidate) {
                return true
            }
        }
        return false
    }
    /**
     * Limpia cualquier espacio en blanco o salto de línea en la cadena Base64.
     * Decodifica la cadena Base64 a bytes binarios (formato X.509 DER si es una clave pública).
     *
     */
    fun cleanAndDecoded(b64EncodedString: String): ByteArray {
        val cleanBase64 = cleanString(b64EncodedString)
        val decodedBytes: ByteArray = android.util.Base64.decode(cleanBase64, android.util.Base64.DEFAULT)
        return decodedBytes
    }
    private fun cleanString(b64EncodedString:String): String {
        val cleanBase64 = b64EncodedString.replace("\\s".toRegex(), "")
        return cleanBase64
    }


}