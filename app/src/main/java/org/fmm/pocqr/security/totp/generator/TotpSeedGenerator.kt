package org.fmm.pocqr.security.totp.generator

import java.security.SecureRandom
import java.util.Base64

object TotpSeedGenerator {
    fun generateTotpSeed(): String {
        val seedSize = 20 // 20 bytes for HMAC-SHA1 (160 bits)
        val random = SecureRandom()
        val seedBytes = ByteArray(seedSize)
        random.nextBytes(seedBytes)
        // Codificar la semilla a Base 64 para facilitar su manejo
        return Base64.getEncoder().encodeToString(seedBytes)
    }
}