package org.fmm.pocqr.security.totp.validator

import org.fmm.pocqr.security.totp.generator.TotpGenerator
import org.fmm.pocqr.security.totp.generator.TotpSeedGenerator
import java.util.concurrent.TimeUnit

object TotpValidator {
    private const val TIME_STEP_SECONDS = 60L // Mismo tiempo que el generador
    private const val TOTP_DIGITS = 6 // Debe ser el mismo que el generador
    private const val TOLERANCE_STEPS = 1 // Tolerancia: 1 paso antes y 1 paso después

    /**
     * Valida un código TOTP
     * @param seedBase64 La semilla TOTP codificada en Base64
     * @param enteredTotp El código TOTP introducido por el admin
     * @param timeInMillis El tiempo actual en milisegundos en el dispositivos del responsable
     * @return true si el código es válido dentro de la tolerancia, false en caso contrario
     */
    fun validateTotp(seedBase64: String, enteredTotp: String, timeInMillis: Long): Boolean {
        val currentStep = timeInMillis / TimeUnit.SECONDS.toMillis(TIME_STEP_SECONDS)

        // Iterar a través de las ventanas de tiempo permitidas (tolerancia)
        for (i in -TOLERANCE_STEPS..TOLERANCE_STEPS) {
            val validTotp = TotpGenerator.generateTotp(seedBase64, (currentStep + i) * TimeUnit
                .SECONDS.toMillis(TIME_STEP_SECONDS))
            if (validTotp == enteredTotp) {
                return true
            }
        }
        return false
    }
}