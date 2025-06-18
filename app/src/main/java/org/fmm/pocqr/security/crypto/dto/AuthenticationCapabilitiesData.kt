package org.fmm.pocqr.security.crypto.dto

import android.os.Build
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager

data class AuthenticationCapabilitiesData(
    val biometricAuthenticators: Int,
    // Para SDK <= 29 (Q)
    val deviceAuthenticators: Int,
) {
    fun hasBiometric(): Boolean = biometricAuthenticators > 0
    fun hasDeviceAuthentication(): Boolean = deviceAuthenticators > 0
    fun hasStrongBiometric(): Boolean = biometricAuthenticators and BiometricManager
        .Authenticators.BIOMETRIC_STRONG == BiometricManager.Authenticators.BIOMETRIC_STRONG
    fun hasWeakBiometric(): Boolean = biometricAuthenticators and BiometricManager
        .Authenticators.BIOMETRIC_WEAK == BiometricManager.Authenticators.BIOMETRIC_WEAK
    fun hasDeviceCredential(): Boolean = biometricAuthenticators and BiometricManager
        .Authenticators.DEVICE_CREDENTIAL == BiometricManager.Authenticators.DEVICE_CREDENTIAL

    @RequiresApi(Build.VERSION_CODES.R)
    fun getKeyPropertiesFromAuthenticators(): Int {
        val s = if (hasBiometric()) KeyProperties.AUTH_BIOMETRIC_STRONG else 0
        val c = if (hasDeviceCredential()) KeyProperties.AUTH_DEVICE_CREDENTIAL else 0
        return s or c
    }
}