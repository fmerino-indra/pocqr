package org.fmm.communitymgmt.ui.security.util

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.fmm.cryptography.R

class BiometricHelper (
    private val activity: FragmentActivity,
    private val onAuthSuccess: () -> Unit,
    private val onAuthError: (String) -> Unit) {

    private val executor = ContextCompat.getMainExecutor(activity)

    private val biometricPrompt = BiometricPrompt (
        activity,
        executor,
        object: BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onAuthSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onAuthError(errString.toString())
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                onAuthError(activity.getString(R.string.biometrics_failed))
            }
        }
    )
    private val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(activity.getString(R.string.biometrics_title))
        .setSubtitle(activity.getString(R.string.biometrics_subtitle))
        .setNegativeButtonText(activity.getString(R.string.cancel))
        .build()

    private fun authenticate() {
        biometricPrompt.authenticate(promptInfo)
    }
}