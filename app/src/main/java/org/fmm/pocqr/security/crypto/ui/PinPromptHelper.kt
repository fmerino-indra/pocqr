package org.fmm.pocqr.security.crypto.ui

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import androidx.activity.result.ActivityResultLauncher
import androidx.fragment.app.FragmentActivity
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.Cipher

const val DEVICE_AUTHENTICATION_FMM = 0x0800//1 shl 11

sealed class PinOperationCryptoObject {
    data class PinCipherObject(val cipher: Cipher, val privateKey: PrivateKey):
        PinOperationCryptoObject()
    data class PinSignatureObject(val unInitSignature: Signature, val privateKey: PrivateKey):
        PinOperationCryptoObject()
//    object None: BiometricOperationCryptoObject() // Para cuando no se necesita
}
class PinPromptHelper(
    private val activity: FragmentActivity,
    private val authenticationLauncher: ActivityResultLauncher<Intent>
    //,
    //private val onSuccess: (Int) -> Unit
) {

    private val keyguardManager = activity.applicationContext.getSystemService(Context
        .KEYGUARD_SERVICE) as KeyguardManager

    fun isDeviceAuthenticationAvailable(): Boolean {
        return keyguardManager.isDeviceSecure
    }
    fun getAllAvailableAuthenticators(): Int  {
        return if (keyguardManager.isDeviceSecure)
            DEVICE_AUTHENTICATION_FMM
        else
            0
    }

/*
    fun handlePinSignature(resultCode: Int) {
        if (resultCode == Activity.RESULT_OK) {
            onSuccess(resultCode)
        } else if (resultCode == Activity.RESULT_CANCELED) {
            Log.d("PinPromptHelper", "El usuario ha cancelado")
        } else {
            Toast.makeText(
                activity, "Error de autenticación. Resultado inesperado", Toast
                    .LENGTH_LONG
            ).show()
        }
    }
*/

    fun authenticate(
        promptTitle: String,
        promptSubtitle: String,
    ) {

        val intent =keyguardManager.createConfirmDeviceCredentialIntent(
            promptTitle, promptSubtitle)
        authenticationLauncher.launch(intent)
    }
}