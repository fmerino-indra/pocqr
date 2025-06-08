package org.fmm.pocqr.security.crypto.util

import android.app.Activity
import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import org.fmm.pocqr.security.crypto.dto.EncryptedData
import org.fmm.pocqr.security.crypto.ui.BiometricOperationCryptoObject
import org.fmm.pocqr.security.crypto.ui.BiometricPromptHelper
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.spec.SecretKeySpec


class AsymmetricRSAHybridCipherManager(
    private val context: Context,
    private val activity: FragmentActivity) {

    private val encryptionUtil= EncryptionUtil()
    private val biometricPrompHelper:BiometricPromptHelper= BiometricPromptHelper(activity)

    private val _signatureUpdatedEvent = MutableSharedFlow<String>(
        extraBufferCapacity = 1, // Puedes ajustar esto. 1 si quieres que el último evento no se pierda si no hay un colector inmediato.
        onBufferOverflow = BufferOverflow.DROP_OLDEST // Opciones como DROP_LATEST, SUSPEND
    )
    val signatureUpdatedEvent: SharedFlow<String> = _signatureUpdatedEvent

    /**
     * Cifra datos grandes utilizando un esquema híbrido:
     * 1. Genera una clave AES aleatoria.
     * 2. Cifra los datos con la clave AES (algoritmo simétrico).
     * 3. Cifra la clave AES con la clave pública RSA (algoritmo asimétrico).
     *
     * @param dataToEncrypt Los datos originales a cifrar.
     * @param recipientPublicKey La clave pública RSA del destinatario.
     * @return Un objeto EncryptedData que contiene la clave simétrica cifrada y los datos cifrados.
     * @throws Exception Si ocurre un error durante el cifrado.
     */
    fun encryptHybridByteArray(dataToEncrypt: ByteArray, recipientPublicKey: PublicKey):
            EncryptedData {
        try {
            // 1. Generar una clave simétrica (AES) aleatoria
            val symmetricEphemeralKey = AndroidKeystoreUtil.generateEphemeralKey()
            // 2. Cifrar los datos grandes con la clave simétrica (AES)
            val encryptedData = encryptionUtil.encryptByteArray(dataToEncrypt, symmetricEphemeralKey)

            // 3. Cifrar la clave simétrica (AES) con la clave pública RSA del destinatario
            val encryptedSymmetricKey = encryptionUtil.encryptByteArray(
                symmetricEphemeralKey.encoded, 
                recipientPublicKey
            )

            return EncryptedData(
                encryptedSymmetricKey,
                encryptedData
            )
        } catch (e: UserNotAuthenticatedException) {
            throw e
        } catch (e: GeneralSecurityException) {
            throw RuntimeException("Cryptographic error when encrypting: ${e.message}", e)
        }
    }

    /**
     * Descifra datos cifrados con un esquema híbrido, incluyendo el IV.
     * 1. Descifra la clave simétrica (AES) con la clave privada RSA.
     * 2. Descifra los datos grandes con la clave AES descifrada y el IV.
     *
     * @param encryptedData Los datos grandes cifrados con AES.
     * @param encryptedSymmetricKey La clave simétrica cifrada con RSA.
     * @param ivBytes El Initialization Vector (IV) utilizado para el cifrado AES.
     * @param recipientPrivateKey La clave privada RSA del destinatario.
     * @return Los datos originales descifrados.
     * @throws Exception Si ocurre un error durante el descifrado.
     */
    fun decryptHybridByteArray(encryptedData: EncryptedData
    ): ByteArray {

        val recipientPrivateKey: PrivateKey? = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
        if (recipientPrivateKey == null)
            throw Exception()

        // Descifra la clave simétrica
        val decryptedSymmetricKeyBytes = encryptionUtil.decryptByteArray(encryptedData
            .encryptedSymmetricKey, recipientPrivateKey!!)
        // Reconstruir la SecretKey AES a partir de los bytes descifrados
        val symmetricKey = SecretKeySpec(decryptedSymmetricKeyBytes, 0,
            decryptedSymmetricKeyBytes.size, "AES")

        return encryptionUtil.decryptByteArray(encryptedData.encryptedData, symmetricKey)
    }

    @Throws(
        NoPrivateKeyException::class,
        UserNotAuthenticatedException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        KeyPermanentlyInvalidatedException::class // Puede ocurrir si se cambia la biometría
    )
    fun signData(dataToSign: ByteArray) {
        activity.lifecycleScope.launch {
            try {
                val privateKey = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
                if (privateKey == null) {
                    Log.e("BiometricPromptHelpter", "No RSA private key prepared to sign")
                    throw NoPrivateKeyException("No privateKey found")
                }
                val signatureBytes = encryptionUtil.signData(dataToSign, privateKey)
                _signatureUpdatedEvent.emit(Base64.encodeToString(signatureBytes, Base64.DEFAULT))
            } catch (e: Exception) {
                e.printStackTrace()
                showBiometricPromptForSigning(dataToSign)
            } catch (unae: UserNotAuthenticatedException) {
                showBiometricPromptForSigning(dataToSign)
            }
        }
    }

    fun verifySignature(data:ByteArray, signatureToVerify: ByteArray): Boolean {
        val publicKey = AndroidKeystoreUtil.getRsaPublicKey()
        return encryptionUtil.verifySignature(data, signatureToVerify, publicKey)
    }

    private fun showBiometricPromptForSigning(dataToReSign: ByteArray) {
        biometricPrompHelper.authenticate(
            promptTitle = "Sign document",
            promptSubtitle = "Authenticate to digital sign",
            cryptoOperationObject = BiometricOperationCryptoObject.SignatureObject
                (encryptionUtil.signature),
            onSuccess = { authResult ->
                activity.lifecycleScope.launch {
                    try {

                        // Authentication successful. The CryptoObject in authResult is now unlocked.
                        val unlockedSignature = (authResult.cryptoObject?.signature)
                            ?: throw IllegalStateException(
                                "Signature CryptoObject is null after " +
                                        "sucessfull authentication"
                            )
                        unlockedSignature.update(dataToReSign)
                        val signatureBytes = unlockedSignature.sign()

                        val signatureBase64 =
                            Base64.encodeToString(signatureBytes, Base64.DEFAULT)
                        _signatureUpdatedEvent.emit(signatureBase64)
                    } catch (e: Exception) {
                        Toast.makeText(
                            activity, "Error reintentando firmar: ${e.message}", Toast
                                .LENGTH_SHORT
                        ).show()
                        e.printStackTrace()
                    }
                }
            },
            onError = { errorCode, errString ->
                Toast.makeText(
                    activity, "Error de autenticación: $errString ($errorCode)", Toast
                        .LENGTH_LONG
                ).show()
            },
            onFailed = {
                Toast.makeText(
                    activity, "Autenticación de firma fallida o cancelada.", Toast
                        .LENGTH_SHORT
                ).show()
            }
        )
    }
}


