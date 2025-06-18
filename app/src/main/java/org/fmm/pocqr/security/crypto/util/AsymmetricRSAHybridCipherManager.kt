package org.fmm.pocqr.security.crypto.util

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import org.fmm.pocqr.PocQRApp
import org.fmm.pocqr.security.crypto.dto.AuthenticationCapabilitiesData
import org.fmm.pocqr.security.crypto.dto.EncryptedData
import org.fmm.pocqr.security.crypto.ui.BiometricOperationCryptoObject
import org.fmm.pocqr.security.crypto.ui.BiometricPromptHelper
import org.fmm.pocqr.security.crypto.ui.PinPromptHelper
import org.fmm.pocqr.security.crypto.ui.PinOperationCryptoObject
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


class AsymmetricRSAHybridCipherManager(
    private val context: Context,
    private val activity: FragmentActivity,
    authenticationLauncher: ActivityResultLauncher<Intent>,
    decryptionAuthenticationLauncher: ActivityResultLauncher<Intent>,
    ) {

    val encryptionUtil= EncryptionUtil()

    private val _signatureUpdatedEvent = MutableSharedFlow<String>(
        extraBufferCapacity = 1, // Puedes ajustar esto. 1 si quieres que el último evento no se pierda si no hay un colector inmediato.
        onBufferOverflow = BufferOverflow.DROP_OLDEST // Opciones como DROP_LATEST, SUSPEND
    )
    val signatureUpdatedEvent: SharedFlow<String> = _signatureUpdatedEvent

    private val _decryptedUpdatedEvent = MutableSharedFlow<String>(
        extraBufferCapacity = 1, // Puedes ajustar esto. 1 si quieres que el último evento no se pierda si no hay un colector inmediato.
        onBufferOverflow = BufferOverflow.DROP_OLDEST // Opciones como DROP_LATEST, SUSPEND
    )
    val decryptedUpdatedEvent: SharedFlow<String> = _decryptedUpdatedEvent

    private val biometricPromptHelper:BiometricPromptHelper= BiometricPromptHelper(activity)

/*
    private val pinPromptHelper: PinPromptHelper= PinPromptHelper(activity,
        authenticationLauncher, ::handlePinSignature)
    private val pinPromptDecryptionHelper: PinPromptHelper= PinPromptHelper(activity,
        authenticationLauncher, ::handlePinDecryption)
*/


    private val pinPromptHelper: PinPromptHelper= PinPromptHelper(activity,
        authenticationLauncher)
    private val pinPromptDecryptionHelper: PinPromptHelper= PinPromptHelper(activity,
        decryptionAuthenticationLauncher)

    val biometricAuthenticators = biometricPromptHelper.getAllAvailableAuthenticators()
    val pinAuthenticators = pinPromptHelper.getAllAvailableAuthenticators()

    val authenticationCapabilitiesData = AuthenticationCapabilitiesData(
        biometricAuthenticators, pinAuthenticators
    )

    private lateinit var lastCryptoOperationObject: PinOperationCryptoObject
    private lateinit var dataToReSign: ByteArray
    private lateinit var dataToDecrypt: ByteArray


    init {
        // Los allowedAuthenticators solo para versión R o superior (>=30)
        try {
            AndroidKeystoreUtil.getOrGenerateRsaKeyPairWithAuthentication(authenticationCapabilitiesData)
        } catch(iape: InvalidAlgorithmParameterException) {
            iape.printStackTrace()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                    putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, biometricPromptHelper.getAllowedAuthenticators())
                }
                activity.startActivityForResult(enrollIntent,101)
            } else {
                val enrollIntent = Intent(Settings.ACTION_SECURITY_SETTINGS)
//                activity.startActivity(enrollIntent)
                activity.startActivityForResult(enrollIntent,101)
            }
        }
    }
    /**
     * Encrypt
     */

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
     * Verify Signature
     */

    /**
     * Verify signature passed as byteArray
     * @param data Data from signature were calculated
     * @param signatureToVerify
     */
    fun verifySignature(data:ByteArray, signatureToVerify: ByteArray): Boolean {
        val publicKey = AndroidKeystoreUtil.getRsaPublicKey()
        return encryptionUtil.verifySignature(data, signatureToVerify, publicKey)
    }

    private fun getAvailableAuthenticators(): Int  {
        val biometrics = biometricPromptHelper.getAllAvailableAuthenticators()
        val device = pinPromptHelper.getAllAvailableAuthenticators()

        return biometrics or device
    }

    /**
     * Sign
     */
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
            val privateKey = AndroidKeystoreUtil.getRsaPrivateKey()
            if (privateKey == null) {
                Log.e("BiometricPromptHelpter", "No RSA private key prepared to sign")
                throw NoPrivateKeyException("No privateKey found")
            }
            try {
                val signatureBytes = encryptionUtil.signData(dataToSign, privateKey)
                _signatureUpdatedEvent.emit(Base64.encodeToString(signatureBytes, Base64.DEFAULT))
            } catch (unae: UserNotAuthenticatedException) {
                unae.printStackTrace()
                showAuthenticationsForSigning(dataToSign, privateKey)
            } catch (e: Exception) {
                e.printStackTrace()
                showAuthenticationsForSigning(dataToSign, privateKey)
            }
        }
    }

    private fun showAuthenticationsForSigning(dataToResign: ByteArray, privateKey: PrivateKey) {
        /* Hay que saber qué características tiene la clave y la versión de la API:
            - init o no init
            - biométrico o PIN (manual)
            - quizá más cosas
                val operation = if (encryptionUtil.){
                    BiometricOperationCryptoObject.SignatureObject(encryptionUtil.prepareToSign(privateKey))
                }
        */
        val keyInfo = AndroidKeystoreUtil.inspectKeyProtection(AndroidKeystoreUtil.KEY_PAIR_ALIAS_RSA)
        if (keyInfo != null) {
            if (keyInfo.isUserAuthenticationRequired) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {

                    if (keyInfo.userAuthenticationValidityDurationSeconds == -1) {
                        // @TODO Biometría, pero para SDK <= 29, si es superior hay que probarlo
                        showBiometricPromptForSigning(dataToResign, privateKey)
                    } else if (keyInfo.userAuthenticationValidityDurationSeconds == 0) {
                        // Cada vez, para SDK <= 29 no funciona
                        // Ninguna está creada así
                    } else if (keyInfo.userAuthenticationValidityDurationSeconds > 0) {
                        showPinPromptForSigning(dataToResign, privateKey)
                    }
                } else {
                    showBiometricPromptForSigning(dataToResign, privateKey)
                }
            }
        }
    }
    fun handlePinSignature(resultCode: Int) {
        if (resultCode == Activity.RESULT_OK) {
            Log.d("AsymmetricRSAHybridCipherManager::handlePinSignature", "Ahora se puede usar la" +
                    " clave")
            (activity.application as PocQRApp).applicationSccope.launch {
                try {

                    val sig = (lastCryptoOperationObject as PinOperationCryptoObject
                        .PinSignatureObject).unInitSignature
                    val pK = (lastCryptoOperationObject as PinOperationCryptoObject
                    .PinSignatureObject).privateKey
                    val signatureBytes = encryptionUtil.signData(dataToReSign, pK)
                    _signatureUpdatedEvent.emit(Base64.encodeToString(signatureBytes, Base64.DEFAULT))
                } catch (unae: UserNotAuthenticatedException) {
                    unae.printStackTrace()
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        } else if (resultCode == Activity.RESULT_CANCELED) {
            Log.d("PinPromptHelper", "El usuario ha cancelado")
        } else {
            Toast.makeText(
                activity, "Error de autenticación. Resultado inesperado", Toast
                    .LENGTH_LONG
            ).show()

        }

    }
    private fun showPinPromptForSigning(dataToReSign: ByteArray, privateKey: PrivateKey) {
        this.dataToReSign=dataToReSign
        lastCryptoOperationObject = PinOperationCryptoObject.PinSignatureObject(encryptionUtil
            .signature, privateKey)
        pinPromptHelper.authenticate(
            promptTitle = "Sign document",
            promptSubtitle = "Authenticate to digital sign"
        )
    }
    private fun showBiometricPromptForSigning(dataToReSign: ByteArray, privateKey: PrivateKey) {
        // Si la clave está protegida con biometría fuerte, falla en Signature.update.
        // El objeto signature debe pasarse el mismo inicializado.
        // Si la clave está protegida con PIN, falla en initSignature.
        // Puede usarse cualquier CryptoObject, de hecho, se invoca a encryptionUtil

        biometricPromptHelper.authenticate(
            promptTitle = "Sign document",
            promptSubtitle = "Authenticate to digital sign",
            cryptoOperationObject = BiometricOperationCryptoObject.SignatureObject
                (encryptionUtil.prepareToSign(privateKey)),
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

    /**
     * Decrypt
     */
    fun decryptAsymmetricByteArray(encryptedBase64: String) {
        val decodedEncryptedData = EncryptionUtil.cleanAndDecoded(encryptedBase64)
        decryptAsymmetricByteArray(decodedEncryptedData)
    }
    fun decryptAsymmetricByteArray(encryptedData: ByteArray) {
        val recipientPrivateKey: PrivateKey? = AndroidKeystoreUtil.getRsaPrivateKey()
        if (recipientPrivateKey == null)
            throw Exception()

        try {
            val decryptedAsymmetricKeyBytes = encryptionUtil.decryptByteArray(encryptedData,
                recipientPrivateKey)
        } catch (unae: UserNotAuthenticatedException) {
            unae.printStackTrace()
            showAuthenticationsForDecrypt(encryptedData, recipientPrivateKey)
        } catch (e: Exception) {
            e.printStackTrace()
            showAuthenticationsForDecrypt(encryptedData, recipientPrivateKey)
        }
    }

    /**
     * @TODO Está mal, en cuanto se use el método casca
     * Descifra datos cifrados con un esquema híbrido, incluyendo el IV.
     * 1. Descifra la clave simétrica (AES) con la clave privada RSA.
     * 2. Descifra los datos grandes con la clave AES descifrada y el IV.
     *
     * @param ivBytes El Initialization Vector (IV) utilizado para el cifrado AES.
     * @param recipientPrivateKey La clave privada RSA del destinatario.
     * @return Los datos originales descifrados.
     * @throws Exception Si ocurre un error durante el descifrado.
     */
    fun decryptHybridByteArray(encryptedData: EncryptedData
    ): ByteArray {


        val recipientPrivateKey: PrivateKey? = AndroidKeystoreUtil.getRsaPrivateKey()
        if (recipientPrivateKey == null)
            throw Exception()

        // Descifra la clave simétrica
        val decryptedSymmetricKeyBytes = encryptionUtil.decryptByteArray(encryptedData
            .encryptedSymmetricKey, recipientPrivateKey)

        // Descifra la clave simétrica

/*
        val decryptedSymmetricKeyBytes = decryptAsymmetricByteArray(
            encryptedData.encryptedSymmetricKey
        )
*/

        // Reconstruir la SecretKey AES a partir de los bytes descifrados
        val symmetricKey = SecretKeySpec(decryptedSymmetricKeyBytes, 0,
            decryptedSymmetricKeyBytes.size, "AES")

        return encryptionUtil.decryptByteArray(encryptedData.encryptedData, symmetricKey)
    }



    private fun showAuthenticationsForDecrypt(dataToReDecrypt: ByteArray, privateKey: PrivateKey) {
        /* Hay que saber qué características tiene la clave y la versión de la API:
            - init o no init
            - biométrico o PIN (manual)
            - quizá más cosas
                val operation = if (encryptionUtil.){
                    BiometricOperationCryptoObject.SignatureObject(encryptionUtil.prepareToSign(privateKey))
                }
        */
        val keyInfo = AndroidKeystoreUtil.inspectKeyProtection(AndroidKeystoreUtil.KEY_PAIR_ALIAS_RSA)
        if (keyInfo != null) {
            if (keyInfo.isUserAuthenticationRequired) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {

                    if (keyInfo.userAuthenticationValidityDurationSeconds == -1) {
                        // @TODO Biometría, pero para SDK <= 29, si es superior hay que probarlo
                        showBiometricPromptForDecrypt(dataToReDecrypt, privateKey)
                    } else if (keyInfo.userAuthenticationValidityDurationSeconds == 0) {
                        // Cada vez, para SDK <= 29 no funciona
                        // Ninguna está creada así
                    } else if (keyInfo.userAuthenticationValidityDurationSeconds > 0) {
                        showPinPromptForDecrypt(dataToReDecrypt, privateKey)
                    }
                } else {
                    showBiometricPromptForDecrypt(dataToReDecrypt, privateKey)
                }
            }
        }
    }
    fun handlePinDecryption(resultCode: Int) {
        if (resultCode == Activity.RESULT_OK) {
            Log.d("AsymmetricRSAHybridCipherManager::handlePinDecryption", "Ahora se puede usar " +
                    "la clave")
            (activity.application as PocQRApp).applicationSccope.launch {
                try {

                    val cip = (lastCryptoOperationObject as PinOperationCryptoObject
                    .PinCipherObject).cipher
                    val pK = (lastCryptoOperationObject as PinOperationCryptoObject
                    .PinCipherObject).privateKey
//                    val decryptedBytes = encryptionUtil.decryptByteArray(dataToDecrypt, pK)
                    cip.init(Cipher.DECRYPT_MODE, pK)
                    val decryptedBytes = cip.doFinal(dataToDecrypt)
                    _decryptedUpdatedEvent.emit(EncryptionUtil.encodeAndClean(decryptedBytes))
                } catch (unae: UserNotAuthenticatedException) {
                    unae.printStackTrace()
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        } else if (resultCode == Activity.RESULT_CANCELED) {
            Log.d("PinPromptHelper", "El usuario ha cancelado")
        } else {
            Toast.makeText(
                activity, "Error de autenticación. Resultado inesperado", Toast
                    .LENGTH_LONG
            ).show()

        }

    }
    private fun showPinPromptForDecrypt(dataToDecrypt: ByteArray, privateKey: PrivateKey) {
        this.dataToDecrypt=dataToDecrypt
        lastCryptoOperationObject = PinOperationCryptoObject.PinCipherObject(encryptionUtil
            .rsaCipher, privateKey)
        pinPromptDecryptionHelper.authenticate(
            promptTitle = "Decrypt data",
            promptSubtitle = "Authenticate to decrypt data"
        )
    }
    private fun showBiometricPromptForDecrypt(dataToDecrypt: ByteArray, privateKey: PrivateKey) {
        // Si la clave está protegida con biometría fuerte, falla en Signature.update.
        // El objeto signature debe pasarse el mismo inicializado.
        // Si la clave está protegida con PIN, falla en initSignature.
        // Puede usarse cualquier CryptoObject, de hecho, se invoca a encryptionUtil

        biometricPromptHelper.authenticate(
            promptTitle = "Sign document",
            promptSubtitle = "Authenticate to digital sign",
            cryptoOperationObject = BiometricOperationCryptoObject.CipherObject
                (encryptionUtil.prepareToDecrypt(privateKey)),
            onSuccess = { authResult ->
                activity.lifecycleScope.launch {
                    try {
                        // Authentication successful. The CryptoObject in authResult is now unlocked.
                        val unlockedCipher = (authResult.cryptoObject?.cipher)
                            ?: throw IllegalStateException(
                                "Cipher CryptoObject is null after " +
                                        "sucessfull authentication"
                            )
                        val decryptedData = unlockedCipher.doFinal(dataToDecrypt)

                        val decryptedBase64 =
                            Base64.encodeToString(decryptedData, Base64.DEFAULT)
                        _decryptedUpdatedEvent.emit(decryptedBase64)
                    } catch (e: Exception) {
                        Toast.makeText(
                            activity, "Error reintentando descifrar: ${e.message}", Toast
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
                    activity, "Autenticación de descrifrado fallida o cancelada.", Toast
                        .LENGTH_SHORT
                ).show()
            }
        )
    }

}


