package org.fmm.pocqr.security.crypto.util

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import org.fmm.pocqr.security.crypto.dto.EncryptedData
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

private const val RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
private const val RSA_SIGNATURE_ALGORITHM = "SHA256withRSA/PSS"

class AsymmetricRSAHybridCipherManager(private val context: Context) {
/*
    private var _signature: Signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM)
    val signature get() = _signature
*/
    private var _rsaCipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY) // OAEP padding
    val rsaCipher get() = _rsaCipher

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
            val encryptedData = EncryptionUtil.encryptByteArray(dataToEncrypt, symmetricEphemeralKey)

            // 3. Cifrar la clave simétrica (AES) con la clave pública RSA del destinatario
            val encryptedSymmetricKey = EncryptionUtil.encryptByteArray(
                symmetricEphemeralKey.encoded, 
                recipientPublicKey
            )
/*
            _rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
            val encryptedSymmetricKey = _rsaCipher.doFinal(symmetricEphemeralKey.encoded)
*/

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
        val decryptedSymmetricKeyBytes = EncryptionUtil.decryptByteArray(encryptedData
            .encryptedSymmetricKey, recipientPrivateKey!!)
        // Reconstruir la SecretKey AES a partir de los bytes descifrados
        val symmetricKey = SecretKeySpec(decryptedSymmetricKeyBytes, 0,
            decryptedSymmetricKeyBytes.size, "AES")

        return EncryptionUtil.decryptByteArray(encryptedData.encryptedData, symmetricKey)
    }

    @Throws(
        NoPrivateKeyException::class,
        UserNotAuthenticatedException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        KeyPermanentlyInvalidatedException::class // Puede ocurrir si se cambia la biometría
    )
    fun signData(dataToSign: ByteArray): ByteArray {
        val privateKey = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
        if (privateKey == null) {
            Log.e("BiometricPromptHelpter", "No RSA private key prepared to sign")
            throw NoPrivateKeyException("No privateKey found")
        }
        return EncryptionUtil.signData(dataToSign, privateKey)
    }

    fun verifySignature(data:ByteArray, signatureToVerify: ByteArray): Boolean {
        val publicKey = AndroidKeystoreUtil.getRsaPublicKey()
        return EncryptionUtil.verifySignature(data, signatureToVerify, publicKey)
    }
}


