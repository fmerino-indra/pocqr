package org.fmm.pocqr.security.crypto.util

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import org.fmm.pocqr.security.crypto.dto.EncryptedData
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
private const val RSA_SIGNATURE_ALGORITM = "SHA256withRSA/PSS"

class AsymmetricRSAHybridCipherManagerOld(private val context: Context) {
    private var _signature: Signature = Signature.getInstance(RSA_SIGNATURE_ALGORITM)
    val signature get() = _signature
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
    fun encryptByteArray(dataToEncrypt: ByteArray, recipientPublicKey: PublicKey): EncryptedData {

        // 1. Generar una clave simétrica (AES) aleatoria
        val symmetricEphemeralKey = AndroidKeystoreUtil.generateEphemeralKey()
        // 2. Cifrar los datos grandes con la clave simétrica (AES)
        val encryptedData = EncryptionUtil.encryptByteArray(dataToEncrypt, symmetricEphemeralKey)

        // 3. Cifrar la clave simétrica (AES) con la clave pública RSA del destinatario
        _rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
        val encryptedSymmetricKey = _rsaCipher.doFinal(symmetricEphemeralKey.encoded)

        return EncryptedData(
            encryptedSymmetricKey,
            encryptedData.toByteArray()
        )
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
    private fun decryptByteArray(
        encryptedData: ByteArray,
        encryptedSymmetricKey: ByteArray,
        ivBytes: ByteArray= byteArrayOf(),
        recipientPrivateKey: PrivateKey
    ): ByteArray {
        // 1. Descifrar la clave simétrica (AES) con la clave privada RSA
        val rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY) // OAEP padding
        rsaCipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey)
        val decryptedSymmetricKeyBytes = rsaCipher.doFinal(encryptedSymmetricKey)

        // Reconstruir la SecretKey AES a partir de los bytes descifrados
        val symmetricKey =
            SecretKeySpec(decryptedSymmetricKeyBytes, 0, decryptedSymmetricKeyBytes.size, "AES")

        // Crear el IvParameterSpec con el IV proporcionado
        if (ivBytes.isEmpty()) {

        }
        val ivSpec = IvParameterSpec(ivBytes)

        // 2. Descifrar los datos grandes con la clave simétrica (AES) y el IV
        val aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivSpec)
        return aesCipher.doFinal(encryptedData)
    }

    fun decryptByteArray(encryptedData: EncryptedData): ByteArray {
        val recipientPrivateKey: PrivateKey? = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
        if (recipientPrivateKey != null) {
            return decryptByteArray(
                encryptedData.encryptedData,
                encryptedData.encryptedSymmetricKey,
                encryptedData.getIv(),
                recipientPrivateKey
            )
        } else {
            throw RuntimeException("No PrivateKey found to decrypt message")
        }
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
        // Aquí intentamos inicializar el Signature. Si la clave es biométrica y no autenticada,
        // se lanzará UserNotAuthenticatedException.
        _signature.initSign(privateKey)
        _signature.update(dataToSign)
        return _signature.sign()
    }
}