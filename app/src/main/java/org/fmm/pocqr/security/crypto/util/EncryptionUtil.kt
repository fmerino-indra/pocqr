package org.fmm.pocqr.security.crypto.util

import android.util.Base64
import android.util.Log
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Clase para encriptar / desencriptar datos usando la SecretKey del Keystore
 */
object EncryptionUtil {

    //ENCRYPTION
    private const val RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" // OAEP para cifrado
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"

    //SIGNATURE
    private const val RSA_SIGNATURE_ALGORITHM = "SHA256withRSA/PSS"

    private const val GCM_IV_LENGTH = 12 // Longitud del IV para GCM en bytes
    private const val GCM_TAG_LENGTH = 128 // Longitud del tag para GCM en bits

    private var _signature: Signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM)

    /**
     * Encripta los datos utilizando la clave simétrica proporcionada.
     * AES/GCM/NoPadding
     * IV 12
     * TAG 128
     * @param data Los datos a encriptar.
     * @param secretKey La SecretKey obtenida del Android Keystore.
     * @return Una cadena Base64 que contiene el IV y los datos encriptados.
     */
    fun encryptByteArray(data: ByteArray, secretKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv) // Generar un IV aleatorio para cada encriptación
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)

        val encryptedBytes = cipher.doFinal(data)

        // Combinar el IV y los datos encriptados para almacenarlos juntos
        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
        return combined
        //return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * Encripta los datos utilizando la clave pública proporcionada.
     * RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * @param data Los datos a encriptar.
     * @param publicKey La SecretKey obtenida del Android Keystore.
     * @return Una cadena Base64 que contiene el IV y los datos encriptados.
     */
    fun encryptByteArray(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data)

        return encryptedBytes
    }
   /**
    * Desencripta los datos utilizando la clave simétrica proporcionada.
    * @param encryptedDataBase64 La cadena Base64 que contiene el IV y los datos encriptados.
    * @param secretKey La SecretKey obtenida del Android Keystore.
    * @return Los datos desencriptados en un ByteArray.
    */
    fun decryptByteArray(encryptedDataBase64: String, secretKey: SecretKey): ByteArray {
        return decryptByteArray(Base64.decode(encryptedDataBase64, Base64.DEFAULT), secretKey)
    }
    /**
     * Desencripta los datos utilizando la clave simétrica proporcionada.
     * @param combined El array de bytes que contiene el IV(12) y los datos encriptados.
     * @param secretKey La SecretKey obtenida del Android Keystore.
     * @return Los datos desencriptados en un ByteArray.
     */
    fun decryptByteArray(combined: ByteArray, secretKey: SecretKey): ByteArray {

        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encryptedData = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(encryptedData)
    }

    /**
     * Desencripta los datos utilizando la clave private proporcionada.
     * @param encryptedDataBase64 La cadena Base64 que representa los datos encriptados.
     * @param privateKey La PrivateKey obtenida del Android Keystore.
     * @return Los datos desencriptados en un ByteArray.
     */
    fun decryptByteArray(encryptedDataBase64: String, privateKey: PrivateKey): ByteArray {
        return decryptByteArray(Base64.decode(encryptedDataBase64, Base64.DEFAULT),privateKey)
    }
    /**
     * Desencripta los datos utilizando la clave private proporcionada.
     * @param encryptedByteArray El array de bytes que representa los datos encriptados.
     * @param privateKey La PrivateKey obtenida del Android Keystore.
     * @return Los datos desencriptados en un ByteArray.
     */
    fun decryptByteArray(encryptedByteArray: ByteArray, privateKey: PrivateKey): ByteArray {

        val cipherRsa = Cipher.getInstance(RSA_ALGORITHM)
        cipherRsa.init(Cipher.DECRYPT_MODE, privateKey)
        return cipherRsa.doFinal(encryptedByteArray)
    }

    fun getIv(encryptedDataBase64: String): ByteArray {
        val combined = Base64.decode(encryptedDataBase64, Base64.DEFAULT)
        return combined.copyOfRange(0, GCM_IV_LENGTH)
    }

    fun signData(dataToSign: ByteArray, privateKey: PrivateKey): ByteArray {
        // Aquí intentamos inicializar el Signature. Si la clave es biométrica y no autenticada,
        // se lanzará UserNotAuthenticatedException.
        _signature.initSign(privateKey)
        _signature.update(dataToSign)
        return _signature.sign()

    }

    fun verifySignature(
        data:ByteArray,
        signatureToVerify: ByteArray,
        publicKey: PublicKey?
    ): Boolean {
        _signature.initVerify(publicKey)
        _signature.update(data)
        return _signature.verify(signatureToVerify)
    }

}