package org.fmm.pocqr.security.crypto.util

import android.util.Base64
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Clase para encriptar / desencriptar datos usando la SecretKey del Keystore
 */
class EncryptionUtil {

    //ENCRYPTION
    private val RSA_TRANSFORMATION_FOR_ASYMMETRIC_KEY = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
//    private const val RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" // OAEP para cifrado
    private val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"


    //SIGNATURE
    private val RSA_SIGNATURE_ALGORITHM = "SHA256withRSA/PSS"

    private val GCM_IV_LENGTH = 12 // Longitud del IV para GCM en bytes
    private val GCM_TAG_LENGTH = 128 // Longitud del tag para GCM en bits

    private var _signature: Signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM)
    val signature get() = _signature

    private var _rsaCipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION_FOR_ASYMMETRIC_KEY) // OAEP padding
    val rsaCipher get() = _rsaCipher

    private var _aesCipher: Cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION) //
    // OAEP padding
    val aesCipher get() = _aesCipher

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
        //val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv) // Generar un IV aleatorio para cada encriptación
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        _aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)

        val encryptedBytes = _aesCipher.doFinal(data)

        // Combinar el IV y los datos encriptados para almacenarlos juntos
        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
        return combined
        //return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    fun encryptByteArray(base64Data: String, publicKey: PublicKey): ByteArray {
        return encryptByteArray(decodeB64(base64Data), publicKey)
//        return encryptByteArray(cleanAndDecoded(base64Data), publicKey)
    }
    /**
     * Encripta los datos utilizando la clave pública proporcionada.
     * RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     * Los datos a cifrar no pueden superar los 214 bytes
     *
     * @param data Los datos a encriptar.
     * @param publicKey La SecretKey obtenida del Android Keystore.
     * @return Una cadena Base64 que contiene el IV y los datos encriptados.
     */
    fun encryptByteArray(data: ByteArray, publicKey: PublicKey): ByteArray {
        //val cipher = Cipher.getInstance(RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY)
        _rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = _rsaCipher.doFinal(data)

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
//        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)

        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encryptedData = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        // Aquí es donde lanza la excepción de autenticación
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return aesCipher.doFinal(encryptedData)
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

//        val cipherRsa = Cipher.getInstance(RSA_TRANSFORMATION_FOR_SYMMETRIC_KEY)
        // Aquí es donde lanza la excepción de autenticación
        _rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
        return _rsaCipher.doFinal(encryptedByteArray)
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

    /**
     * If key
     */
    fun prepareToSign(privateKey: PrivateKey): Signature {
        _signature.initSign(privateKey)
        return signature
    }

    fun prepareToDecrypt(privateKey: PrivateKey): Cipher {
        _rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
        return _rsaCipher
    }

    fun verifySignature(
        data:ByteArray,
        signatureToVerify: ByteArray,
        publicKey: PublicKey?
    ): Boolean {
        // Aquí es donde lanza la excepción de autenticación
        _signature.initVerify(publicKey)
        _signature.update(data)
        return _signature.verify(signatureToVerify)
    }

    fun publicKeyFromString(encodedPublicKey: String): PublicKey? {
        // Limpia cualquier espacio en blanco o salto de línea en la cadena Base64.
        // Decodifica la cadena Base64 a bytes binarios (formato X.509 DER).
        val decodedBytes: ByteArray = decodeB64(encodedPublicKey)
//        val decodedBytes: ByteArray = cleanAndDecoded(encodedPublicKey)

        // Crear un KeySpec a partir de los bytes decodificados
        val keySpec = X509EncodedKeySpec(decodedBytes)

        // Obtener una instancia de KeyFactory para el algoritmo de clave (ej. RSA, EC, DSA)
        // En la mayoría de los casos, X.509 puede contener diferentes tipos de claves.
        // Si sabes que es RSA, puedes especificar "RSA". Si no, "RSA" o "EC" son comunes.
        val keyFactory = KeyFactory.getInstance("RSA") // O "EC", "DSA", etc., dependiendo del algoritmo

        try {
            // Generar la clave pública
            return keyFactory.generatePublic(keySpec)

        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }

    }

    companion object {
        /**
         * Limpia cualquier espacio en blanco o salto de línea en la cadena Base64.
         * Decodifica la cadena Base64 a bytes binarios (formato X.509 DER si es una clave pública).
         * Debería estar en otra clase, pero de momento...
         */
/*
        private fun cleanAndDecoded(b64EncodedString: String): ByteArray {
            val cleanBase64 = b64EncodedString.replace("\\s".toRegex(), "")
            val decodedBytes: ByteArray = Base64.decode(cleanBase64, Base64.DEFAULT)
            return decodedBytes
        }

        private fun encodeAndClean(data: ByteArray): String {
            val base64Encoded = Base64.encodeToString(data, Base64.DEFAULT)
            return base64Encoded.replace("\\s".toRegex(), "")
        }
*/
        fun decodeB64(b64EncodedString: String): ByteArray {
//            val cleanBase64 = b64EncodedString.replace("\\s".toRegex(), "")
            val decodedBytes: ByteArray = Base64.decode(b64EncodedString, Base64.NO_WRAP)
            return decodedBytes
        }

        fun encodeB64(data: ByteArray): String {
            val base64Encoded = Base64.encodeToString(data, Base64.NO_WRAP)
            return base64Encoded
//            return base64Encoded.replace("\\s".toRegex(), "")
        }
    }
}