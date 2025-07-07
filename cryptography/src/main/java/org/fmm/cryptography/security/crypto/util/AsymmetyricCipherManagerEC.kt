package org.fmm.pocqr.security.crypto.util

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyAgreement
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Lo hago aparte porque el propósito: KeyProperties.PURPOSE_AGREE_KEY exige API 31
 */
class AsymmetyricCipherManagerEC(private val alias:String) {
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val EC_ALGORITHM = "EC" // Elliptic Curve
    private val ECDH_KEY_AGREEMENT_ALGORITHM = "ECDH"

    // Simétrico para cifrar / descifrar los datos una vez que la clave ECDH ha sido derivada
    private val AES_ALGORITHM = "AES"
    private val AES_CIPHER_MODE = "AES/GCM/NoPadding" // AES en modo GCM con No Padding
    private val GCM_IV_LENGTH = 12 // bytes para GCM
    private val GCM_TAG_LENGH = 16 // bytes para GCM (128 bits)

    private lateinit var keyStore: KeyStore

    init {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: CertificateException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    /**
     * Genera un par de claves EC (pública y privada) y las almacena en el Android Keystore.
     * Si las claves ya existen para el alias dado, no se regeneran.
     */
    @RequiresApi(Build.VERSION_CODES.S)
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        KeyStoreException::class,
        CertificateException::class,
        IOException::class
    )
    fun generateKeyPair(): KeyPair? {
        if (!keyStore.containsAlias(alias)) {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                EC_ALGORITHM,
                ANDROID_KEYSTORE
            )
            keyPairGenerator.initialize(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_AGREE_KEY // Propósito para ECDH
                )
                    .setDigests(KeyProperties.DIGEST_SHA256) // Puedes especificar los digests necesarios
                    .setKeySize(256) // Tamaño de clave para EC (por ejemplo, 256 bits para secp256r1)
                    .build()
            )
            return keyPairGenerator.generateKeyPair()
        }
        return getKeyPair()
    }

    /**
     * Obtiene el par de claves EC del Android Keystore para el alias dado.
     *
     * @return El KeyPair si existe, o null si no se encuentra.
     */
    fun getKeyPair(): KeyPair? {
        try {
            val entry = keyStore.getEntry(alias, null)
            if (entry is KeyStore.PrivateKeyEntry) {
                // Para EC, certificate.publicKey no es necesariamente el KeyPair completo,
                // pero sí proporciona la clave pública asociada.
                return KeyPair(entry.certificate.publicKey, entry.privateKey)
            }
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: UnrecoverableEntryException) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * Realiza un intercambio de claves ECDH para derivar una clave secreta compartida.
     * La clave privada local (nuestra) se usa con la clave pública de la otra parte.
     *
     * @param privateKey Nuestra clave privada.
     * @param otherPublicKey La clave pública de la otra parte.
     * @return La clave secreta (SecretKey) derivada.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        InvalidKeyException::class
    )
    fun deriveSharedSecret(privateKey: PrivateKey, otherPublicKey: PublicKey): SecretKey {
        val keyAgreement = KeyAgreement.getInstance(ECDH_KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        // La clave derivada puede ser usada directamente como clave AES,
        // o pasada por una función de derivación de clave (KDF) para mayor seguridad.
        // Para este ejemplo, la usaremos directamente.
        return SecretKeySpec(keyAgreement.generateSecret(), AES_ALGORITHM)
    }

    /**
     * Cifra datos utilizando una clave simétrica derivada (ej. AES).
     *
     * @param plainText Los datos a cifrar.
     * @param secretKey La clave simétrica derivada.
     * @return Los datos cifrados incluyendo el IV (Initialization Vector) y la etiqueta GCM.
     * El formato es: [IV (12 bytes)] + [Datos Cifrados] + [Etiqueta GCM (16 bytes)]
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class
    )
    fun encrypt(plainText: ByteArray, secretKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(AES_CIPHER_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedData = cipher.doFinal(plainText)
        val iv = cipher.iv ?: throw IllegalStateException("IV no disponible después de cifrar")
        return iv + encryptedData
    }

    /**
     * Descifra datos utilizando una clave simétrica derivada (ej. AES).
     *
     * @param encryptedDataWithIv Los datos cifrados que incluyen el IV al principio.
     * @param secretKey La clave simétrica derivada.
     * @return Los datos descifrados como ByteArray.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class,
        InvalidAlgorithmParameterException::class
    )
    fun decrypt(encryptedDataWithIv: ByteArray, secretKey: SecretKey): ByteArray {
        // Extraer IV
        val iv = encryptedDataWithIv.copyOfRange(0, GCM_IV_LENGTH)
        val encryptedData = encryptedDataWithIv.copyOfRange(GCM_IV_LENGTH, encryptedDataWithIv.size)

        val cipher = Cipher.getInstance(AES_CIPHER_MODE)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        return cipher.doFinal(encryptedData)
    }

    /**
     * Elimina el par de claves EC del Android Keystore.
     */
    fun deleteKeyPair() {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
    }
}