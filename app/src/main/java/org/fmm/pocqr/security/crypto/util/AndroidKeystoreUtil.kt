package org.fmm.pocqr.security.crypto.util

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.util.Enumeration
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AndroidKeystoreUtil {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_AES = "MasterKey-FMMP"
//    private const val KEY_PAIR_ALIAS_RSA = "MasterKeyPair-FMMP"
    private const val KEY_PAIR_ALIAS_RSA = "MasterKeyPair-FMMP-V2"
    private const val AES_LENGTH = 256

    const val AUTH_VALIDITY_SECONDS = 30

//    private val KEY_ALIAS_RSA = "my_rsa_key_with_biometric"
//    private val KEY_ALIAS_AES = "my_aes_key_with_biometric" // Aunque AES se usaría
// efímeramente, es un ejemplo

    /**
     * Carga la instancia del KeyStore
     */
    private fun getKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null) // null si no se requiere contraseña para el Keystore
        }
    }

    fun getAlias(): Enumeration<String> {
        return getKeyStore().aliases()
    }

    fun getEntry(alias: String): KeyStore.Entry {
        return getKeyStore().getEntry(alias,null)
    }

// Simétricos
    /**
     * Devuelve la clave asumiendo que ya fue generada con autenticación requerida
     * Si falla, porque la autenticación biométrica ha fallado, debe propagar
     * la excepción hasta el UI y pedir de nuevo la autenticación
     */
    fun getSecretKey(): SecretKey {
        val keyStore = getKeyStore()
        return keyStore.getKey(KEY_ALIAS_AES, null) as SecretKey
    }

    fun generateSecretKeyIfNecessary(context: Context) {
        val keyStore = getKeyStore()
        if (!keyStore.containsAlias(KEY_ALIAS_AES)) {
            generateNewSecretKey()
        }
    }

    /**
     *
     * AES GCM No Padding 256
     *
     */
    fun generateEphemeralKey(): SecretKey {
/*
        val keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM)
        keyGenerator.init(AES_LENGTH) // Clave AES de 256 bits
        val symmetricKey = keyGenerator.generateKey()
        return symmetricKey
*/
        return generateNewSecretKey("NONE", "NONE")
    }

// Asimétricos

    /**
     * Intenta obtener la clave privada RSA del KeyStore.
     * Si requiere autenticación, prepara un Cipher para ser usado con BiometricPrompt.
     */
    @Throws(
        UnrecoverableKeyException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        IOException::class,
        CertificateException::class
    )
    fun getRsaPrivateKeyForBiometricUse(): PrivateKey? {
        val aliases = getKeyStore().aliases()
        aliases.toList().stream().forEach {
            Log.d("AndroidKeystoreUtil", "Alias: $it")
        }
        return getKeyStore().getKey(KEY_PAIR_ALIAS_RSA, null) as? PrivateKey
    }

    /**
     * Intenta obtener la clave pública RSA del KeyStore.
     * La clave pública no requiere autenticación.
     */
    @Throws(
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        UnrecoverableKeyException::class
    )
    fun getRsaPublicKey(): PublicKey? {
        val entry = getKeyStore().getEntry(KEY_PAIR_ALIAS_RSA, null)
        return if (entry is KeyStore.PrivateKeyEntry) {
            entry.certificate.publicKey
        } else {
            null
        }
    }

    /**
     * Genera un par de claves RSA en el Android KeyStore que requieren autenticación del usuario.
     * La autenticación es necesaria para cada uso de la clave privada.
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        KeyPermanentlyInvalidatedException::class // Puede ocurrir si se cambia la biometría
    )
    @SuppressLint("ObsoleteSdkInt")
    fun generateRsaKeyPairWithBiometricAuthentication(): KeyPair {
        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE)
        val keyGenParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            KeyGenParameterSpec.Builder(
                KEY_PAIR_ALIAS_RSA,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0,KeyProperties.AUTH_DEVICE_CREDENTIAL or
                        KeyProperties.AUTH_BIOMETRIC_STRONG)
//                .setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG )
        } else {
            KeyGenParameterSpec.Builder(
                KEY_PAIR_ALIAS_RSA,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
        }
        //.setUserAuthenticationValidityDurationSeconds(-1) // Siempre que se use requiere
        // autenticación
        // Opcional: Requiere que el cifrado sea por hardware (enclaves seguros) si está disponible
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            keyGenParameterSpec.setInvalidatedByBiometricEnrollment(true) // La clave se invalida si se añaden/eliminan huellas
        }
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
//            keyGenParameterSpec.setIsStrongBoxBacked(true) // Prioriza StrongBox (hardware más
//    // seguro)
//        }

        keyGenerator.initialize(keyGenParameterSpec.build())
        return keyGenerator.generateKeyPair()
    }

    /**
     * Genera una clave AES en el Android KeyStore que requiere autenticación del usuario.
     * Útil si quisieras proteger una clave AES de larga duración, aunque para cifrado híbrido
     * la clave AES es efímera. Se incluye como ejemplo.
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class
    )
    fun generateAesKeyWithBiometricAuthentication(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_AES,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(true) // <-- ¡Esta es la clave!
            .setUserAuthenticationValidityDurationSeconds(30) // Válida por 30 segundos tras autenticación

        keyGenerator.init(keyGenParameterSpec.build())
        return keyGenerator.generateKey()
    }

    /**
     * Genera una nueva clave simétrica (AES) en el Keystore
     * AES GCM No Padding 256
     */
    private fun generateNewSecretKey(provider: String = ANDROID_KEYSTORE, alias: String = KEY_ALIAS_AES):
            SecretKey {
        try {
            val keyGenerator = if (provider == "NONE")
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
            else
                KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE
                )
// @TODO Revisar si cuando no se almacena en KeyStore necesita un alias o qué pasa
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS_AES,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // GCM no usa PADDING
                .setKeySize(AES_LENGTH) // Tamaño de clave (256 bits para AES)
                // Opcional: Para requerir autenticación del usuario (ej. huella digital)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS) // 5 minutos sin
                // re-autenticación
                // Opcional: Invalidar la clave si se registra una nueva huella digital (API 24+)
                .setInvalidatedByBiometricEnrollment(true) // API 24+
                // Opcional: Almacenar en StrongBox si está disponible (API 28+)
                .setIsStrongBoxBacked(true)
                .build()
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey() // Esta clave se genera y se guarda en el Keystore
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Error al generar la clave: Algoritmo no encontrado.", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Error al generar la clave: Proveedor Keystore no encontrado.", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException("Error al generar la clave: Parámetros inválidos.", e)
        }
    }

    // Opcional: Eliminar la clave del Keystore
    fun deleteKey() {
        try {
            val keyStore = getKeyStore()
            if (keyStore.containsAlias(KEY_ALIAS_AES)) {
                keyStore.deleteEntry(KEY_ALIAS_AES)
            }
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
    }

//------------------------------------------------------------------------------------------//
    // Estos son antiguos, funcionan pero no permiten el flujo de la autenticación
    /**
     * Genera o recupera una clave simétrica (AES) del Keystore
     */
    fun getOrCreateSecretKey(): SecretKey {
        val keyStore = getKeyStore()

        // Verificar si la clave ya existe
        if (keyStore.containsAlias(KEY_ALIAS_AES)) {
            try {
                return keyStore.getKey(KEY_ALIAS_AES, null) as SecretKey
            } catch (e: UnrecoverableKeyException) {
                // La clave podría no ser recuperable (ej. si requiere autenticación)
                // En este caso, podrías necesitar regenerarla o pedir autenticación.
                // Por simplicidad, aquí la regeneramos si no se puede recuperar.
                Log.e("AndroidKeystoreUtil",
                    e.message ?: ("Excepción UnrecoverableKeyException al" +
                            " recuperar la clave")
                )
                try {
                    keyStore.deleteEntry(KEY_ALIAS_AES)
                } catch (deleteEx: KeyStoreException) {
                    Log.e("AndroidKeystoreUtil",
                        e.message ?: ("Excepción KeyStoreException al borrar la clave")
                    )
                }
                return generateNewSecretKey()
            }
        } else {
            return generateNewSecretKey()
        }
    }


}