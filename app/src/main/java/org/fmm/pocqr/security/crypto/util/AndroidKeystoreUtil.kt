package org.fmm.pocqr.security.crypto.util

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import org.fmm.pocqr.security.crypto.dto.AuthenticationCapabilitiesData
import org.fmm.pocqr.security.crypto.ui.DEVICE_AUTHENTICATION_FMM
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
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
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.KeySpec
import java.util.Enumeration
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AndroidKeystoreUtil {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val KEY_ALIAS_AES = "MasterKey-FMMP"
//    private const val KEY_PAIR_ALIAS_RSA = "MasterKeyPair-FMMP"
    const val KEY_PAIR_ALIAS_RSA = "MasterKeyPair-FMMP-V9"
    const val AES_LENGTH = 256

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
    fun getRsaPrivateKey(): PrivateKey? {
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
     * Return or generate a key pair with authentication
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        KeyPermanentlyInvalidatedException::class // Puede ocurrir si se cambia la biometría
    )
    fun getOrGenerateRsaKeyPairWithAuthentication(authenticatorCapabilitiesData: AuthenticationCapabilitiesData): KeyPair {

        if (getKeyStore().containsAlias(KEY_PAIR_ALIAS_RSA)) {
            val key = getKeyStore().getEntry(KEY_PAIR_ALIAS_RSA, null)
            return if (key is KeyStore.PrivateKeyEntry)
                KeyPair(key.certificate.publicKey, key.privateKey)
            else {
                generateRsaKeyPairWithAuthentication(authenticatorCapabilitiesData)
            }
        } else {
            return generateRsaKeyPairWithAuthentication(authenticatorCapabilitiesData)
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
    private fun generateRsaKeyPairWithAuthentication(authenticatorCapabilitiesData: AuthenticationCapabilitiesData): KeyPair {
        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE)

        val keyGenParameterSpecBuilder2 : KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(
            KEY_PAIR_ALIAS_RSA,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .let {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    it.setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(
                            0, authenticatorCapabilitiesData.getKeyPropertiesFromAuthenticators()
                        )
                } else if (authenticatorCapabilitiesData.biometricAuthenticators > 0) {
                    it.setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(-1)

                } else if (
                    (authenticatorCapabilitiesData.deviceAuthenticators
                            and DEVICE_AUTHENTICATION_FMM )
                    == DEVICE_AUTHENTICATION_FMM
                    ){
                    it.setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(20)
                } else {
                    throw RuntimeException("Debe habilitar algún método de autenticación")
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    it.setInvalidatedByBiometricEnrollment(true) // La clave se invalida si se
                }
                it
            }

/*
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyGenParameterSpecBuilder2.setIsStrongBoxBacked(true)
        }
*/

        keyGenerator.initialize(keyGenParameterSpecBuilder2.build())
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

    @SuppressLint("ObsoleteSdkInt")
    fun inspectKeyProtection(alias:String): KeyInfo? {
        try {
            if (!getKeyStore().containsAlias(alias)) {
                Log.w("AndroidKeystoreUtil", "The key with alias: '$alias' doesn't exist")
                return null
            }
            val entry = getKeyStore().getEntry(alias,null)
            if (entry == null) {
                Log.w("AndroidKeystoreUtil", "The key with alias: '$alias' doesn't exist")
                return null
            }
            val key = getKeyStore().getKey(alias, null)
            val keyFactory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val keySpec: KeySpec = if (key is PrivateKey) {
                keyFactory.getKeySpec(key, KeyInfo::class.java)
            } else if (key is SecretKey) {
                keyFactory.getKeySpec(key, KeyInfo::class.java)
            } else {
                Log.w("AndroidKeystoreUtil", "Key type not supported: ${key.javaClass.name}")
                return null
            }
            val keyInfo = keySpec as KeyInfo

            Log.d("KeyInspector", "--- Propiedades de la clave '$alias' ---")
            Log.d("KeyInspector", "Algoritmo: ${key.algorithm}")
            Log.d("KeyInspector", "Tamaño de clave: ${keyInfo.keySize} bits")
            Log.d("KeyInspector", "Origen: ${getOriginString(keyInfo.origin)}")
            Log.d("KeyInspector", "Reside en hardware seguro (TEE/SE): ${keyInfo.isInsideSecureHardware}")

            // **Propiedades de Autenticación**
            Log.d("KeyInspector", "Requiere autenticación de usuario: ${keyInfo.isUserAuthenticationRequired}")
            if (keyInfo.isUserAuthenticationRequired) {
                val validityDuration = keyInfo.userAuthenticationValidityDurationSeconds
                if (validityDuration == -1) {
                    Log.d("KeyInspector", "  -> Autenticación requerida para CADA uso.")
                } else if (validityDuration > 0) {
                    Log.d("KeyInspector", "  -> Autenticación válida por ${validityDuration} segundos.")
                } else {
                    Log.d("KeyInspector", "  -> Duración de autenticación no especificada o 0 (puede ser por defecto para 'cada uso').")
                }
                Log.d("KeyInspector", "  -> Autenticación forzada por hardware seguro: ${keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware}")
                Log.d("KeyInspector", "  -> Invalidada por enrolamiento biométrico/cambio de PIN: ${keyInfo.isInvalidatedByBiometricEnrollment}")

                // A partir de API 28 (Android P)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    Log.d("KeyInspector", "  -> Requiere presencia de usuario (confirmación física): ${keyInfo.isTrustedUserPresenceRequired}")
                    Log.d("KeyInspector", "  -> Requiere confirmación de usuario (ej. diálogo): ${keyInfo.isUserConfirmationRequired}")
                }
            }

            // Propiedades de validez de tiempo
            Log.d("KeyInspector", "Válida desde: ${keyInfo.keyValidityStart ?: "No restringido"}")
            Log.d("KeyInspector", "Válida hasta (signing/encryption): ${keyInfo.keyValidityForOriginationEnd ?: "No restringido"}")
            Log.d("KeyInspector", "Válida hasta (verification/decryption): ${keyInfo.keyValidityForConsumptionEnd ?: "No restringido"}")

            // Propósitos de la clave
            Log.d("KeyInspector", "Propósitos: ${getPurposesString(keyInfo.purposes)}")

            // Para ver propiedades específicas del algoritmo (opcional)
            if (key is RSAKey) {
                Log.d("KeyInspector", "Es clave RSA. Módulo: ${key.modulus.bitLength()} bits")
            } else if (key is ECKey) {
                Log.d("KeyInspector", "Es clave EC. Curva: ${key.params.curve.field.fieldSize} bits")
            }
            return keyInfo

        } catch (e: Exception) {
            Log.e("KeyInspector", "Error al inspeccionar la clave '$alias': ${e.message}", e)
        }
        return null
    }
//    private fun getOriginString(@KeyProperties.OriginEnum origin: Int): String {
    private fun getOriginString(origin: Int): String {
        return when (origin) {
            KeyProperties.ORIGIN_GENERATED -> "Generada en el dispositivo"
            KeyProperties.ORIGIN_IMPORTED -> "Importada al Keystore"
            KeyProperties.ORIGIN_UNKNOWN -> "Origen desconocido"
            KeyProperties.ORIGIN_SECURELY_IMPORTED -> "Importada de forma segura"
            else -> "Desconocido ($origin)"
        }
    }

//    private fun getPurposesString(@KeyProperties.PurposeEnum purposes: Int): String {
    private fun getPurposesString(purposes: Int): String {
        val list = mutableListOf<String>()
        if (purposes and KeyProperties.PURPOSE_ENCRYPT != 0) list.add("ENCRYPT")
        if (purposes and KeyProperties.PURPOSE_DECRYPT != 0) list.add("DECRYPT")
        if (purposes and KeyProperties.PURPOSE_SIGN != 0) list.add("SIGN")
        if (purposes and KeyProperties.PURPOSE_VERIFY != 0) list.add("VERIFY")
        if (purposes and KeyProperties.PURPOSE_WRAP_KEY != 0) list.add("WRAP_KEY")
        return if (list.isEmpty()) "Ninguno" else list.joinToString(", ")
    }

}