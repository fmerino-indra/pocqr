package org.fmm.pocqr.security.crypto.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AndroidKeystoreUtilV0 {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "MasterKey-FMMP"

    /**
     * Carga la instancia del KeyStore
     */
    private fun getKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null) // null si no se requiere contraseña para el Keystore
        }
    }

    /**
     * Genera o recupera una clave simétrica (AES) dek Keystore
     */
    fun getOrCreateSecretKey(): SecretKey {
        val keyStore = getKeyStore()

        // Verificar si la clave ya existe
        if (keyStore.containsAlias(KEY_ALIAS)) {
            try {
                return keyStore.getKey(KEY_ALIAS, null) as SecretKey
            } catch (e: UnrecoverableKeyException) {
                // La clave podría no ser recuperable (ej. si requiere autenticación)
                // En este caso, podrías necesitar regenerarla o pedir autenticación.
                // Por simplicidad, aquí la regeneramos si no se puede recuperar.
                Log.e("AndroidKeystoreUtil",
                    e.message ?: ("Excepción UnrecoverableKeyException al" +
                            " recuperar la clave")
                )
                try {
                    keyStore.deleteEntry(KEY_ALIAS)
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

    /**
     * Genera una nueva clave simétrica (AES) en el Keystore
     */
    private fun generateNewSecretKey(): SecretKey {
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // GCM no usa PADDING
                .setKeySize(256) // Tamaño de clave (256 bits para AES)
                // Opcional: Para requerir autenticación del usuario (ej. huella digital)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(300) // 5 minutos sin re-autenticación
                // Opcional: Invalidar la clave si se registra una nueva huella digital (API 24+)
                .setInvalidatedByBiometricEnrollment(true)
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
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
    }

}