package org.fmm.pocqr.security.crypto.ui

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.fmm.pocqr.R
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.security.crypto.util.AsymmetricRSAHybridCipherManager
import org.fmm.pocqr.security.crypto.util.NoPrivateKeyException
import java.security.Signature
import javax.crypto.Cipher

sealed class BiometricCryptoObject {
    data class CipherObject(val cipher: Cipher): BiometricCryptoObject()
    data class SignatureObject(val signature: Signature): BiometricCryptoObject()
    object None: BiometricCryptoObject() // Para cuando no se necesita
}
class BiometricPromptHelper(val activity: FragmentActivity) {

    private val executor = ContextCompat.getMainExecutor(activity)
    private val asymmetricRSACipherManager = AsymmetricRSAHybridCipherManager(
        context = activity.applicationContext
    )
    fun authenticateAndUseKey() {
        // Se instancia el Prompt de biometría
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object: BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onAuthError("Authentication error: $errString ($errorCode)")
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    try {
                        result.cryptoObject?.let { cryptoObject ->
                            // Aquí se usa el objeto Cipher/Signature que ha sido inicializado
                            // con la clave protegida por biometría
                            cryptoObject.cipher?.let {cipher ->
                                cipherOperation?.invoke(cipher)
                            }
                        } ?: run { {
                            Log.d("BiometricPromptHelper", "CryptoObject is null after authentication" +
                                    ". The key is not protected or bad configuration")
                        } }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }
            }
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.biometrics_title))
            .setSubtitle(activity.getString(R.string.biometrics_subtitle))
            .setNegativeButtonText(activity.getString(R.string.cancel))
            .build()

        // Aquí es donde intentamos inicializar el Cipher/Signature *antes* de la autenticación.
        // Si la clave requiere autenticación, esto fallará con UserNotAuthenticatedException.
        // BiometricPrompt lo detectará y pedirá la autenticación.
        try {
            // Ejemplo de uso para cifrado (adaptar para tu caso de uso)
            val privateKey = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
            if (privateKey != null) {
                // @TODO Integrar con AsymmetricRSAHybridCipherManager
                // Preparamos el Cipher para RSA (para
                // descifrar la clave AES en un esquema híbrido)
                val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")

                // *** PUNTO CLAVE: Aquí intentamos INICIALIZAR el Cipher con la clave privada. ***
                // Si la clave requiere autenticación y el usuario no está autenticado,
                // esta línea lanzará UserNotAuthenticatedException.
                cipher.init(Cipher.DECRYPT_MODE, privateKey)

                // Si la línea anterior NO lanza la excepción (ej. clave no requiere biometría o usuario ya autenticado
                // dentro del período de validez), entonces el Cipher ya está listo para usar.
                // Aún así, llamamos a authenticate para mostrar el prompt (aunque podría no ser estrictamente necesario si ya está autenticado)
                // y para manejar el caso de CryptoObject nulo si la clave no requería autenticación.
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            } else {
                println("La clave privada RSA no está disponible en el KeyStore.")
                // Posiblemente generar la clave si no existe
            }
        } catch (e: UserNotAuthenticatedException) {
/*
        // *** CAPTURAMOS LA EXCEPCIÓN AQUÍ ***
        println("La clave requiere autenticación. Iniciando prompt biométrico.")
        // Y luego, INICIAMOS la autenticación. El BiometricPrompt ahora sabe que
        // necesita "desbloquear" el 'cipher' que le pasamos.
        // La autenticación será exitosa cuando el usuario se autentique y el sistema
        // pueda inicializar el 'cipher' con la clave.
        val privateKey = getRsaPrivateKeyForBiometricUse() // Re-obtenemos la clave para el CryptoObject
        if (privateKey != null) {
             val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
             // IMPORTANTE: NO hacemos cipher.init(..., privateKey) aquí directamente.
             // El CryptoObject y el sistema Android se encargarán de la inicialización
             // una vez que la autenticación sea exitosa.
             biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } else {
             // Manejo de error si la clave desapareció mágicamente
        }
*/

            // *** ESTE ES EL ESCENARIO ESPERADO CUANDO LA CLAVE REQUIERE BIOMETRÍA ***
            println("La clave requiere autenticación. Lanzando prompt biométrico.")
            // Aquí, inicializamos un NUEVO Cipher/Signature (sin la clave privada directamente),
            // y se lo pasamos al CryptoObject. El sistema intentará inicializarlo
            // con la clave protegida DESPUÉS de la autenticación exitosa.
            try {
                val cipherToAuthenticate = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
                // No llamamos a init(privateKey) aquí, porque la clave está protegida.
                // El sistema lo hará internamente si la autenticación es exitosa.
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipherToAuthenticate))
            } catch (e: Exception) {
                println("Error al preparar CryptoObject para UserNotAuthenticatedException: ${e.message}")
                e.printStackTrace()
            }


        } catch (e: KeyPermanentlyInvalidatedException) {
            println("La clave ha sido invalidada (ej. por cambio de biometría). Generar nueva clave.")
            // Deberías borrar la clave existente y generar una nueva
        } catch (e: Exception) {
            println("Error al inicializar el Cipher para la autenticación: ${e.message}")
            e.printStackTrace()
        }
    }

    fun signData(dataToSign: ByteArray,  callback: (ByteArray?) ->  Unit) {
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object: BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onAuthError("Authentication error: $errString ($errorCode)")
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    try {
                        result.cryptoObject?.signature?.let { signature ->
                            signature.update(dataToSign)
                            val digitalSignature = signature.sign()
                            callback(digitalSignature)
                        } ?: run { {
                            Log.d("BiometricPromptHelper", "CryptoObject is null after authentication" +
                                    ". The key is not protected or bad configuration")
                            callback(null)
                        } }
                    } catch (e: Exception) {
                        e.printStackTrace()
                        callback(null)
                    }
                }
            }
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.biometrics_signature_title))
            .setSubtitle(activity.getString(R.string.biometrics_signature_subtitle))
            .setNegativeButtonText(activity.getString(R.string.cancel))
            .build()
        try {
            val sign = asymmetricRSACipherManager.signData(dataToSign)
            callback(sign)
//            biometricPrompt.authenticate(promptInfo)
/* Otra forma
            val privateKey = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()
            if (privateKey == null) {
                Log.e("BiometricPromptHelpter", "No RSA private key prepared to sign")
                callback(null)
                return
            }
*/
            // Aquí intentamos inicializar el Signature. Si la clave es biométrica y no autenticada,
            // se lanzará UserNotAuthenticatedException.
/*
            val signature = Signature.getInstance("SHA256withRSA/PSS")
            signature.initSign(privateKey)
*/

            // Si llegamos aquí, la inicialización fue exitosa.
            // Para forzar el prompt, podemos pasarlo.
//            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
        } catch (npke: NoPrivateKeyException) {
            // Hacer algo con esto
        } catch (e: UserNotAuthenticatedException) {
            println("La clave para firma requiere autenticación. Iniciando prompt biométrico.")
            try {
/*
                val signatureToAuthenticate = Signature.getInstance("SHA256withRSA/PSS")
                // No llamamos a init(privateKey) aquí. El sistema lo hará tras la autenticación.
                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(signatureToAuthenticate))
*/
                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(asymmetricRSACipherManager.signature))

            } catch (e: Exception) {
                println("Error al preparar CryptoObject para UserNotAuthenticatedException (firma): ${e.message}")
                e.printStackTrace()
                callback(null)
            }

        } catch (e: KeyPermanentlyInvalidatedException) {
            println("La clave de firma ha sido invalidada. Generar nueva clave.")
            callback(null)
        } catch (e: Exception) {
            println("Error al inicializar la firma para la autenticación: ${e.message}")
            e.printStackTrace()
            callback(null)
        }
    }
}