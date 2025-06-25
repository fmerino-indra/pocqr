package org.fmm.pocqr.ui.management.adapterold

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import org.fmm.pocqr.databinding.ItemEntryBinding
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ManagementViewHolder(view: View): RecyclerView.ViewHolder(view) {
    private val binding = ItemEntryBinding.bind(view)

    fun render(alias: String, entry: KeyStore.Entry) {
        binding.keyName.text = alias
        if (entry is KeyStore.PrivateKeyEntry) {
            val privateKeyEntry = entry as KeyStore.PrivateKeyEntry
            binding.keyType.text = privateKeyEntry.certificate.type
            binding.keyType.text = "Asymmetric Key"

//            binding.creationDate.text = formatDate(privateKeyEntry.creationDate)
            val privateKey = entry.privateKey
            val publicKey = entry.certificate.publicKey

            binding.algorithm.text = privateKey.algorithm
            binding.kSize.text = getKeySize(publicKey).toString()


            // Solo para API 23+ (Android 6.0 Marshmallow)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    val keyFactory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
                    binding.authenticationRequired.text = keyInfo.isUserAuthenticationRequired.toString()

                    if (keyInfo.isUserAuthenticationRequired) {
                        val authDuration = keyInfo.userAuthenticationValidityDurationSeconds
                        if (authDuration == 0) {
                            binding.duration.text = "Time: Always"
                        } else {
                            binding.duration.text = "Time: $authDuration sec"
                        }

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) { // AUTH_BIOMETRIC_STRONG etc. desde API 30
                            val authenticators = keyInfo.userAuthenticationType
                            val authType = when {
                                authenticators and KeyProperties.AUTH_BIOMETRIC_STRONG != 0 -> "Biométrica Fuerte"
                                //authenticators and KeyProperties.AUTH_BIOMETRIC_WEAK != 0 ->
//                                    "Biométrica Débil"
                                authenticators and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0 -> "Credencial Dispositivo"
                                else -> "Desconocido"
                            }
                            binding.userAuthenticationType.text = authType
                        }
                    }
                    //keyDetails.append("Hardware Seguro: ").append(keyInfo.isInsideSecureHardware).append("\n")

                    binding.purposes.text = parsePurposes(keyInfo.purposes)
                } catch (e: Exception) {
                    Log.e(
                        "ManagementViewHolder", "Error getting KeyInfo for alias $alias: ${
                            e
                                .message
                        }", e
                    )
                }
            }
        }
/*
        } else if (entry is SecretKeyEntry) {
            keyDetails.append("Tipo: Clave Secreta\n")
            keyDetails.append("Fecha Creación: ")
                .append(formatDate(entry.creationDate)).append("\n")
            keyDetails.append("Algoritmo: ").append(entry.secretKey.algorithm).append("\n")
            keyDetails.append("Tamaño: ").append(getKeySize(entry.secretKey)).append(" bits\n")
            // Las claves secretas también pueden tener KeyInfo, pero su uso es menos común en este contexto.
        } else if (entry is KeyStore.TrustedCertificateEntry) {
            keyDetails.append("Tipo: Certificado de Confianza\n")
            keyDetails.append("Fecha Creación: ")
                .append(formatDate(entry.creationDate)).append("\n")
            keyDetails.append("Sujeto: ").append(entry.certificate.subjectX500Principal.name).append("\n")
        } else {
            keyDetails.append("Tipo: Desconocido\n")
        }
*/
    }
    private fun formatDate(date: Date?): String {
        return date?.let {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(it)
        } ?: "N/A"
    }
    private fun parsePurposes(purposes: Int): String {
        val list = mutableListOf<String>()
        if (purposes and KeyProperties.PURPOSE_ENCRYPT != 0) list.add("Cifrar")
        if (purposes and KeyProperties.PURPOSE_DECRYPT != 0) list.add("Descifrar")
        if (purposes and KeyProperties.PURPOSE_SIGN != 0) list.add("Firmar")
        if (purposes and KeyProperties.PURPOSE_VERIFY != 0) list.add("Verificar")
        if (purposes and KeyProperties.PURPOSE_WRAP_KEY != 0) list.add("Envolver Clave")
        return list.joinToString(", ")
    }
    private fun getKeySize(key: java.security.Key): Int {
        // Para claves RSA, el tamaño se puede inferir del módulo público
        // Para claves simétricas, es el tamaño del material de la clave
        return try {
            when (key.algorithm) {
                KeyProperties.KEY_ALGORITHM_RSA -> {
                    if (key is PublicKey) {
                        (key as java.security.interfaces.RSAPublicKey).modulus.bitLength()
                    } else {
                        key.encoded?.size?.times(8) ?: 0
                    }
                }
                KeyProperties.KEY_ALGORITHM_AES -> key.encoded?.size?.times(8) ?: 0
                else -> key.encoded?.size?.times(8) ?: 0 // Intento genérico
            }
        } catch (e: Exception) {
            Log.w("ManagementViewHolder", "Could not determine key size for ${key.algorithm}: ${e
                .message}")
            0
        }
    }

}