package org.fmm.pocqr.security.crypto.util

import android.content.Context
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.util.concurrent.ConcurrentHashMap

/* No vale porque siempre usa el mismo nombre de archivo. Quiero más flexibilidad
// Extensión para acceder al DataStore de preferencias encriptadas
val Context.encryptedPreferencesDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "my_encrypted_prefs", // Nombre del archivo del DataStore
    corruptionHandler = ReplaceFileCorruptionHandler {
        // Manejo de corrupción: simplemente reemplaza el archivo con preferencias vacías
        // Puedes implementar una lógica más robusta si es necesario
        emptyPreferences()
    },
    scope = CoroutineScope(Dispatchers.IO + SupervisorJob()) // Ámbito para las operaciones asíncronas
)

 */

// Paso 1: Crea un objeto o una clase de factoría para DataStore
// Esto asegura que para cada 'fileName', solo haya UNA instancia de DataStore.
private object FMMDataStoreFactory {
    private val instances: ConcurrentHashMap<String, DataStore<Preferences>> = ConcurrentHashMap()

    /**
     * Similar a "by  preferencesDataStore(...) En PreferenceDataStoreDelegate
     */
    fun getEncryptedPreferencesDataStore(context: Context, fileName: String): DataStore<Preferences> {
        return instances.computeIfAbsent(fileName) {
            PreferenceDataStoreFactory.create(
                corruptionHandler = ReplaceFileCorruptionHandler {
                    emptyPreferences()
                },
                scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
                // Aquí se especifica cómo obtener el archivo para este DataStore
                produceFile = {
                    // preferencesDataStoreFile es una función de extensión de Context
                    // que sí existe y es la forma recomendada para obtener la ruta del archivo
                    // para un Preferences DataStore.
                    context.preferencesDataStoreFile(fileName)
                }
            )
        }
    }
}


class EncryptedDataStoreManager(private val context: Context, private val
prefsDataStoreName:String) {

    private val preferenceDataStore = FMMDataStoreFactory.getEncryptedPreferencesDataStore(context,
        prefsDataStoreName)

    private val encryptionUtil = EncryptionUtil()
/*
    private suspend fun encryptString(data: String): String {
        val secretKey = AndroidKeystoreUtil.getSecretKey() // Puede lanzar UserNotAuthenticatedException
        val encryptedBytes = EncryptionUtil.encryptByteArray(data.toByteArray(), secretKey)
        return encryptedBytes
    }
 */

    private suspend fun encryptValue(data: String): String {
        val secretKey = AndroidKeystoreUtil.getSecretKey() // Puede lanzar UserNotAuthenticatedException
        val encryptedBytes = encryptionUtil.encryptByteArray(data.toByteArray(), secretKey)
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    private suspend fun decryptString(encryptedData: String): String {
        val secretKey = AndroidKeystoreUtil.getSecretKey() // Puede lanzar UserNotAuthenticatedException
        val decryptedBytes = encryptionUtil.decryptByteArray(encryptedData, secretKey)
        return String(decryptedBytes, Charsets.UTF_8)
    }

    // Encrypt & decrypt Boolean
/*
    private suspend fun encryptBoolean(data: Boolean): String {
        return encryptString(data.toString())
    }
*/
    private suspend fun encryptValue(data: Boolean): String {
        return encryptValue(data.toString())
    }
    private suspend fun decryptBoolean(encryptedData:String): Boolean {
        return decryptString(encryptedData).toBooleanStrict()
    }

    // Encrypt & decrypt Int
/*
    private suspend fun encryptInt(data: Int): String {
        return encryptString(data.toString())
    }
*/
    private suspend fun encryptValue(data: Int): String {
        return encryptValue(data.toString())
    }
    private suspend fun decryptInt(encryptedData:String): Int {
        return decryptString(encryptedData).toInt()
    }

    // Encrypt & decrypt Long
/*
    private suspend fun encryptLong(data:Long): String {
        return encryptString(data.toString())
    }
*/
    private suspend fun encryptValue(data: Long): String {
        return encryptValue(data.toString())
    }
    private suspend fun decryptLong(encryptedData:String): Long {
        return decryptString(encryptedData).toLong()
    }

    /**
     * API. Bloque que consume la lógica de negocio
     */
    private suspend fun saveEncryptedValueToDataStore(keyName: String, value: String) {
        val encryptedValue = encryptValue(value)
        preferenceDataStore.edit {preferences ->
            preferences[stringPreferencesKey(keyName)] = encryptedValue
        }
    }
    suspend fun saveEncryptedValue(keyName: String, value: String) {
        saveEncryptedValueToDataStore(keyName,value)
    }
    suspend fun saveEncryptedValue(keyName: String, value: Boolean) {
        saveEncryptedValueToDataStore(keyName,value.toString())
    }
    suspend fun saveEncryptedValue(keyName: String, value: Int) {
        saveEncryptedValueToDataStore(keyName,value.toString())
    }
    suspend fun saveEncryptedValue(keyName: String, value: Long) {
        saveEncryptedValueToDataStore(keyName,value.toString())
    }

    private suspend fun getEncryptedValueFromDataStore(keyName:String): String?  {
        return preferenceDataStore.data.map {
            preferences -> preferences[stringPreferencesKey(keyName)]
        }.first()
    }

    suspend fun getDecryptedString(keyName: String): String? {
        val encryptedValue =getEncryptedValueFromDataStore(keyName)
        return encryptedValue?.let { decryptString(it) }
    }
    suspend fun getDecryptedBoolean(keyName: String): Boolean? {
        val encryptedValue =getEncryptedValueFromDataStore(keyName)
        return encryptedValue?.let { decryptBoolean(it) }
    }
    suspend fun getDecryptedInt(keyName: String): Int? {
        val encryptedValue =getEncryptedValueFromDataStore(keyName)
        return encryptedValue?.let { decryptInt(it) }
    }
    suspend fun getDecryptedLong(keyName: String): Long? {
        val encryptedValue =getEncryptedValueFromDataStore(keyName)
        return encryptedValue?.let { decryptLong(it) }
    }
}