package org.fmm.pocqr.security.crypto

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecureStorage (private val context: Context, private val
securePrefsName:String) {
    private val keyAlias = "secureTokenKey"
    private val cipherName = "AES/GCM/NoPadding"

    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val masterKey: MasterKey by lazy {
        var keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
//            .setUserAuthenticationRequired(true)
//            .setUserAuthenticationValidityDurationSeconds(60)
        // KeyProperties. -> >= API 30, lo dejo de momento.
            //.setUserAuthenticationParameters(60, KeyProperties.)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
//            keyGenParameterSpecBuilder.setIsStrongBoxBacked(true)
        }


        /*
         La llamada a build, no crea siempre una nueva MasterKey. Si no existe la cre,
         si existe la devuelve.
         */
        MasterKey.Builder(context, keyAlias)
            .setKeyGenParameterSpec(keyGenParameterSpecBuilder.build())
            .build()
    }

//    private val newMasterKey: SecretKey {
//    }

    // Get or create the encryption key from Keystore
    private fun getOrCreateKey(): SecretKey {
        return (keystore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: run {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore")
                keyGenerator.init(
                    KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or
                            KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
                )
                keyGenerator.generateKey()
            }
    }

    private fun getEncryptedPrefs():SharedPreferences {
        return EncryptedSharedPreferences.create(
            context,
            securePrefsName,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    // Encrypt & decrypt byteArray
    private fun encryptByteArray(value:ByteArray):String {
        val cipher = Cipher.getInstance(cipherName).apply {
            init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        }

        val iv = cipher.iv
        val encryption = cipher.doFinal(value)

        // CombiNar IV + datos cifrados para el almacenamiento
        val ivAndData = iv + encryption
        return ivAndData.joinToString ( "," ) { it.toString() }
    }

    // Decrypt a String
    private fun decryptByteArray (encryptedValue: String): ByteArray {
        val ivAndData = encryptedValue.split(",").map { it.toByte() }
        val iv = ivAndData.take(12).toByteArray()
        val encryptedData = ivAndData.drop(12).toByteArray()

        val cipher = Cipher.getInstance(cipherName).apply {
            val spec = GCMParameterSpec(128, iv)
            init(Cipher.DECRYPT_MODE, getOrCreateKey(), spec)
        }
        return cipher.doFinal(encryptedData)
    }

    // Encrypt & decrypt String
    private fun encryptString(value:String):String {
        return encryptByteArray(value.toByteArray())
    }
    private fun encryptValue(value:String):String {
        return encryptString(value.toString())
    }
    private fun decryptString (encryptedValue: String): String {
        return String(decryptByteArray(encryptedValue))
    }

    // Encrypt & decrypt Boolean
    private fun encryptBoolean(value:Boolean):String {
        return encryptByteArray(value.toString().toByteArray())
    }
    private fun encryptValue(value:Boolean):String {
        return encryptString(value.toString())
    }
    private fun decryptBoolean (encryptedValue: String): Boolean {
        return decryptString(encryptedValue).toBoolean()
    }

    // Encrypt & decrypt Int
    private fun encryptInt(value:Int):String {
        return encryptString(value.toString())
    }
    private fun encryptValue(value:Int):String {
        return encryptString(value.toString())
    }
    private fun decryptInt (encryptedValue: String): Int {
        return decryptString(encryptedValue).toInt()
    }

    // Encrypt & decrypt Long
    private fun encryptLong(value:Long):String {
        return encryptString(value.toString())
    }
    private fun encryptValue(value:Long):String {
        return encryptString(value.toString())
    }
    private fun decryptLong (encryptedValue: String): Long {
        return decryptString(encryptedValue).toLong()
    }



    private fun saveEncryptedValueToPreference(key:String, encryptedValue:String) {
        val encryptedPrefs = getEncryptedPrefs()
        encryptedPrefs.edit().putString(key,encryptedValue).apply()
    }

    private fun getEncryptedValueFromPreferences(key:String): String? {
        val encryptedPrefs = getEncryptedPrefs()
        return encryptedPrefs.getString(key, null)
    }
    /**
     * Encrypt and save String value to EncryptedSharedPreferences
     */
    fun saveEncryptedString(key: String, value: String) {
        val encryptedValue = encryptString(value)
        this.saveEncryptedValueToPreference(key, encryptedValue)
    }

    /**
     * Retrieve and decrypt String value with key from EncryptedSharedPreferences
     */
    fun getEncryptedString(key:String): String? {
        val encryptedValue = getEncryptedValueFromPreferences(key)
        return encryptedValue?.let { decryptString(it)}
    }

    /**
     * Encrypt and save Boolean value to EncryptedSharedPreferences
     */
    fun saveEncryptedBoolean(key: String, value: Boolean) {
        val encryptedValue = encryptBoolean(value)
        this.saveEncryptedValueToPreference(key, encryptedValue)
    }

    /**
     * Retrieve and decrypt Boolean value with <code>key</code> from EncryptedSharedPreferences
     */
    fun getEncryptedBoolean(key:String): Boolean? {
//        val encryptedPrefs = getEncryptedPrefs()
//        val encryptedValue = encryptedPrefs.getString(key, null)
        val encryptedValue = getEncryptedValueFromPreferences(key)
        return encryptedValue?.let { decryptBoolean(it)}
    }

    /**
     * Encrypt and save Int value to EncryptedSharedPreferences
     */
    fun saveEncryptedInt(key: String, value: Int) {
        val encryptedValue = encryptInt(value)
        this.saveEncryptedValueToPreference(key, encryptedValue)
    }

    /**
     * Retrieve and decrypt Int value with <code>key</code> from EncryptedSharedPreferences
     */
    fun getEncryptedInt(key:String): Int? {
//        val encryptedPrefs = getEncryptedPrefs()
//        val encryptedValue = encryptedPrefs.getString(key, null)
        val encryptedValue = getEncryptedValueFromPreferences(key)
        return encryptedValue?.let { decryptInt(it)}
    }

    /**
     * Encrypt and save Long value to EncryptedSharedPreferences
     */
    fun saveEncryptedLong(key: String, value: Long) {
        val encryptedValue = encryptLong(value)
        this.saveEncryptedValueToPreference(key, encryptedValue)
    }

    /**
     * Retrieve and decrypt Long value with <code>key</code> from EncryptedSharedPreferences
     */
    fun getEncryptedLong(key:String): Long? {
        val encryptedValue = getEncryptedValueFromPreferences(key)
        return encryptedValue?.let { decryptLong(it)}
    }

    fun deleteEncryptedValue(key:String) {
        val encryptedPrefs = getEncryptedPrefs()
        encryptedPrefs.edit().remove(key).apply()
    }

    fun clearAll() {
        val encryptedPrefs=getEncryptedPrefs()
        encryptedPrefs.edit().clear().apply()
    }

/*
From com.auth0.android.authentication.storage.Storage

    override fun remove(name: String) {
        this.deleteEncryptedValue(name)
    }

    override fun retrieveBoolean(name: String): Boolean? {
        return this.getEncryptedBoolean(name)
    }

    override fun retrieveInteger(name: String): Int? {
        return this.getEncryptedInt(name)
    }

    override fun retrieveLong(name: String): Long? {
        return this.getEncryptedLong(name)
    }

    override fun retrieveString(name: String): String? {
        return this.getEncryptedString(name)
    }

    override fun store(name: String, value: Boolean?) {
        this.saveEncryptedBoolean(name, value?:false)
    }

    override fun store(name: String, value: Int?) {
        this.saveEncryptedInt(name, value?:0)
    }

    override fun store(name: String, value: Long?) {
        this.saveEncryptedLong(name, value?:0)
    }

    override fun store(name: String, value: String?) {
        this.saveEncryptedString(name, value?:"")
    }

 */
}