package org.fmm.pocqr.security.crypto

import android.content.Context
import org.fmm.pocqr.R
import javax.inject.Inject

class EncryptedPrefsStorage @Inject constructor (context:Context) {
    private var secureStorage: SecureStorage = SecureStorage(context, context.getString(R.string
    .secure_prefs_name))

    fun saveString(key: String, value:String) {
        secureStorage.saveEncryptedString(key, value)
    }

    fun getString(key:String, default:String?=null):String? {
        return secureStorage.getEncryptedString(key)?:default
    }

    fun saveBoolean(key:String, value:Boolean) {
        secureStorage.saveEncryptedBoolean(key, value)
    }

    fun getBoolean(key:String, default:Boolean?=false):Boolean {
        return secureStorage.getEncryptedBoolean(key)?:default!!
    }

    fun deleteValue(key:String) {
        secureStorage.deleteEncryptedValue(key)
    }

    fun clear() {
        secureStorage.clearAll()
    }
/*
    override fun remove(name: String) {
        secureStorage.deleteEncryptedValue(name)
    }

    override fun retrieveBoolean(name: String): Boolean? {
        return secureStorage.getEncryptedBoolean(name)
    }

    override fun retrieveInteger(name: String): Int? {
        return secureStorage.getEncryptedInt(name)
    }

    override fun retrieveLong(name: String): Long? {
        return secureStorage.getEncryptedLong(name)
    }

    override fun retrieveString(name: String): String? {
        return secureStorage.getEncryptedString(name)
    }

    override fun store(name: String, value: Boolean?) {
        secureStorage.saveEncryptedBoolean(name, value?:false)
    }

    override fun store(name: String, value: Int?) {
        secureStorage.saveEncryptedInt(name, value?:0)
    }

    override fun store(name: String, value: Long?) {
        secureStorage.saveEncryptedLong(name, value?:0)
    }

    override fun store(name: String, value: String?) {
        secureStorage.saveEncryptedString(name, value?:"")
    }

 */

}