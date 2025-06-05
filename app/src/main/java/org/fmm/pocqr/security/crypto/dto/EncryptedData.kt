package org.fmm.pocqr.security.crypto.dto

private const val GCM_IV_LENGTH:Int = 12 // Longitud del IV para GCM en bytes

data class EncryptedData(

    val encryptedSymmetricKey: ByteArray,
//    val encryptedSymmetricKeyB64: String,
    val encryptedData: ByteArray,
//    val encryptedDataB64: String,
//    val iv: ByteArray,
//    val ivB64: String
    ) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedData

        if (!encryptedSymmetricKey.contentEquals(other.encryptedSymmetricKey)) return false
//        if (encryptedSymmetricKeyB64 != other.encryptedSymmetricKeyB64) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
//        if (encryptedDataB64 != other.encryptedDataB64) return false
//        if (!iv.contentEquals(other.iv)) return false
//        if (ivB64 != other.ivB64) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedSymmetricKey.contentHashCode()
//        result = 31 * result + encryptedSymmetricKeyB64.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
//        result = 31 * result + encryptedDataB64.hashCode()
//        result = 31 * result + iv.contentHashCode()
//        result = 31 * result + ivB64.hashCode()
        return result
    }

    fun getIv(): ByteArray {
//        val combined = Base64.decode(encryptedDataBase64, Base64.DEFAULT)
        return this.encryptedData.copyOfRange(0, GCM_IV_LENGTH)
    }

}