package org.fmm.pocqr.dto

import kotlinx.serialization.Serializable

@Serializable
data class QREncryptedData (
    val qrSignedData: QRSignedData,
    val totpSeed:String
){
}