package org.fmm.pocqr.dto

import kotlinx.serialization.Serializable

@Serializable
data class QRSignedData (
    val data: QRData,
    val publicKey:String,
    val signature:String,
){
}