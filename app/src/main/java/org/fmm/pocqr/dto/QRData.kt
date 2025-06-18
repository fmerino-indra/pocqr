package org.fmm.pocqr.dto

import kotlinx.serialization.Serializable

@Serializable
data class QRData (
    val name:String,
    val community:String,
){
}