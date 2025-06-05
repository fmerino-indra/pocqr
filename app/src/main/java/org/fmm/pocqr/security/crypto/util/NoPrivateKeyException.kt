package org.fmm.pocqr.security.crypto.util

import java.security.KeyManagementException
import java.security.Signature
import javax.crypto.Cipher

class NoPrivateKeyException(
    msg: String,
    val signature: Signature?=null
): KeyManagementException(msg) {
}