package org.fmm.pocqr.ui.management.adapter

import java.security.KeyStore

data class EntryInfo(
    val alias: String,
    val keyEntry: KeyStore.Entry,
    val isSelected: Boolean = false
) {
}