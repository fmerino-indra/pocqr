package org.fmm.pocqr

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

class PocQRApp: Application() {
    val applicationSccope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onTerminate() {
        super.onTerminate()
        applicationSccope.cancel()
    }
}