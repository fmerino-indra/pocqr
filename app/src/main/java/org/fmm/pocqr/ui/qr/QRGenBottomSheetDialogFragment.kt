package org.fmm.pocqr.ui.qr

import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentQRGenBinding

class QRGenBottomSheetDialogFragment (): BottomSheetDialogFragment() {
    private var _binding: FragmentQRGenBinding? = null
    private val binding get() = _binding!!

    var uri: String = ""
    private val barcodeEncoder = BarcodeEncoder()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentQRGenBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        generateQR()
    }

    fun generateQR() {
        val qrBitmap: Bitmap? =
            try {
                barcodeEncoder.encodeBitmap(uri, BarcodeFormat.QR_CODE, 400, 400)
            } catch (e: Exception) {
                Log.e("QRGenBottomSheetDialogFragment",getString(R.string.qrException))
                null
            }
        binding.qrImageView.setImageBitmap(qrBitmap)
    }
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}