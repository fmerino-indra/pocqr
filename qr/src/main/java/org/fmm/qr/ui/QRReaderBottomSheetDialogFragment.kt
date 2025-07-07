package org.fmm.qr.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import org.fmm.qr.databinding.FragmentQRReaderBinding
import org.fmm.qr.ui.util.playBeep
import org.fmm.qr.ui.util.vibrate

class QRReaderBottomSheetDialogFragment (private val callback: (String) -> Unit):
BottomSheetDialogFragment() {
    private var _binding: FragmentQRReaderBinding? = null
    private val binding get() = _binding!!

    private lateinit var barcodeCallback: BarcodeCallback

    private var _result: String = ""
    val result get() = _result

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentQRReaderBinding.inflate(layoutInflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initData()
        stoppedState()
        barcodeCallback = object: BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult?) {
                if (result?.text != null && result.text.isNotEmpty())
                    processQR(result.text)
            }
        }

        binding.btnStartScan.setOnClickListener {
            if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA) != PackageManager
                    .PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    requireActivity(),
                    arrayOf(Manifest.permission.CAMERA),
                    100
                )
            } else {
                startScanner()
            }
        }
        binding.btnStopScan.setOnClickListener {
            stopScanner()
        }
    }

    private fun initData() {
        _result = ""
    }
    private fun stoppedState() {
        binding.progressBar.isVisible = false
        binding.btnStartScan.isVisible = true
        binding.btnStopScan.isVisible = false
    }

    private fun scanningState() {
        binding.progressBar.isVisible = false
        binding.btnStartScan.isVisible = false
        binding.btnStopScan.isVisible = true
    }

    private fun processQR(uri: String) {
        this.playBeep()
        this.vibrate()
        stopScanner()
        message(uri)
        _result = uri
        callback(uri)

    }

    private fun stopScanner() {
        stoppedState()
        binding.barcodeScannerView.apply {
            pause()
//            View.setVisibility = View.GONE - Dejó de funcionar
            isVisible = false
        }
    }

    private fun startScanner() {
        scanningState()
        binding.barcodeScannerView.apply {
//            View.setVisibility = View.VISIBLE
            isVisible = true
            decodeContinuous(barcodeCallback)
            resume()
        }
    }
    private fun message(message: String) {
        Toast.makeText(
            requireContext(), message, Toast.LENGTH_LONG
        ).show()

    }

    override fun onPause() {
        super.onPause()
        binding.barcodeScannerView.pause()
    }

    override fun onResume() {
        super.onResume()
        if(binding.barcodeScannerView.isVisible) {
            binding.barcodeScannerView.resume()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startScanner()
            } else {
                Toast.makeText(requireContext(), "Permiso de cámara necesario", Toast.LENGTH_LONG)
            }
        }

    }

/*
    fun readQRFromFile() {
        val barcodeBitmap =
        val barcodeReader: QRCodeReader = QRCodeReader()
        barcodeReader.decode()
    }
*/
    companion object {
        private const val CAMERA_PERMISSION_REQUEST_CODE = 100
    }
}