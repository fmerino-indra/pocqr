package org.fmm.pocqr.ui

import android.os.Bundle
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.fmm.pocqr.databinding.FragmentBrotherBinding
import org.fmm.pocqr.dto.QREncryptedData
import org.fmm.pocqr.dto.QRSignedData
import org.fmm.pocqr.security.totp.generator.TotpGenerator
import org.fmm.pocqr.security.totp.generator.TotpSeedGenerator
import org.fmm.pocqr.ui.qr.QRGenBottomSheetDialogFragment
import org.fmm.pocqr.ui.qr.QRReaderBottomSheetDialogFragment

class BrotherFragment : Fragment() {
    private var _binding : FragmentBrotherBinding?=null
    val binding get() = _binding!!

    private var totpSeed = TotpSeedGenerator.generateTotpSeed()

    private lateinit var qrGenBottomSheetDialogFragment: QRGenBottomSheetDialogFragment
    private lateinit var qrReaderBottomDialog: QRReaderBottomSheetDialogFragment
    private var qrSignedData: QRSignedData? = null
    private var qrEncryptedData: QREncryptedData? = null


    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentBrotherBinding.inflate(layoutInflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initUI()
    }

    private fun initUI() {
        binding.totpSeed.text=totpSeed
        initDialogs()
        initListeners()
    }
    private fun initDialogs() {
        qrGenBottomSheetDialogFragment= QRGenBottomSheetDialogFragment()
        qrReaderBottomDialog=QRReaderBottomSheetDialogFragment { stringRead ->
            onQRRead(stringRead)
        }
    }

    private fun initListeners() {
        binding.btnReadQR.setOnClickListener {
            readQR()
        }
        binding.btnGenQR.setOnClickListener {
            showQR()
        }
        binding.btnGenTOTP.setOnClickListener {
            generateTOTP()
        }
    }
    private fun readQR() {
        qrReaderBottomDialog.show(parentFragmentManager, "qrReaderBottomSheet")
    }
    private fun onQRRead(stringRead: String) {
        qrReaderBottomDialog.dismiss()

        Log.d("ResponsibleFragment", "QR read: $stringRead")
        val qrSignedData = Json.decodeFromString< QRSignedData>(stringRead)
        this.qrSignedData = qrSignedData

        binding.name.setText(qrSignedData.data.name)
        binding.community.setText(qrSignedData.data.community)
        binding.pubKey.setText(qrSignedData.publicKey)
        binding.signature.setText(qrSignedData.signature)

        val responsibleSignature = qrSignedData.signature
        val responsiblePubKey = qrSignedData.publicKey
        // Validar firma del responsable

        binding.totpSeed.text = totpSeed
        //binding.totpEntered.text = generateTotp(qrData.totpSeed)

    }


    private fun showQR() {
        val json = createJSON()
        qrGenBottomSheetDialogFragment.uri = json.toString()
        qrGenBottomSheetDialogFragment.show(parentFragmentManager, "qrGeneratorBottomSheet")

    }

    private fun createJSON(): Any {
        return buildJsonObject {
            put("name", binding.name.text.toString())
            put("community", binding.community.text.toString())
            put("publicKey", binding.pubKey.text.toString())
            put("signature", binding.signature.text.toString())
            put("totpSeed", totpSeed)
        }

    }

    private fun generateTOTP() {
        binding.totpGenerated.text = TotpGenerator.generateTotp(totpSeed, System.currentTimeMillis())
    }

}