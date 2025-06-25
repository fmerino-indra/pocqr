package org.fmm.pocqr.ui

import android.app.Dialog
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentBrotherBinding
import org.fmm.pocqr.dto.QRData
import org.fmm.pocqr.dto.QREncryptedData
import org.fmm.pocqr.dto.QRSignedData
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.security.crypto.util.AsymmetricRSAHybridCipherManager
import org.fmm.pocqr.security.crypto.util.EncryptionUtil
import org.fmm.pocqr.security.totp.generator.TotpGenerator
import org.fmm.pocqr.ui.qr.QRGenBottomSheetDialogFragment
import org.fmm.pocqr.ui.qr.QRReaderBottomSheetDialogFragment
import java.security.interfaces.RSAPublicKey

class BrotherFragment : Fragment() {
    private var _binding : FragmentBrotherBinding?=null
    val binding get() = _binding!!

    private var clearTotpSeed = TotpGenerator.generateTotpSeed()

    private lateinit var qrGenBottomSheetDialogFragment: QRGenBottomSheetDialogFragment
    private lateinit var qrReaderBottomDialog: QRReaderBottomSheetDialogFragment

    private var myQRSignedData: QRSignedData? = null
    private var qrEncryptedData: QREncryptedData? = null
    private var originalQRSignedData: QRSignedData? = null

    private val encryptionUtil = EncryptionUtil()

    private lateinit var asymmetricRSAManager: AsymmetricRSAHybridCipherManager

    private val authenticationLauncher = registerForActivityResult(
        ActivityResultContracts
            .StartActivityForResult()
    ) { result: ActivityResult ->
        asymmetricRSAManager.handlePinSignature(result.resultCode)
    }

    private val decryptionAuthenticationLauncher = registerForActivityResult(
        ActivityResultContracts
            .StartActivityForResult()
    ) { result: ActivityResult ->
        asymmetricRSAManager.handlePinDecryption(result.resultCode)
    }

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
        initData()
    }

    private fun initData() {
        val qrData = QRData(binding.name.text.toString(), binding.community.text.toString())
        this.myQRSignedData = QRSignedData(qrData,
            publicKey = binding.pubKey.text.toString(),
            signature = binding.signature.text.toString())
/*
        this.qrEncryptedData = QREncryptedData(
            this.myQRSignedData!!,
            this.clearTotpSeed)
*/
    }

    private fun initUI() {
        binding.totpSeed.text=clearTotpSeed
        initSecurity()
        initDialogs()
        initListeners()
        initEvents()
    }

    /**
     * Initialize the Manager. Must have ActivityResultLauncher
     */
    private fun initSecurity() {
        try {
            asymmetricRSAManager = AsymmetricRSAHybridCipherManager(
                this.requireContext(),
                this.requireActivity(),
                this.authenticationLauncher,
                this.decryptionAuthenticationLauncher
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
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
        binding.btnShowJson.setOnClickListener {
            showJSON()
        }
        binding.btnGenQR.setOnClickListener {
            showQR()
        }
        binding.btnSignJson.setOnClickListener {
            signJSON()
        }
        binding.btnGenTOTP.setOnClickListener {
            generateTOTP()
        }
    }
    private fun initEvents() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.signatureUpdatedEvent.collect { newSignature ->
                    updateSignature(newSignature)
                }
            }
        }
    }


    private fun readQR() {
        qrReaderBottomDialog.show(parentFragmentManager, "qrReaderBottomSheet")
    }
    @OptIn(ExperimentalSerializationApi::class)
    private fun showJSON() {
        val dialog = Dialog(this.requireContext())
        dialog.setContentView(R.layout.dialog_json)
        val tvMessage: TextView = dialog.findViewById(R.id.txtMessage)
        val prettyJson = Json {
            prettyPrint = true
            prettyPrintIndent = " "
        }
        val data: QREncryptedData = qrEncryptedData!!
        tvMessage.text = prettyJson.encodeToString<QREncryptedData>(QREncryptedData.serializer() , data)
        dialog.show()

    }

    @OptIn(ExperimentalSerializationApi::class)
    private fun signJSON() {
//        val qrSigned = qrEncryptedData.qrSignedData.copy()


        val json = createJsonToSign()
        Log.d("BrotherFragment", "JSON to sign: ${json}")
        asymmetricRSAManager.signData(json.toString().toByteArray())
    }

    private fun showQR() {
        Log.d("BrotherFragment", "TOTPSeed: ${qrEncryptedData!!.totpSeed}")

        val encryptedTOTPSeed = encryptTOTPSeed()
        this.qrEncryptedData = qrEncryptedData!!.copy(
            totpSeed = EncryptionUtil.encodeB64(encryptedTOTPSeed)
//            totpSeed = EncryptionUtil.encodeAndClean(encryptedTOTPSeed)
        )
        Log.d("BrotherFragment", "Encrypted TOTPSeed: ${qrEncryptedData!!.totpSeed}")
        val json = createEncryptedJSON()
        qrGenBottomSheetDialogFragment.uri = json.toString()
        qrGenBottomSheetDialogFragment.show(parentFragmentManager, "qrGeneratorBottomSheet")

    }

    /**
     * Encrypts the TOTP Seed
     */
    private fun encryptTOTPSeed(): ByteArray {
        val pubKey = encryptionUtil.publicKeyFromString(originalQRSignedData!!.publicKey)!!
        Log.d("BrotherFragment", "TOTPSeed: ${EncryptionUtil.decodeB64(qrEncryptedData!!
            .totpSeed).contentToString()}")
//        Log.d("BrotherFragment", "TOTPSeed: ${EncryptionUtil.cleanAndDecoded(qrEncryptedData!!
//            .totpSeed).contentToString()}")
//        Log.d("BrotherFragment", "Public Key: $pubKey")
//        Log.d("BrotherFragment", "Public Key: ${originalQRSignedData!!.publicKey}")

        if (pubKey is RSAPublicKey) {
            Log.d("BrotherFragment", "Public Key: $pubKey")
            Log.d("BrotherFragment", "Public Key:B64 : ${originalQRSignedData!!.publicKey}")
            Log.d("BrotherFragment", "Public Key:Algoritmo : ${pubKey.algorithm}")
            Log.d("BrotherFragment", "Public Key:Módulo : ${pubKey.modulus}")
            Log.d("BrotherFragment", "Public Key:PublicExponent : ${pubKey
                .publicExponent}")
        }

        return encryptionUtil.encryptByteArray(
            qrEncryptedData!!.totpSeed,
            encryptionUtil.publicKeyFromString(originalQRSignedData!!.publicKey)!!
        )
    }

    /**
     * Callback from QR Read Bottom Panel
     */
    private fun onQRRead(stringRead: String) {
        qrReaderBottomDialog.dismiss()

        Log.d("BrotherFragment", "QR read: $stringRead")
        val qrSignedData = Json.decodeFromString< QRSignedData>(stringRead)
        this.originalQRSignedData = qrSignedData
        this.qrEncryptedData = QREncryptedData(qrSignedData, clearTotpSeed)

        if (validateSignature(qrSignedData)) {

            binding.name.setText(qrSignedData.data.name)
            binding.community.setText(qrSignedData.data.community)
            binding.pubKey.setText(qrSignedData.publicKey)
            binding.signature.setText(qrSignedData.signature)

            binding.totpSeed.text = clearTotpSeed
        } else {
            Toast.makeText(
                activity, "Error de validación de firma", Toast
                    .LENGTH_SHORT
            ).show()
        }
    }
    private fun validateSignature(qrSignedData: QRSignedData): Boolean {
        val jsonToValidate =createJSONToValidate(qrSignedData.data)
        val pubKey = encryptionUtil.publicKeyFromString(qrSignedData.publicKey)
        Log.d("BrotherFragment", "JSON to sign: $jsonToValidate")
        Log.d("BrotherFragment", "PubKey Signature Validation: $pubKey")
        return encryptionUtil.verifySignature(
            jsonToValidate.toString().toByteArray(),
            signatureToVerify = Base64.decode(qrSignedData.signature, Base64.DEFAULT),
            publicKey = pubKey)
    }

    private fun createEncryptedJSON(): JsonObject {
        return Json.encodeToJsonElement(qrEncryptedData!!).jsonObject
    }
    private fun createJsonToSign(): JsonObject {
        return Json.encodeToJsonElement(qrEncryptedData!!.qrSignedData.data).jsonObject
    }


    @OptIn(ExperimentalSerializationApi::class)
    private fun createPrettyJson(): String {
        val prettyJson = Json {
            prettyPrint = true
            prettyPrintIndent = " "
        }
        return prettyJson.encodeToString<QREncryptedData>(QREncryptedData.serializer() , qrEncryptedData!!)

    }
    private fun generateTOTP() {
        binding.totpGenerated.text = TotpGenerator.generateTotp(clearTotpSeed, System.currentTimeMillis())
    }

    /**
     * Crea:
     * "data": {
     *   "name": "Felix",
     *   "community": "2 Siena"
     * }
     */
    private fun createJSONToValidate(qrData: QRData): JsonObject {
        val data = buildJsonObject {
            put("name", qrData.name)
            put("community", qrData.community)
        }

        return buildJsonObject {
            put("data", data)
        }
    }

    private fun updateSignature(newSignature: String) {
        val pK = Base64.encodeToString(AndroidKeystoreUtil
            .getRsaPublicKey()?.encoded, Base64.DEFAULT)
        binding.signature.setText(newSignature)
        binding.pubKey.setText(pK)
        // Se actualiza la PK y la signature
        val qrSignedData = this.originalQRSignedData!!.copy(
            publicKey = pK,
            signature = newSignature
        )
        this.myQRSignedData = qrSignedData
        this.qrEncryptedData = qrEncryptedData!!.copy(qrSignedData= qrSignedData)
    }
}