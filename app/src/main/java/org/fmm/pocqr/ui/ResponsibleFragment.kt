package org.fmm.pocqr.ui

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentResponsibleBinding
import org.fmm.pocqr.dto.QREncryptedData
import org.fmm.pocqr.security.crypto.ui.BiometricPromptHelper
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.security.crypto.util.AsymmetricRSAHybridCipherManager
import org.fmm.pocqr.security.totp.generator.TotpGenerator
import org.fmm.pocqr.ui.qr.QRGenBottomSheetDialogFragment
import org.fmm.pocqr.ui.qr.QRReaderBottomSheetDialogFragment
import java.security.InvalidAlgorithmParameterException
import java.util.Base64

class ResponsibleFragment : Fragment() {
    private var _binding: FragmentResponsibleBinding?=null
    private val binding get() = _binding!!

    private lateinit var qrReaderBottomDialog: QRReaderBottomSheetDialogFragment
    private lateinit var qrGenBottomSheetDialogFragment: QRGenBottomSheetDialogFragment

    private var qrEncryptedData: QREncryptedData? = null

//    private lateinit var biometricPromptHelper: BiometricPromptHelper
    private lateinit var asymmetricRSAManager: AsymmetricRSAHybridCipherManager

    // MutableSharedFlow para emitir eventos

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResponsibleBinding.inflate(layoutInflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initUI()
    }

    private fun initUI() {
        initSecurity()
        initDialogs()
        initListeners()
        initEvents()
    }

    private fun initEvents() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.signatureUpdatedEvent.collect { newSignature ->
                    binding.signature.setText(newSignature)
                    showQR()
                }
            }
        }
    }

    private fun initSecurity() {
        asymmetricRSAManager= AsymmetricRSAHybridCipherManager(
            this.requireContext(),
            this.requireActivity()
        )
        /*
        biometricPromptHelper = BiometricPromptHelper(
            this.requireActivity(),
            { error -> println(error)},
            cipherOperation = { cipher ->

            }
            )

         */
    }

    private fun initDialogs() {
        qrGenBottomSheetDialogFragment= QRGenBottomSheetDialogFragment()
        qrReaderBottomDialog=QRReaderBottomSheetDialogFragment { stringRead ->
            onQRRead(stringRead)
        }
    }

    private fun initListeners() {
        binding.btnPubKey.setOnClickListener {
            generateCryptography()
        }
        binding.btnQR.setOnClickListener {
            signData()
//            showQR()
        }
        binding.btnResponse.setOnClickListener {
            readQR()
        }
        binding.btnValidate.setOnClickListener {
            validateTOTP()
        }
    }

    private fun signData() {
        val json = createJSONToSign()
        asymmetricRSAManager.signData(json.toString().toByteArray())
    }
    private fun generateCryptography() {
        try {
            // 1 Recupera par de claves o las crea
            val keyPair = AndroidKeystoreUtil.generateRsaKeyPairWithBiometricAuthentication()
            binding.pubKey.setText(Base64.getEncoder().encodeToString(keyPair.public.encoded))
        } catch (iape: InvalidAlgorithmParameterException) {
            // Si no tiene huella configurada, lleva dentro IllegalStateException
        } catch (ise: IllegalStateException) {
        } catch (e: Exception) {
            Log.e("ResponsibleFragment", "Error al generar el par de claves", e)
        }
        val privateKey = AndroidKeystoreUtil.getRsaPrivateKeyForBiometricUse()

    }
    private fun showQR() {
        val json = createJSON()
        Log.d("ResponsibleFragment", "Signed JSON: $json")
        qrGenBottomSheetDialogFragment.uri = json.toString()
        qrGenBottomSheetDialogFragment.show(parentFragmentManager, "qrGeneratorBottomSheet")
    }

    private fun createJSON(): JsonObject {
        var data = createJSONToSign()

        return buildJsonObject {
            put("signature", binding.signature.text.toString())
            put("publicKey", binding.pubKey.text.toString())
            put("data", data["data"]!!)
        }

/* Lo dejo comentado porque es interesante el mapOf
        return JsonObject(json + mapOf(
            "data" to data["data"]!!
        ) )
*/
    }

    private fun createJSONToSign(): JsonObject {
        val data = buildJsonObject {
            put("name", binding.name.text.toString())
            put("community", binding.community.text.toString())
        }

        return buildJsonObject {
            put("data", data)
        }
    }

    private fun readQR() {
        qrReaderBottomDialog.show(parentFragmentManager, "qrReaderBottomSheet")
    }

    private fun onQRRead(stringRead: String) {
        // Primero habrá que descifrar lo leído:
        // 1. Descf. clave simétrica con nuestra privada
        // 2. Descf. data con clave simétrica

        qrReaderBottomDialog.dismiss()

        Log.d("ResponsibleFragment", "QR read: $stringRead")
        val qrEncryptedData = Json.decodeFromString<QREncryptedData>(stringRead)
        this.qrEncryptedData = qrEncryptedData

        binding.name.setText(qrEncryptedData.qrSignedData.data.name)
        binding.community.setText(qrEncryptedData.qrSignedData.data.community)


        binding.totpSeed.text = qrEncryptedData.totpSeed
        binding.totpEntered.isEnabled = true
        //binding.totpEntered.text = generateTotp(qrData.totpSeed)

    }

    private fun generateTotp(seed:String):String {
        return TotpGenerator.generateTotp(seedBase64 = seed, timeInMillis = System.currentTimeMillis() )
    }
    private fun ResponsibleFragment.validateTOTP() {
        if (qrEncryptedData == null)
            return
        val totpCalculated = generateTotp(qrEncryptedData!!.totpSeed!!)
        val totpEntered: String = binding.totpEntered.text.toString()
        if (totpCalculated == totpEntered) {
            binding.imgCheck.setImageResource(R.drawable.ic_check_green)
        } else {
            binding.imgCheck.setImageResource(R.drawable.ic_close)

        }
    }
}

