package org.fmm.pocqr.ui

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentResponsibleBinding
import org.fmm.pocqr.dto.QREncryptedData
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.security.crypto.util.AsymmetricRSAHybridCipherManager
import org.fmm.pocqr.security.crypto.util.EncryptionUtil
import org.fmm.pocqr.security.totp.generator.TotpGenerator
import org.fmm.pocqr.ui.qr.QRGenBottomSheetDialogFragment
import org.fmm.pocqr.ui.qr.QRReaderBottomSheetDialogFragment
import java.security.InvalidAlgorithmParameterException
import java.security.interfaces.RSAPublicKey


class ResponsibleFragment : Fragment() {
    private var _binding: FragmentResponsibleBinding?=null
    private val binding get() = _binding!!

    private lateinit var qrReaderBottomDialog: QRReaderBottomSheetDialogFragment
    private lateinit var qrGenBottomSheetDialogFragment: QRGenBottomSheetDialogFragment

    private var qrEncryptedData: QREncryptedData? = null
    private var cleanTotpSeed: String = ""

    private val decryptionAuthenticationLauncher = registerForActivityResult(
        ActivityResultContracts
            .StartActivityForResult()
    ) { result: ActivityResult ->
        Log.d("ResponsibleFragment", "Este es el resultado ${result.data}")
//        currentAuthCallback?.invoke(result)
        asymmetricRSAManager.handlePinDecryption(result.resultCode)
    }

    private val authenticationLauncher = registerForActivityResult(
            ActivityResultContracts
                .StartActivityForResult()
        ) { result: ActivityResult ->
            asymmetricRSAManager.handlePinSignature(result.resultCode)
        }

/*
    private val newAuthenticationLauncher = registerForActivityResult(
        ActivityResultContracts
            .StartActivityForResult()
    ) { result: ActivityResult ->
        asymmetricRSAManager.authCallback(result)
    }
*/

    private lateinit var asymmetricRSAManager: AsymmetricRSAHybridCipherManager

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

    override fun onViewStateRestored(savedInstanceState: Bundle?) {
        super.onViewStateRestored(savedInstanceState)
        Log.d("ResponsibleFragment", "Fragment restaurado: onViewStateRestored" +
                "restaurada")
    }

    override fun onStart() {
        super.onStart()
        Log.d("ResponsibleFragment", "Fragment activo: onStart")
    }

    override fun onResume() {
        super.onResume()
        Log.d("ResponsibleFragment", "Fragment en foco. Activity: onResume")
    }

    override fun onPause() {
        super.onPause()
        Log.d("ResponsibleFragment", "onPause: No primer plano")
    }

    override fun onStop() {
        super.onStop()
        Log.d("ResponsibleFragment", "onStop: No visible")
    }

    override fun onDestroyView() {
        super.onDestroyView()
    }

    override fun onDestroy() {
        super.onDestroy()
    }

    override fun onDetach() {
        super.onDetach()
    }
    private fun initUI() {
        initSecurity()
        initDialogs()
        initListeners()
        initEvents()
        buttonStates()
    }

    private fun initEvents() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.signatureUpdatedEvent.collect { newSignature ->
                    binding.signature.setText(newSignature)
                    buttonStates()
                }
/*
                asymmetricRSAManager.decryptedUpdatedEvent.collect { decryptedData ->
                    binding.totpSeed.text = decryptedData
                    cleanTotpSeed = decryptedData
                    binding.totpEntered.isEnabled = true

                    buttonStates()
                }
*/
            }
        }
    }

    private fun initSecurity() {
        try {
            asymmetricRSAManager = AsymmetricRSAHybridCipherManager(
                this.requireContext(),
                this.requireActivity(),
                this.authenticationLauncher,
                this.decryptionAuthenticationLauncher
//                ,
//                this.newAuthenticationLauncher
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == Activity.RESULT_OK && requestCode == 1) {
            Toast.makeText(
                activity, "Error reintentando navegar a Settings", Toast
                    .LENGTH_SHORT
            ).show()
        }
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
            buttonStates()
        }

        binding.btnSign.setOnClickListener {
            signData()
            buttonStates()
        }

        binding.btnQR.setOnClickListener {
//            signData()
            showQR()
            buttonStates()
        }
        binding.btnResponse.setOnClickListener {
            readQR()
            buttonStates()
        }
        binding.btnValidate.setOnClickListener {
            validateTOTP()
            buttonStates()
        }
    }

    private fun signData() {
        val json = createJSONToSign()
        Log.d("ResponsibleFragment", "JSON to sign: ${json}")
        asymmetricRSAManager.signData(json.toString().toByteArray())
    }
    private fun generateCryptography() {
        try {
            // 1 Recupera par de claves o las crea

            val publicKey = AndroidKeystoreUtil.getRsaPublicKey()
            val b64PubKey = EncryptionUtil.encodeB64(publicKey!!.encoded)
            if (publicKey is RSAPublicKey) {
                Log.d("ResponsibleFragment", "Public Key: $publicKey")
                Log.d("ResponsibleFragment", "Public Key:B64 : $b64PubKey")
                Log.d("ResponsibleFragment", "Public Key:Algoritmo : ${publicKey.algorithm}")
                Log.d("ResponsibleFragment", "Public Key:Módulo : ${publicKey.modulus}")
                Log.d("ResponsibleFragment", "Public Key:PublicExponent : ${publicKey
                    .publicExponent}")
            }
            binding.pubKey.setText(b64PubKey)
//            binding.pubKey.setText(Base64.getEncoder().encodeToString(publicKey?.encoded))
        } catch (iape: InvalidAlgorithmParameterException) {
            // Si no tiene huella configurada, lleva dentro IllegalStateException
        } catch (ise: IllegalStateException) {
        } catch (e: Exception) {
            Log.e("ResponsibleFragment", "Error al generar el par de claves", e)
        }
        val privateKey = AndroidKeystoreUtil.getRsaPrivateKey()

    }
    private fun showQR() {
        val json = createJSON()
        Log.d("ResponsibleFragment", "Signed JSON: $json")
        qrGenBottomSheetDialogFragment.uri = json.toString()
        qrGenBottomSheetDialogFragment.show(parentFragmentManager, "qrGeneratorBottomSheet")
    }

    /**
     * Crea:
     * "signature": "NoZkHIPi7...",
     * "publicKey": "MIIBIjANBgk...
     * "data": {
     *   "name": "Felix",
     *   "community": "2 Siena"
     * }
     */
    private fun createJSON(): JsonObject {
        var data = createJSONToSign()
        val publicKey = AndroidKeystoreUtil.getRsaPublicKey()


        return buildJsonObject {

            put("signature", binding.signature.text.toString())
            put("publicKey", EncryptionUtil.encodeB64(publicKey!!.encoded))
            put("data", data["data"]!!)
        }

/* Lo dejo comentado porque es interesante el mapOf
        return JsonObject(json + mapOf(
            "data" to data["data"]!!
        ) )
*/
    }

    /**
     * Crea:
     * "data": {
     *   "name": "Felix",
     *   "community": "2 Siena"
     * }
    */
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
        Log.d("ResponsibleFragment", "Encrypted TOTPSeed: ${qrEncryptedData.totpSeed}")

        binding.name.setText(qrEncryptedData.qrSignedData.data.name)
        binding.community.setText(qrEncryptedData.qrSignedData.data.community)
        binding.signature.setText(qrEncryptedData.qrSignedData.signature)
        binding.pubKey.setText(qrEncryptedData.qrSignedData.publicKey)

        val encryptedSeed =  qrEncryptedData.totpSeed

//        subscribeSymmetricKeyDecryptEvent()

        lifecycleScope.launch {
            try {
/*
                val decryptedSeed = asymmetricRSAManager.decryptAsymmetricByteArrayV2(
                    EncryptionUtil.cleanAndDecoded(encryptedSeed)
                )
*/
                val decryptedSeed = asymmetricRSAManager.decryptAsymmetricByteArrayV2(
                    EncryptionUtil.decodeB64(encryptedSeed)
                )
                cleanTotpSeed = decryptedSeed
                binding.totpSeed.text = decryptedSeed

                val totpCalculated = generateTotp(cleanTotpSeed)
                binding.totpCalculated.text = totpCalculated
                buttonStates()
            } catch (e: Exception) {
                Log.e("ResponsibleFragment", "Se ha producido una excepción al desencriptar:",e)
            }
        }
    }
    private fun subscribeSymmetricKeyDecryptEvent() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.decryptedUpdatedEvent.collect { decryptedData ->
                    binding.totpSeed.text = decryptedData
                    cleanTotpSeed = decryptedData
                    binding.totpCalculated.isEnabled = true

                    buttonStates()
                }
            }
        }
    }

    private fun subscribeTotpSeedDecryptEvent() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.decryptedUpdatedEvent.collect { decryptedData ->
                    binding.totpSeed.text = decryptedData
                    cleanTotpSeed = decryptedData
                    binding.totpCalculated.isEnabled = true

                    buttonStates()
                }
            }
        }
    }

    private fun subscribeSignatureEvent() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                asymmetricRSAManager.signatureUpdatedEvent.collect { newSignature ->
                    binding.signature.setText(newSignature)
                    buttonStates()
                }
            }
        }

    }

    private fun generateTotp(seed:String):String {
        return TotpGenerator.generateTotp(seedBase64 = seed, timeInMillis = System.currentTimeMillis() )
    }
    private fun validateTOTP() {
        if (qrEncryptedData == null)
            return
        val totpCalculated = generateTotp(cleanTotpSeed)
        val totpEntered: String = binding.totpEntered.text.toString()

        if (totpCalculated == totpEntered) {
            binding.imgCheck.imageTintList = ColorStateList.valueOf(Color.GREEN)
            binding.imgCheck.setImageResource(R.drawable.ic_check_green)
        } else {
            binding.imgCheck.imageTintList = ColorStateList.valueOf(Color.RED)
            binding.imgCheck.setImageResource(R.drawable.ic_close)
        }
    }


    private fun buttonStates() {
        binding.btnSign.isEnabled = binding.name.text.isNotBlank()
                && binding.community.text.isNotBlank()
        binding.btnQR.isEnabled = binding.pubKey.text.isNotBlank()
                && binding.name.text.isNotBlank()
                && binding.community.text.isNotBlank()
        binding.btnValidate.isEnabled = binding.totpSeed.text.isNotBlank()
    }
}

