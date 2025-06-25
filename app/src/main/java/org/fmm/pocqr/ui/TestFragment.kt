package org.fmm.pocqr.ui

import android.os.Bundle
import android.security.keystore.KeyProperties
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import org.fmm.pocqr.databinding.FragmentTestBinding
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.security.crypto.util.EncryptionUtil
import org.fmm.pocqr.security.totp.generator.TotpGenerator
import java.security.KeyPair
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import kotlin.math.E

class TestFragment : Fragment() {
    private var _binding: FragmentTestBinding?=null
    private val binding get() = _binding!!

    private val encryptionUtil= EncryptionUtil()
    private val totpSeed = TotpGenerator.generateTotpSeed()

    private lateinit var masterPair: KeyPair
    private lateinit var encryptedData: ByteArray
    private lateinit var encryptedText: String

    //ENCRYPTION
    private val RSA_TRANSFORMATION_RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding"//"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private val RSA_TRANSFORMATION_RSA_ECB_OAEP ="RSA/ECB/OAEPWithSHA-512AndMGF1Padding"

    private var _rsaCipherPKCS1Padding: Cipher = Cipher.getInstance(RSA_TRANSFORMATION_RSA_ECB_PKCS1)
    private var _rsaCipherOAEP: Cipher = Cipher.getInstance(RSA_TRANSFORMATION_RSA_ECB_OAEP)

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentTestBinding.inflate(layoutInflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initUI()
    }

    private fun initUI() {
        initCrypto()
        initButtons()
    }

    private fun initButtons() {
        binding.btnEncryptPKCS1.setOnClickListener {
            binding.txtDecryptedText.text=""
            initCipherForEncryptPKCS1()
            encryptData(_rsaCipherPKCS1Padding)
        }
        binding.btnDecryptPKCS1.setOnClickListener {
            initCipherForDecryptPKCS1()
            decryptData(_rsaCipherPKCS1Padding)
        }
        binding.btnEncryptOAEP.setOnClickListener {
            binding.txtDecryptedText.text=""
            initCipherForEncryptOAEP()
            encryptData(_rsaCipherOAEP)
        }
        binding.btnDecryptOAEP.setOnClickListener {
            initCipherForDecryptOAEP()
            decryptData(_rsaCipherOAEP)
        }
    }

    private fun encryptData(rsaCipher: Cipher) {
        try {
//            rsaCipher.init(Cipher.ENCRYPT_MODE, masterPair.public)
            encryptedData = rsaCipher.doFinal(EncryptionUtil.decodeB64(totpSeed))
            encryptedText = EncryptionUtil.encodeB64(encryptedData)
            binding.txtEncryptedText.text = this@TestFragment.encryptedText
        } catch (e: Exception) {
            e.printStackTrace()
            binding.txtEncryptedText.text= e.message
        }
    }
    private fun decryptData(rsaCipher: Cipher) {
        try {
//            rsaCipher.init(Cipher.DECRYPT_MODE, masterPair.private)
            val decryptedText = rsaCipher.doFinal(encryptedData)
            binding.txtDecryptedText.text = EncryptionUtil.encodeB64(decryptedText)
        } catch (e: Exception) {
            e.printStackTrace()
            binding.txtDecryptedText.text= "EXCEPTION ocurred: ${e.message}"
        }
    }
    private fun initCipherForEncryptPKCS1() {
        _rsaCipherPKCS1Padding.init(Cipher.ENCRYPT_MODE, masterPair.public)
    }

    private fun initCipherForDecryptPKCS1() {
        _rsaCipherPKCS1Padding.init(Cipher.DECRYPT_MODE, masterPair.private)
    }

    private fun initCipherForEncryptOAEP() {
        val pS: OAEPParameterSpec = OAEPParameterSpec("SHA-256", "mgf1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )
        _rsaCipherOAEP.init(Cipher.ENCRYPT_MODE, masterPair.public, pS)
    }
    private fun initCipherForDecryptOAEP() {
        val pS: OAEPParameterSpec = OAEPParameterSpec("SHA-256", "mgf1",
            MGF1ParameterSpec("SHA-1"),
            PSource.PSpecified.DEFAULT
        )
        _rsaCipherOAEP.init(Cipher.DECRYPT_MODE, masterPair.private, pS)
    }


    private fun initCrypto() {
        masterPair = AndroidKeystoreUtil.getOrGenerateRsaKeyPairWithoutAuthentication()
        val info = AndroidKeystoreUtil.inspectKeyProtection(AndroidKeystoreUtil.KEY_PAIR_ALIAS_RSA_NO_AUTH)
        if (info != null) {
            binding.txtClearText.setText(totpSeed)
            binding.keyAlias.text = AndroidKeystoreUtil.KEY_PAIR_ALIAS_RSA_NO_AUTH
            binding.keyType.text = masterPair.private.algorithm
            binding.keyLength.text = info.keySize.toString()
            binding.keyPurposes.text = parsePurposes(info.purposes)
        }
    }
    private fun parsePurposes(purposes: Int): String {
        val list = mutableListOf<String>()
        if (purposes and KeyProperties.PURPOSE_ENCRYPT != 0) list.add("Cifrar")
        if (purposes and KeyProperties.PURPOSE_DECRYPT != 0) list.add("Descifrar")
        if (purposes and KeyProperties.PURPOSE_SIGN != 0) list.add("Firmar")
        if (purposes and KeyProperties.PURPOSE_VERIFY != 0) list.add("Verificar")
        if (purposes and KeyProperties.PURPOSE_WRAP_KEY != 0) list.add("Envolver Clave")
        return list.joinToString(", ")
    }

}