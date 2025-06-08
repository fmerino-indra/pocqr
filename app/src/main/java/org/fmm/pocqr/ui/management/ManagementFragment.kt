package org.fmm.pocqr.ui.management

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentManagementBinding
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.ui.management.adapter.ManagementAdapter

class ManagementFragment : Fragment() {
    private var _binding: FragmentManagementBinding? = null
    private val binding get() = _binding!!

    private lateinit var managementAdapter: ManagementAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentManagementBinding.inflate(layoutInflater, container, false)
        return binding?.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initUI()
    }

    private fun initUI() {
        initAdapter()
        managementAdapter.update()
    }

    private fun initAdapter() {
        val aliases = AndroidKeystoreUtil.getAlias()
        val entryMap = aliases.toList().associateWith { alias ->
            AndroidKeystoreUtil.getEntry(alias) }
        managementAdapter = ManagementAdapter(entryMap)
        binding.rvKeys.apply {
            layoutManager = GridLayoutManager(context, 1)
//            layoutManager = LinearLayoutManager(context)
            adapter = managementAdapter
        }

    }
}