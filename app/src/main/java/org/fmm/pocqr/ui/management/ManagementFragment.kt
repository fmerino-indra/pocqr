package org.fmm.pocqr.ui.management

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.fmm.pocqr.databinding.FragmentManagementBinding
import org.fmm.pocqr.security.crypto.util.AndroidKeystoreUtil
import org.fmm.pocqr.ui.management.adapter.EntryInfo
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
        var aliases = AndroidKeystoreUtil.getAlias()
        val entryMap = aliases.toList()
            .associateWith { alias -> AndroidKeystoreUtil.getEntry(alias) }

        aliases = AndroidKeystoreUtil.getAlias()
        var entryList: List<EntryInfo> = aliases.toList()
            .mapNotNull { alias ->
                runCatching {
                    EntryInfo(alias, AndroidKeystoreUtil.getEntry(alias), false)
                }.onSuccess {entry ->
                    Log.d("ManagementFragment", "Alias: $alias Entry: $entry")
                }.getOrElse {
                    Log.d("ManagementFragment", "Alias es null")
                    null
                }
            }

        aliases = AndroidKeystoreUtil.getAlias()
        entryList = mutableListOf()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            try {
                val entry = AndroidKeystoreUtil.getEntry(alias)
                if (entry != null) {
                    entryList.add(EntryInfo(alias, entry))
                } else
                    Log.w("ManagementFragment", "Entrada nula para alias: $alias")
            } catch (e: Exception) {
                Log.e("ManagementFragment", "Error obteniendo entrada para alias: $alias", e)
            }
        }
        managementAdapter = ManagementAdapter(entryList)
        binding.rvKeys.apply {
            layoutManager = LinearLayoutManager(context, RecyclerView.VERTICAL, false)
            adapter = managementAdapter
        }
    }
/*
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

 */
}