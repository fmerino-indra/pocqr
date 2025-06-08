package org.fmm.pocqr.ui.management.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import org.fmm.pocqr.R
import java.security.KeyStore

class ManagementAdapter(
    private var keyMap: Map<String, KeyStore.Entry>
//    = emptyMap<String, KeyStore.Entry>()
) : RecyclerView.Adapter<ManagementViewHolder>() {

    private val aliasMap: Map<Int, String> = keyMap.keys.withIndex()
        .associate { (index, alias) -> index to alias }

    override fun onCreateViewHolder(
        parent: ViewGroup,
        viewType: Int
    ): ManagementViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_entry, parent, false)
        return ManagementViewHolder(view)
    }

    override fun onBindViewHolder(
        holder: ManagementViewHolder,
        position: Int
    ) {
        val alias = aliasMap[position]!!
        holder.render(alias, keyMap[alias]!!)
    }

    override fun getItemCount(): Int {
        return keyMap.size
    }

    fun update() {
        notifyDataSetChanged()
    }
}