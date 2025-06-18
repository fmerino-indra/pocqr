package org.fmm.pocqr.ui.management.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import org.fmm.pocqr.R
import java.security.KeyStore

class ManagementAdapter(
    private var keyEntryList: List<EntryInfo> = emptyList<EntryInfo>()
) : RecyclerView.Adapter<ManagementViewHolder>() {

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
        holder.render(keyEntryList[position])
    }

    override fun getItemCount(): Int {
        return keyEntryList.size
    }

    fun update() {
        notifyDataSetChanged()
    }
}