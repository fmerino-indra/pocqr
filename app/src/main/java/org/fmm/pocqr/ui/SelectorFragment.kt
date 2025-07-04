package org.fmm.pocqr.ui

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.navigation.NavController
import androidx.navigation.fragment.findNavController
import org.fmm.pocqr.R
import org.fmm.pocqr.databinding.FragmentSelectorBinding

class SelectorFragment : Fragment() {
    private var _binding: FragmentSelectorBinding?=null
    private val binding get() = _binding!!
    private lateinit var navController: NavController

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSelectorBinding.inflate(layoutInflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initUI()
    }

    private fun initUI() {
        initListeners()
    }

    private fun initListeners() {
        binding.btnResponsible.setOnClickListener {
            navigateToResponsible()
        }

        binding.btnBrother.setOnClickListener {
            navigateToBrother()
        }
        binding.btnManage.setOnClickListener {
            navigateToManagement()
        }
        binding.btnTest.setOnClickListener {
            navigateToTest()
        }
    }

    private fun navigateToTest() {
        findNavController().navigate(
            R.id.action_blankFragment_to_testFragment
        )
    }
    private fun navigateToManagement() {
        findNavController().navigate(
            R.id.action_blankFragment_to_managementFragment
        )
    }
    private fun navigateToResponsible() {
        findNavController().navigate(
            R.id.action_blankFragment_to_responsibleFragment
        )
    }
    private fun navigateToBrother() {
        findNavController().navigate(
            R.id.action_blankFragment_to_brotherFragment
        )
    }
}