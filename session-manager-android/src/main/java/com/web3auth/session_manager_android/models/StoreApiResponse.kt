package com.web3auth.session_manager_android.models

import androidx.annotation.Keep

@Keep
data class StoreApiResponse(
    val message: String? = null,
    val success: Boolean? = false,
)