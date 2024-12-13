package com.web3auth.session_manager_android.models

import androidx.annotation.Keep

@Keep
data class SessionRequestBody(
    val key: String,
    val data: String,
    val signature: String,
    val timeout: Int = 0,
    val allowedOrigin: String? = null,
    val namespace: String? = null
)