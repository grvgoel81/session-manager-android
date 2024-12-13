package com.web3auth.session_manager_android.models

import androidx.annotation.Keep

@Keep
data class AuthorizeSessionRequest(
    val key: String,
    val namespace: String
)