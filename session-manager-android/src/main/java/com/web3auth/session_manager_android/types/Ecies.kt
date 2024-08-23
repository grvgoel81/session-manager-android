package com.web3auth.session_manager_android.types

import androidx.annotation.Keep

@Keep
data class Ecies(
    val iv: String,
    val ephemPublicKey: String,
    val ciphertext: String,
    val mac: String
)