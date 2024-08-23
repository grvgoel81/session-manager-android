package com.web3auth.session_manager_android.types

enum class ErrorCode {
    NOUSERFOUND,
    SESSIONID_NOT_FOUND,
    ENCODING_ERROR,
    DECODING_ERROR,
    RUNTIME_ERROR,
    SESSION_EXPIRED,
    SOMETHING_WENT_WRONG,
}