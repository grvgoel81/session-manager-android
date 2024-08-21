package com.web3auth.session_manager_android

import android.content.Context
import com.google.gson.GsonBuilder
import com.web3auth.session_manager_android.api.ApiHelper
import com.web3auth.session_manager_android.api.Web3AuthApi
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.models.StoreApiResponse
import com.web3auth.session_manager_android.types.AES256CBC
import com.web3auth.session_manager_android.types.ErrorCode
import com.web3auth.session_manager_android.types.SessionManagerError
import com.web3auth.session_manager_android.types.ShareMetadata
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject
import retrofit2.Response
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import kotlin.math.min
import android.util.Base64.encode

class SessionManager(context: Context) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)
    private val mContext = context
    private val scope = CoroutineScope(Job() + Dispatchers.IO)

    companion object {
        fun generateRandomSessionKey(): String {
            return KeyStoreManager.generateRandomSessionKey()
        }
    }

    init {
        KeyStoreManager.initializePreferences(context.applicationContext)
        initiateKeyStoreManager()
    }

    private fun initiateKeyStoreManager() {
        KeyStoreManager.getKeyGenerator()
    }

    fun saveSessionId(sessionId: String) {
        if (sessionId.isNotEmpty()) {
            KeyStoreManager.savePreferenceData(
                KeyStoreManager.SESSION_ID, sessionId
            )
        }
    }

    fun getSessionId(): String {
        return KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()
    }

    /**
     * Authorize User session in order to avoid re-login
     */
    suspend fun authorizeSession(fromOpenLogin: Boolean): String {
        val sessionId = KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()

        if (sessionId.isEmpty()) {
            throw Exception(
                SessionManagerError.getError(
                    ErrorCode.SESSIONID_NOT_FOUND
                )
            )
        }

        if (!(sessionId.isNotEmpty() && ApiHelper.isNetworkAvailable(mContext))) {
            throw Exception(
                SessionManagerError.getError(
                    ErrorCode.RUNTIME_ERROR
                )
            )
        }
        val pubKey = "04".plus(KeyStoreManager.getPubKey(sessionId))
        var response: Response<StoreApiResponse>? = null
        scope.launch {
            response = web3AuthApi.authorizeSession(pubKey)
        }.join()

        if (!(response?.isSuccessful == true && response?.body() != null && response?.body()?.message != null)) {
            throw Exception(
                SessionManagerError.getError(
                    ErrorCode.NOUSERFOUND
                )
            )
        }

        val messageObj =
            response?.body()?.message?.let { JSONObject(it).toString() }

        val shareMetadata: ShareMetadata = gson.fromJson(
            messageObj, ShareMetadata::class.java
        )

        val aes256cbc = AES256CBC(
            sessionId,
            shareMetadata.ephemPublicKey,
            shareMetadata.iv.toString()
        )

        val share = if (fromOpenLogin) {
            val encryptedShareBytes =
                AES256CBC.toByteArray(shareMetadata.ciphertext?.let {
                    BigInteger(
                        it,
                        16
                    )
                })
            aes256cbc.decrypt(
                String(encode(encryptedShareBytes,0), StandardCharsets.UTF_8),
                shareMetadata.mac
            )
        } else {
            aes256cbc.decrypt(shareMetadata.ciphertext, shareMetadata.mac)
        }
        return String(share, Charsets.UTF_8)
    }

    suspend fun invalidateSession(): Boolean {
        if (!ApiHelper.isNetworkAvailable(mContext)) {
            throw Exception(
                SessionManagerError.getError(
                    ErrorCode.RUNTIME_ERROR
                )
            )
        }

        val sessionId =
            KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID)
                .toString()
        val ephemKey = "04" + KeyStoreManager.getPubKey(sessionId)
        val ivKey = KeyStoreManager.randomBytes(16)

        val aes256cbc = AES256CBC(
            sessionId, ephemKey, KeyStoreManager.convertByteToHexadecimal(ivKey)
        )
        if (ephemKey.isEmpty() || sessionId.isEmpty()) {
            return false
        }

        val encryptedData =
            aes256cbc.encrypt("".toByteArray(StandardCharsets.UTF_8))
        val mac = aes256cbc.getMac(encryptedData)
        val encryptedMetadata = ShareMetadata(
            KeyStoreManager.convertByteToHexadecimal(ivKey),
            ephemKey,
            KeyStoreManager.convertByteToHexadecimal(encryptedData),
            KeyStoreManager.convertByteToHexadecimal(mac)
        )
        val gsonData = gson.toJson(encryptedMetadata)

        var result: Response<JSONObject>? = null
        scope.launch {
            result = web3AuthApi.invalidateSession(
                SessionRequestBody(
                    key = "04".plus(KeyStoreManager.getPubKey(sessionId = sessionId)),
                    data = gsonData,
                    signature = KeyStoreManager.getECDSASignature(
                        BigInteger(sessionId, 16), gsonData
                    ),
                    timeout = 1
                )
            )
        }.join()

        if (result?.isSuccessful == true) {
            KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID)
            return true
        } else {
            throw Exception(
                SessionManagerError.getError(
                    ErrorCode.SOMETHING_WENT_WRONG
                )
            )
        }
    }

    suspend fun createSession(data: String, sessionTime: Long, saveSession: Boolean): String {
        val newSessionKey = generateRandomSessionKey()
        if (!ApiHelper.isNetworkAvailable(mContext)) {
            throw Exception(
                SessionManagerError.getError(ErrorCode.RUNTIME_ERROR)
            )
        }

        val ephemKey = "04" + KeyStoreManager.getPubKey(newSessionKey)
        val ivKey = KeyStoreManager.randomBytes(16)
        val aes256cbc = AES256CBC(
            newSessionKey, ephemKey, KeyStoreManager.convertByteToHexadecimal(ivKey)
        )

        val encryptedData = aes256cbc.encrypt(data.toByteArray(StandardCharsets.UTF_8))
        val mac = aes256cbc.getMac(encryptedData)
        val encryptedMetadata = ShareMetadata(
            KeyStoreManager.convertByteToHexadecimal(ivKey),
            ephemKey,
            KeyStoreManager.convertByteToHexadecimal(encryptedData),
            KeyStoreManager.convertByteToHexadecimal(mac)
        )
        val gsonData = gson.toJson(encryptedMetadata)

        var result: Response<JSONObject>? = null
        scope.launch {
            result = web3AuthApi.createSession(
                SessionRequestBody(
                    key = "04".plus(KeyStoreManager.getPubKey(sessionId = newSessionKey)),
                    data = gsonData,
                    signature = KeyStoreManager.getECDSASignature(
                        BigInteger(newSessionKey, 16), gsonData
                    ),
                    timeout = min(sessionTime, 7 * 86400)
                )
            )
        }.join()

        if (result?.isSuccessful == true) {
            if (saveSession) {
                KeyStoreManager.savePreferenceData(
                    KeyStoreManager.SESSION_ID, newSessionKey
                )
            } else {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SOMETHING_WENT_WRONG
                    )
                )
            }
        }
        return newSessionKey
    }
}