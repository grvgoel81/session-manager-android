package com.web3auth.session_manager_android

import android.content.Context
import android.util.Base64.encode
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONObject
import retrofit2.Response
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.math.min

class SessionManager(context: Context) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)
    private val mContext = context

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

    fun authorizeSession(fromOpenLogin: Boolean): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
            val sessionId =
                KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()

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
            val response: Response<StoreApiResponse> =
                runBlocking { withContext(Dispatchers.IO) { web3AuthApi.authorizeSession(pubKey) } }


            if (!(response.isSuccessful && response.body() != null && response.body()?.message != null)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.NOUSERFOUND
                    )
                )
            }

            val messageObj =
                response.body()?.message?.let { JSONObject(it).toString() }

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
                    String(encode(encryptedShareBytes, 0), StandardCharsets.UTF_8),
                    shareMetadata.mac
                )
            } else {
                aes256cbc.decrypt(shareMetadata.ciphertext, shareMetadata.mac)
            }
            String(share, Charsets.UTF_8)
        }.exceptionally { throw it }
    }

    fun invalidateSession(): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync {
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
                false
            } else {

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

                val result: Response<JSONObject> = runBlocking {
                    withContext(Dispatchers.IO) {
                        web3AuthApi.invalidateSession(
                            SessionRequestBody(
                                key = "04".plus(KeyStoreManager.getPubKey(sessionId = sessionId)),
                                data = gsonData,
                                signature = KeyStoreManager.getECDSASignature(
                                    BigInteger(sessionId, 16), gsonData
                                ),
                                timeout = 1
                            )
                        )
                    }
                }

                if (result.isSuccessful) {
                    KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID)
                    true
                } else {
                    throw Exception(
                        SessionManagerError.getError(
                            ErrorCode.SOMETHING_WENT_WRONG
                        )
                    )
                }
            }
        }.exceptionally { throw it }
    }
    fun createSession(
        data: String,
        sessionTime: Long,
        saveSession: Boolean
    ): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
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

            val result: Response<JSONObject> = runBlocking {
                withContext(Dispatchers.IO) {
                    web3AuthApi.createSession(
                        SessionRequestBody(
                            key = "04".plus(KeyStoreManager.getPubKey(sessionId = newSessionKey)),
                            data = gsonData,
                            signature = KeyStoreManager.getECDSASignature(
                                BigInteger(newSessionKey, 16), gsonData
                            ),
                            timeout = min(sessionTime, 7 * 86400)
                        )
                    )
                }
            }

            if (result.isSuccessful) {
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
            newSessionKey
        }.exceptionally { throw it }
    }
}