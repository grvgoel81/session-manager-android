package com.web3auth.session_manager_android

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.os.postDelayed
import com.google.gson.GsonBuilder
import com.web3auth.session_manager_android.api.ApiHelper
import com.web3auth.session_manager_android.api.Web3AuthApi
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.types.AES256CBC
import com.web3auth.session_manager_android.types.Base64.encodeBytes
import com.web3auth.session_manager_android.types.ErrorCode
import com.web3auth.session_manager_android.types.SessionManagerError
import com.web3auth.session_manager_android.types.ShareMetadata
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.math.min

class SessionManager(context: Context) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)
    private val mContext = context

    private var createSessionResponseCompletableFuture: CompletableFuture<String> =
        CompletableFuture()
    private var sessionCompletableFuture: CompletableFuture<String> = CompletableFuture()
    private var invalidateSessionCompletableFuture: CompletableFuture<Boolean> = CompletableFuture()

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

    @OptIn(DelicateCoroutinesApi::class)
    /*fun createSession(data: String, sessionTime: Long, saveSession: Boolean): CompletableFuture<String> {
        createSessionResponseCompletableFuture = CompletableFuture()
        val newSessionKey = generateRandomSessionKey()
        if (ApiHelper.isNetworkAvailable(mContext)) {
            try {
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

                GlobalScope.launch {
                    val result = web3AuthApi.createSession(
                        SessionRequestBody(
                            key = "04".plus(KeyStoreManager.getPubKey(sessionId = newSessionKey)),
                            data = gsonData,
                            signature = KeyStoreManager.getECDSASignature(
                                BigInteger(newSessionKey, 16), gsonData
                            ),
                            timeout = min(sessionTime, 7 * 86400)
                        )
                    )
                    if (result.isSuccessful) {
                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            if(saveSession) {
                                KeyStoreManager.savePreferenceData(
                                    KeyStoreManager.SESSION_ID, newSessionKey
                                )
                            }
                            createSessionResponseCompletableFuture.complete(newSessionKey)
                        }
                    } else {
                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            createSessionResponseCompletableFuture.completeExceptionally(
                                Exception(
                                    SessionManagerError.getError(
                                        ErrorCode.SOMETHING_WENT_WRONG
                                    )
                                )
                            )
                        }
                    }
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                createSessionResponseCompletableFuture.completeExceptionally(ex)
            }
        } else {
            createSessionResponseCompletableFuture.completeExceptionally(
                Exception(
                    SessionManagerError.getError(ErrorCode.RUNTIME_ERROR)
                )
            )
        }
        return createSessionResponseCompletableFuture
    }*/

    /**
     * Authorize User session in order to avoid re-login
     */
    fun authorizeSession(fromOpenLogin: Boolean): CompletableFuture<String> {
        sessionCompletableFuture = CompletableFuture()
        val sessionId = KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()
        if (sessionId.isEmpty()) {
            sessionCompletableFuture.completeExceptionally(
                Exception(
                    SessionManagerError.getError(
                        ErrorCode.SESSIONID_NOT_FOUND
                    )
                )
            )
        }
        if (sessionId.isNotEmpty() && ApiHelper.isNetworkAvailable(mContext)) {
            val pubKey = "04".plus(KeyStoreManager.getPubKey(sessionId))
            GlobalScope.launch {
                try {
                    val result = web3AuthApi.authorizeSession(pubKey)
                    if (result.isSuccessful && result.body() != null) {
                        val messageObj = result.body()?.message?.let { JSONObject(it).toString() }
                        val shareMetadata: ShareMetadata = gson.fromJson(
                            messageObj, ShareMetadata::class.java
                        )

                        val aes256cbc = AES256CBC(
                            sessionId, shareMetadata.ephemPublicKey, shareMetadata.iv.toString()
                        )

                        val share = if (fromOpenLogin) {
                            val encryptedShareBytes =
                                AES256CBC.toByteArray(shareMetadata.ciphertext?.let { BigInteger(it, 16) })
                            aes256cbc.decrypt(encodeBytes(encryptedShareBytes), shareMetadata.mac)
                        } else {
                            aes256cbc.decrypt(shareMetadata.ciphertext, shareMetadata.mac)
                        }

                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            sessionCompletableFuture.complete(String(share, Charsets.UTF_8))
                        }
                    } else {
                        sessionCompletableFuture.completeExceptionally(
                            Exception(
                                SessionManagerError.getError(
                                    ErrorCode.SESSION_EXPIRED
                                )
                            )
                        )
                    }
                } catch (ex: Exception) {
                    ex.printStackTrace()
                    sessionCompletableFuture.completeExceptionally(
                        Exception(
                            SessionManagerError.getError(
                                ErrorCode.NOUSERFOUND
                            )
                        )
                    )
                }
            }
        } else {
            sessionCompletableFuture.completeExceptionally(
                Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            )
        }
        return sessionCompletableFuture
    }

    fun invalidateSession(): CompletableFuture<Boolean> {
        invalidateSessionCompletableFuture = CompletableFuture()
        if (ApiHelper.isNetworkAvailable(mContext)) {
            try {
                val sessionId = KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()
                val ephemKey = "04" + KeyStoreManager.getPubKey(sessionId)
                val ivKey = KeyStoreManager.randomBytes(16)

                val aes256cbc = AES256CBC(
                    sessionId, ephemKey, KeyStoreManager.convertByteToHexadecimal(ivKey)
                )



                if (ephemKey.isNullOrEmpty() || sessionId.isEmpty()) {
                    invalidateSessionCompletableFuture.complete(false)
                }

                val encryptedData = aes256cbc.encrypt("".toByteArray(StandardCharsets.UTF_8))
                val mac = aes256cbc.getMac(encryptedData)
                val encryptedMetadata = ShareMetadata(
                    KeyStoreManager.convertByteToHexadecimal(ivKey),
                    ephemKey,
                    KeyStoreManager.convertByteToHexadecimal(encryptedData),
                    KeyStoreManager.convertByteToHexadecimal(mac)
                )
                val gsonData = gson.toJson(encryptedMetadata)

                GlobalScope.launch {
                    val result = web3AuthApi.invalidateSession(
                        SessionRequestBody(
                            key = "04".plus(KeyStoreManager.getPubKey(sessionId = sessionId)),
                            data = gsonData,
                            signature = KeyStoreManager.getECDSASignature(
                                BigInteger(sessionId, 16), gsonData
                            ),
                            timeout = 1
                        )
                    )
                    if (result.isSuccessful) {
                        KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID)
                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            invalidateSessionCompletableFuture.complete(true)
                        }
                    } else {
                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            invalidateSessionCompletableFuture.completeExceptionally(
                                Exception(
                                    SessionManagerError.getError(
                                        ErrorCode.SOMETHING_WENT_WRONG
                                    )
                                )
                            )
                        }
                    }
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                invalidateSessionCompletableFuture.completeExceptionally(ex)
            }
        } else {
            invalidateSessionCompletableFuture.completeExceptionally(
                Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            )
        }
        return invalidateSessionCompletableFuture
    }

    suspend fun createSession(data: String, sessionTime: Long, saveSession: Boolean): String {
        val newSessionKey = generateRandomSessionKey()

        if (!ApiHelper.isNetworkAvailable(mContext)) {
            throw Exception(SessionManagerError.getError(ErrorCode.RUNTIME_ERROR))
        }

        try {
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

            val result = withContext(Dispatchers.IO) {
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

            if (result.isSuccessful) {
                if (saveSession) {
                    KeyStoreManager.savePreferenceData(KeyStoreManager.SESSION_ID, newSessionKey)
                }
                return newSessionKey
            } else {
                throw Exception(SessionManagerError.getError(ErrorCode.SOMETHING_WENT_WRONG))
            }

        } catch (ex: Exception) {
            ex.printStackTrace()
            throw ex
        }
    }
}