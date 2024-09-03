package com.web3auth.session_manager_android

import android.content.Context
import com.google.gson.GsonBuilder
import com.web3auth.session_manager_android.api.ApiHelper
import com.web3auth.session_manager_android.api.Web3AuthApi
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.models.StoreApiResponse
import com.web3auth.session_manager_android.types.AES256CBC
import com.web3auth.session_manager_android.types.Ecies
import com.web3auth.session_manager_android.types.ErrorCode
import com.web3auth.session_manager_android.types.SessionManagerError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject
import retrofit2.Response
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.math.min

class SessionManager(context: Context) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)

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
                KeyStoreManager.SESSION_ID_TAG, sessionId
            )
        }
    }

    fun getSessionId(): String {
        return KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID_TAG).toString()
    }

    /**
     * Authorize User session in order to avoid re-login
     */

    fun authorizeSession(context: Context): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            }

            val sessionId =
                getSessionId()

            if (sessionId.isEmpty()) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SESSIONID_NOT_FOUND
                    )
                )
            }

            if (!(sessionId.isNotEmpty() && ApiHelper.isNetworkAvailable(context))) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            }
            val pubKey = "04".plus(KeyStoreManager.getPubKey(sessionId).padStart(128,'0'))
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

            val ecies: Ecies = gson.fromJson(
                messageObj, Ecies::class.java
            )

            val aes256cbc = AES256CBC()
            val aesKey = aes256cbc.getAESKey(sessionId, ecies.ephemPublicKey)
            val macKey = aes256cbc.getMacKey(sessionId, ecies.ephemPublicKey)
            val share = aes256cbc.decrypt(ecies.ciphertext, aesKey, macKey, ecies.mac, Hex.decode(ecies.iv), Hex.decode(ecies.ephemPublicKey))
            String(share, Charsets.UTF_8)
        }.exceptionally { throw it }
    }

    fun invalidateSession(context: Context): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync {
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            }

            val sessionId = getSessionId()
            val ephemKey = "04" + KeyStoreManager.getPubKey(sessionId).padStart(128,'0')
            val ivKey = KeyStoreManager.randomBytes(16)

            val aes256cbc = AES256CBC()
            if (ephemKey.isEmpty() || sessionId.isEmpty()) {
                false
            } else {

                val aesKey = aes256cbc.getAESKey(sessionId, ephemKey)
                val macKey = aes256cbc.getMacKey(sessionId, ephemKey)
                val encryptedData =
                    aes256cbc.encrypt("".toByteArray(StandardCharsets.UTF_8), aesKey, ivKey)
                val mac = aes256cbc.getMac(encryptedData, macKey,ivKey,Hex.decode(ephemKey))
                val encryptedMetadata = Ecies(
                    Hex.toHexString(ivKey),
                    ephemKey,
                    Hex.toHexString(encryptedData),
                    Hex.toHexString(mac)
                )
                val gsonData = gson.toJson(encryptedMetadata)

                val result: Response<JSONObject> = runBlocking {
                    withContext(Dispatchers.IO) {
                        web3AuthApi.invalidateSession(
                            SessionRequestBody(
                                key = "04".plus(KeyStoreManager.getPubKey(sessionId = sessionId).padStart(128,'0')),
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
                    KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID_TAG)
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
        context: Context
    ): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
            val newSessionKey = generateRandomSessionKey()
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(ErrorCode.RUNTIME_ERROR)
                )
            }

            val ephemKey = "04" + KeyStoreManager.getPubKey(newSessionKey).padStart(128,'0')
            val ivKey = KeyStoreManager.randomBytes(16)
            val aes256cbc = AES256CBC()
            val aesKey = aes256cbc.getAESKey(newSessionKey, ephemKey)
            val macKey = aes256cbc.getMacKey(newSessionKey, ephemKey)

            val encryptedData = aes256cbc.encrypt(data.toByteArray(StandardCharsets.UTF_8), aesKey, ivKey)
            val mac = aes256cbc.getMac(encryptedData, macKey, ivKey, Hex.decode(ephemKey))
            val encryptedMetadata = Ecies(
                Hex.toHexString(ivKey),
                ephemKey,
                Hex.toHexString(encryptedData),
                Hex.toHexString(mac)
            )
            val gsonData = gson.toJson(encryptedMetadata)

            val result: Response<JSONObject> = runBlocking {
                withContext(Dispatchers.IO) {
                    web3AuthApi.createSession(
                        SessionRequestBody(
                            key = "04".plus(KeyStoreManager.getPubKey(sessionId = newSessionKey).padStart(128,'0')),
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
                    KeyStoreManager.savePreferenceData(
                        KeyStoreManager.SESSION_ID_TAG, newSessionKey
                    )
            } else {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SOMETHING_WENT_WRONG
                    )
                )
            }
            newSessionKey
        }.exceptionally { throw it }
    }
}