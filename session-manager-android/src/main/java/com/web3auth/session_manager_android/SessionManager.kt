package com.web3auth.session_manager_android

import android.content.Context
import com.google.gson.GsonBuilder
import com.web3auth.session_manager_android.api.ApiHelper
import com.web3auth.session_manager_android.api.Web3AuthApi
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.models.AuthorizeSessionRequest
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

class SessionManager(
    context: Context,
    sessionTime: Int = 86400,
    allowedOrigin: String = "*",
    sessionId: String? = null,
    sessionNamespace: String? = null
) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)
    private var sessionTime: Int
    private var allowedOrigin: String
    private var sessionNamespace: String = ""
    private lateinit var sessionId: String

    companion object {
        fun generateRandomSessionKey(): String {
            return KeyStoreManager.generateRandomSessionKey()
        }

        fun getSessionIdFromStorage(): String {
            return KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID_TAG).toString()
        }

        fun deleteSessionIdFromStorage() {
            KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID_TAG)
        }

        fun saveSessionIdToStorage(sessionId: String) {
            if (sessionId.isNotEmpty() && sessionId.isNotBlank()) {
                KeyStoreManager.savePreferenceData(KeyStoreManager.SESSION_ID_TAG, sessionId)
            }
        }
    }

    init {
        KeyStoreManager.initializePreferences(context.applicationContext)
        initiateKeyStoreManager()
        if (!sessionId.isNullOrEmpty()) {
            this.sessionId = sessionId
        }
        this.sessionTime = sessionTime
        this.allowedOrigin = allowedOrigin
        if (!sessionNamespace.isNullOrEmpty()) {
            this.sessionNamespace = sessionNamespace
        }
    }

    fun setSessionId(sessionId: String) {
        if (sessionId.isNotEmpty()) {
            this.sessionId = sessionId
        }
    }

    fun getSessionId(): String {
        return this.sessionId
    }

    private fun initiateKeyStoreManager() {
        KeyStoreManager.getKeyGenerator()
    }


    /**
     * Authorizes a session for a given origin, performing any necessary authentication or token generation.
     * This method operates asynchronously and returns a `CompletableFuture` that holds the result of the authorization.
     *
     * @param origin A string representing the origin or source of the session. This can be the app's package name or a specific domain.
     * @param context The context in which the session authorization occurs. Typically used to access resources or perform operations within the application.
     *
     * @return A `CompletableFuture<String>` that will contain the result of the session authorization. This will usually be a token or session ID upon successful authorization.
     *
     * Usage example:
     * ```
     * authorizeSession("com.example.app", context)
     * ```
     */
    fun authorizeSession(origin: String, context: Context): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            }

            val sessionId = this.sessionId

            if (sessionId.isNullOrEmpty()) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SESSIONID_NOT_FOUND
                    )
                )
            }
            val pubKey = "04".plus(KeyStoreManager.getPubKey(sessionId).padStart(128, '0'))
            val response: Response<StoreApiResponse> =
                runBlocking {
                    withContext(Dispatchers.IO) {
                        web3AuthApi.authorizeSession(
                            origin = origin,
                            AuthorizeSessionRequest(key = pubKey, namespace = sessionNamespace)
                        )
                    }
                }

            if (!(response.isSuccessful)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SOMETHING_WENT_WRONG
                    )
                )
            }

            if (response.body()?.success == false && response.body()?.message.isNullOrEmpty()) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.NOUSERFOUND
                    )
                )
            }

            val messageObj =
                response.body()?.message?.let { JSONObject(it).toString() }

            if (messageObj.isNullOrEmpty()) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.NOUSERFOUND
                    )
                )
            }

            val ecies: Ecies = gson.fromJson(
                messageObj, Ecies::class.java
            )

            val aes256cbc = AES256CBC()
            val aesKey = aes256cbc.getAESKey(sessionId, ecies.ephemPublicKey)
            val macKey = aes256cbc.getMacKey(sessionId, ecies.ephemPublicKey)
            val share = aes256cbc.decrypt(
                ecies.ciphertext,
                aesKey,
                macKey,
                ecies.mac,
                Hex.decode(ecies.iv),
                Hex.decode(ecies.ephemPublicKey)
            )
            String(share, Charsets.UTF_8)
        }.exceptionally { throw it }
    }

    /**
     * Invalidates the current session, effectively logging the user out or clearing session-related data.
     *
     * @param context The context in which the session invalidation occurs. Typically used to access resources
     * or perform operations within the application (e.g., clearing shared preferences or cache).
     *
     * Usage example:
     * ```
     * invalidateSession(context)
     * ```
     */
    fun invalidateSession(
        context: Context,
    ): CompletableFuture<Boolean> {
        return CompletableFuture.supplyAsync {
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.RUNTIME_ERROR
                    )
                )
            }

            val sessionId = this.sessionId
            if (sessionId.isNullOrEmpty()) {
                throw Exception(
                    SessionManagerError.getError(
                        ErrorCode.SESSIONID_NOT_FOUND
                    )
                )
            }
            val ephemKey = "04" + KeyStoreManager.getPubKey(sessionId).padStart(128, '0')
            val ivKey = KeyStoreManager.randomBytes(16)

            val aes256cbc = AES256CBC()
            if (ephemKey.isEmpty() || sessionId.isEmpty()) {
                false
            } else {

                val aesKey = aes256cbc.getAESKey(sessionId, ephemKey)
                val macKey = aes256cbc.getMacKey(sessionId, ephemKey)
                val encryptedData =
                    aes256cbc.encrypt("".toByteArray(StandardCharsets.UTF_8), aesKey, ivKey)
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
                        web3AuthApi.invalidateSession(
                            SessionRequestBody(
                                key = "04".plus(
                                    KeyStoreManager.getPubKey(sessionId = sessionId)
                                        .padStart(128, '0')
                                ),
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

    /**
     * Creates a new session with the provided data.
     *
     * @param data The session data as a string. This can include information such as tokens or user-specific identifiers.
     * @param context The context in which the session is being created. Typically used to access resources or perform operations within the application.
     *
     * @return This function can be extended to return a result, such as a success or failure message.
     *
     * Usage example:
     * ```
     * createSession("sessionData", context)
     * ```
     */
    fun createSession(
        data: String,
        context: Context,
    ): CompletableFuture<String> {
        return CompletableFuture.supplyAsync {
            val newSessionKey = this.sessionId

            if (newSessionKey.isNullOrEmpty()) {
                throw Exception(SessionManagerError.getError(ErrorCode.SESSIONID_NOT_FOUND))
            }
            if (!ApiHelper.isNetworkAvailable(context)) {
                throw Exception(
                    SessionManagerError.getError(ErrorCode.RUNTIME_ERROR)
                )
            }

            val ephemKey = "04" + KeyStoreManager.getPubKey(newSessionKey).padStart(128, '0')
            val ivKey = KeyStoreManager.randomBytes(16)
            val aes256cbc = AES256CBC()
            val aesKey = aes256cbc.getAESKey(newSessionKey, ephemKey)
            val macKey = aes256cbc.getMacKey(newSessionKey, ephemKey)

            val encryptedData =
                aes256cbc.encrypt(data.toByteArray(StandardCharsets.UTF_8), aesKey, ivKey)
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
                            key = "04".plus(
                                KeyStoreManager.getPubKey(sessionId = newSessionKey)
                                    .padStart(128, '0')
                            ),
                            data = gsonData,
                            signature = KeyStoreManager.getECDSASignature(
                                BigInteger(newSessionKey, 16), gsonData
                            ),
                            timeout = min(sessionTime, 7 * 86400),
                            allowedOrigin = allowedOrigin,
                            namespace = sessionNamespace
                        )
                    )
                }
            }

            if (!result.isSuccessful) {
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