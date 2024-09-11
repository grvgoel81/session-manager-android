package com.web3auth.session_manager_android.api

import com.web3auth.session_manager_android.models.AuthorizeSessionRequest
import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.models.StoreApiResponse
import org.json.JSONObject
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.POST

interface Web3AuthApi {

    @POST("/v2/store/set")
    suspend fun createSession(@Body sessionRequestBody: SessionRequestBody): Response<JSONObject>

    @POST("/v2/store/get")
    suspend fun authorizeSession(
        @Header("origin") origin: String,
        @Body authorizeSessionRequest: AuthorizeSessionRequest
    ): Response<StoreApiResponse>

    @POST("/v2/store/set")
    suspend fun invalidateSession(@Body sessionRequestBody: SessionRequestBody): Response<JSONObject>
}