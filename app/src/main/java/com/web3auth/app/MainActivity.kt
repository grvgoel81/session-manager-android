package com.web3auth.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.web3auth.core.Web3Auth
import com.web3auth.core.types.*
import com.web3auth.session_manager_android.SessionManager
import org.json.JSONObject
import java.util.concurrent.CompletableFuture

class MainActivity : AppCompatActivity() {

    private lateinit var sessionManager: SessionManager
    private lateinit var web3Auth: Web3Auth
    private lateinit var tvResponse: TextView
    private lateinit var btnLogin: Button
    private lateinit var btnLogout: Button
    private lateinit var sessionId: String
    private lateinit var btnSession: Button
    private lateinit var btnAuthorize: Button
    private var web3AuthResponse = Web3AuthResponse()
    private var sessionTime: Long = 86400

    private val gson = Gson()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvResponse = findViewById(R.id.tvResponse)
        btnLogin = findViewById(R.id.btnLogin)
        btnLogout = findViewById(R.id.btnLogout)
        btnSession = findViewById(R.id.btnSession)
        btnAuthorize = findViewById(R.id.btnAuthorize)

        web3Auth = Web3Auth(
            Web3AuthOptions(
                context = this,
                clientId = getString(R.string.web3auth_project_id),
                network = Network.MAINNET,
                redirectUrl = Uri.parse("torusapp://org.torusresearch.web3authexample/redirect"),
                whiteLabel = WhiteLabelData(  // Optional param
                    "Web3Auth Sample App", null, null, "en", true,
                    hashMapOf(
                        "primary" to "#123456"
                    )
                )
            )
        )

        web3Auth.setResultUrl(intent?.data)

        btnLogin.setOnClickListener {
            onClickLogin()
        }

        btnLogout.setOnClickListener {
            logout()
        }

        btnAuthorize.setOnClickListener {
            sessionManager = SessionManager(this.applicationContext)
            val sessionResponse: String = sessionManager.authorizeSession(false).get()
            Log.d("sessionResponse", sessionResponse)
            val tempJson = JSONObject(sessionResponse)
            tvResponse.text = tempJson.get("privateKey").toString()
        }

        btnSession.setOnClickListener {
            sessionManager = SessionManager(this.applicationContext)
            // Sample data for create session
            val json = JSONObject()
            json.put(
                "privateKey",
                "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
            )
            json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
            try {
                val sessionKey =
                    sessionManager.createSession(json.toString(), sessionTime, true).get()
                // Handle the session key
                sessionId = sessionKey
                btnSession.visibility = View.GONE
            } catch (e: Exception) {
                // Handle the error
                Log.e("MyClass", "Error: ${e.message}")
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        web3Auth.setResultUrl(intent?.data)
    }

    private fun onClickLogin() {
        val selectedLoginProvider = Provider.GOOGLE
        val loginCompletableFuture: CompletableFuture<Web3AuthResponse> =
            web3Auth.login(LoginParams(selectedLoginProvider))

        loginCompletableFuture.whenComplete { loginResponse, error ->
            if (error == null) {
                val jsonObject = JSONObject(gson.toJson(web3Auth.getUserInfo()))
                tvResponse.text =
                    jsonObject.toString(4) + "\n Private Key: " + web3Auth.getPrivkey()
                sessionId = loginResponse.sessionId.toString()
                loginResponse.sessionId?.let { useSessionManageSdk(it) }
            } else {
                // render login error UI
            }
        }
    }

    private fun useSessionManageSdk(sessionId: String) {
        sessionManager = SessionManager(this.applicationContext)
        sessionManager.saveSessionId(sessionId)
        val sessionResponse: String = sessionManager.authorizeSession(true).get()
        btnLogin.visibility = View.GONE
        btnLogout.visibility = View.VISIBLE
        val tempJson = JSONObject(sessionResponse)
        tempJson.put("userInfo", tempJson.get("store"))
        tempJson.remove("store")
        web3AuthResponse =
            gson.fromJson(tempJson.toString(), Web3AuthResponse::class.java)
        val jsonObject = JSONObject(gson.toJson(web3AuthResponse))
        tvResponse.text = jsonObject.toString(4)
    }

    private fun logout() {
        sessionManager = SessionManager(this.applicationContext)
        sessionManager.invalidateSession()
        btnLogout.visibility = View.GONE
        btnLogin.visibility = View.VISIBLE
        tvResponse.text = "Logout"
    }
}