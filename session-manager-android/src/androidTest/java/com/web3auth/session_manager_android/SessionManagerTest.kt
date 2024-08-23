package com.web3auth.session_manager_android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import junit.framework.TestCase.assertEquals
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.ExecutionException

@RunWith(AndroidJUnit4::class)
class SessionManagerTest {

    private lateinit var sessionManager: SessionManager

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun test_createSession() {
        val context = InstrumentationRegistry.getInstrumentation().context
        sessionManager = SessionManager(context)
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        val sessionKey = sessionManager.createSession(
            json.toString(),
            86400,
            context
        ).get()
        assert(sessionKey != null)
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun test_authorizeSession() {
        val context = InstrumentationRegistry.getInstrumentation().context
        sessionManager = SessionManager(context)
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        sessionManager.createSession(
            json.toString(),
            86400,
            context
        ).get()
        sessionManager = SessionManager(context)
        val authResponse = sessionManager.authorizeSession(
            context
        ).get()
        val resp = JSONObject(authResponse)
        assert(resp.get("privateKey").toString().isNotEmpty())
        assert(resp.get("publicAddress").toString().isNotEmpty())
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun test_invalidateSession() {
        val context = InstrumentationRegistry.getInstrumentation().context
        sessionManager = SessionManager(context)
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        sessionManager.createSession(
            json.toString(),
            86400,
            context
        ).get()
        sessionManager = SessionManager(context)
        val invalidateRes = sessionManager.invalidateSession(context).get()
        assertEquals(invalidateRes, true)
    }
}