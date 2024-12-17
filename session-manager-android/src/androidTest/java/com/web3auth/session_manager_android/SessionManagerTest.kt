package com.web3auth.session_manager_android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.types.AES256CBC
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertTrue
import org.bouncycastle.util.encoders.Hex
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
        val sessionId = SessionManager.generateRandomSessionKey()
        sessionManager = SessionManager(context, 86400, context.packageName, sessionId)
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        val sessionKey = sessionManager.createSession(
            json.toString(),
            context
        ).get()
        assert(sessionKey != null)
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun test_authorizeSession() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val sessionId = SessionManager.generateRandomSessionKey()
        sessionManager = SessionManager(context, 86400, context.packageName, sessionId, "sfa")
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        val created = sessionManager.createSession(
            json.toString(),
            context
        ).get()
        SessionManager.saveSessionIdToStorage(created)
        assertTrue(created.isNotEmpty())
        val authResponse = sessionManager.authorizeSession(
            context.packageName,
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
        val sessionId = SessionManager.generateRandomSessionKey()
        sessionManager = SessionManager(context, 86400, context.packageName, sessionId)
        val json = JSONObject()
        json.put(
            "privateKey",
            "91714924788458331086143283967892938475657483928374623640418082526960471979197446884"
        )
        json.put("publicAddress", "0x93475c78dv0jt80f2b6715a5c53838eC4aC96EF7")
        val created = sessionManager.createSession(
            json.toString(),
            context
        ).get()
        SessionManager.saveSessionIdToStorage(created)
        val invalidateRes = sessionManager.invalidateSession(context).get()
        assertEquals(invalidateRes, true)
        SessionManager.deleteSessionIdFromStorage()
        val res = SessionManager.getSessionIdFromStorage().isNotEmpty()
        assertEquals(res, false)
    }

    @Test
    @Throws(ExecutionException::class)
    fun testAes() {
        val message = "Hello World"
        val sessionId = KeyStoreManager.generateRandomSessionKey()
        val ephemKey = "04" + KeyStoreManager.getPubKey(sessionId).padStart(128,'0')
        val aes256cbc = AES256CBC()
        val aesKey = aes256cbc.getAESKey(sessionId, ephemKey)
        val iv = KeyStoreManager.randomBytes(16)
        val macKey = aes256cbc.getMacKey(sessionId, ephemKey)
        assert(!aesKey.contentEquals(macKey))
        assert(aesKey.size == 32)
        assert(macKey.size == 32)
        val encrypted = aes256cbc.encrypt(message.toByteArray(Charsets.UTF_8), aesKey, iv)
        val mac = aes256cbc.getMac(encrypted, macKey, iv, Hex.decode(ephemKey))
        val decrypted = aes256cbc.decrypt(Hex.toHexString(encrypted),aesKey,macKey, Hex.toHexString(mac), iv, Hex.decode(ephemKey))
        val decryptedString = String(decrypted, Charsets.UTF_8)
        assert(decryptedString == message)
    }
}