package com.web3auth.session_manager_android

import com.web3auth.session_manager_android.keystore.KeyStoreManager
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {
    @Test
    fun addition_isCorrect() {
        assertEquals(4, 2 + 2)
    }

    @Test
    fun encryptionExample() {
        val newSessionKey = SessionManager.generateRandomSessionKey()
        val data = "a"
        val ephemKey = "04" + KeyStoreManager.getPubKey(newSessionKey)
        val ivKey = KeyStoreManager.randomBytes(16)
    }
}