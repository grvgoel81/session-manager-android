package com.web3auth.session_manager_android

import com.google.gson.Gson
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.types.AES256CBC
import com.web3auth.session_manager_android.types.ShareMetadata
import org.junit.Test

import org.junit.Assert.*
import java.nio.charset.StandardCharsets

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
        val ivKey = KeyStoreManager.randomString(16)
        val aes256cbc = AES256CBC(
            newSessionKey,
            ephemKey,
            ivKey
        )

        val encryptedData = aes256cbc.encrypt(data.toByteArray(StandardCharsets.UTF_8))
        val mac = aes256cbc.macKey
        val encryptedMetadata = ShareMetadata(ivKey, ephemKey, encryptedData, mac)
        val gson = Gson()
        val gsonData = gson.toJson(encryptedMetadata)
    }
}