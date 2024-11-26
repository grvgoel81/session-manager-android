package com.web3auth.session_manager_android.types;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256CBC {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public byte[] getAESKey(String privateKeyHex, String ephemPublicKeyHex) throws NoSuchAlgorithmException {
        byte[] hash = SHA512.digest(toByteArray(ecdh(privateKeyHex, ephemPublicKeyHex)));
        return Arrays.copyOfRange(hash, 0, 32);
    }
    public byte[] getMacKey(String privateKeyHex, String ephemPublicKeyHex) throws NoSuchAlgorithmException {
        byte[] hash = SHA512.digest(toByteArray(ecdh(privateKeyHex, ephemPublicKeyHex)));
        return Arrays.copyOfRange(hash, 32, hash.length);
    }

    /**
     * Utility method to convert a BigInteger to a byte array in unsigned
     * format as needed in the handshake messages. BigInteger uses
     * 2's complement format, i.e. it prepends an extra zero if the MSB
     * is set. We remove that.
     */
    public static byte[] toByteArray(BigInteger bi) {
        byte[] b;
        try {
            b = bi.toByteArray();
            if (b.length > 1 && b[0] == 0) {
                int n = b.length - 1;
                byte[] newArray = new byte[n];
                System.arraycopy(b, 1, newArray, 0, n);
                b = newArray;
            }
            return b;
        } catch (Exception ex) {
            throw ex;
        }
    }

    public byte[] encrypt(byte[] src, byte[] aesKey, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher;
        cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(src);
    }

    public byte[] decrypt(String src, byte[] aesKey, byte[] macKey, String mac, byte[] iv, byte[] ephemeralPublicKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher;
        if (!hmacSha256Verify(macKey, getCombinedData(Hex.decode(src), iv, ephemeralPublicKey), mac)) {
            throw new RuntimeException("Bad MAC error during decrypt");
        }
        cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(Hex.decode(src));
    }

    private BigInteger ecdh(String privateKeyHex, String ephemPublicKeyHex) {
        String affineX = ephemPublicKeyHex.substring(2, 66);
        String affineY = ephemPublicKeyHex.substring(66);

        ECPointArithmetic ecPoint = new ECPointArithmetic(new EllipticCurve(new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")), new BigInteger("0"), new BigInteger("7")), new BigInteger(affineX, 16), new BigInteger(affineY, 16), null);
        return ecPoint.multiply(new BigInteger(privateKeyHex, 16)).getX();
    }

    public byte[] getMac(byte[] cipherTextBytes, byte[] macKey, byte[] iv, byte[] ephemeralPublicKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        return hmacSha256Sign(macKey, getCombinedData(cipherTextBytes, iv, ephemeralPublicKey));
    }

    public byte[] getCombinedData(byte[] cipherTextBytes, byte[] iv, byte[] ephemeralPublicKey) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(ephemeralPublicKey);
        outputStream.write(cipherTextBytes);
        return outputStream.toByteArray();
    }

    /**
     * Generates an HMAC-SHA256 signature.
     *
     * @param key  The secret key used for the HMAC-SHA256 operation.
     * @param data The data on which the HMAC-SHA256 operation is performed.
     * @return The resulting HMAC-SHA256 signature.
     */
    public byte[] hmacSha256Sign(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    /**
     * Verifies an HMAC-SHA256 signature.
     *
     * @param key  The secret key used for the HMAC-SHA256 operation.
     * @param data The data on which the HMAC-SHA256 operation is performed.
     * @param sig  The provided HMAC-SHA256 signature.
     * @return True if the signature is valid, false otherwise.
     */
    public boolean hmacSha256Verify(byte[] key, byte[] data, String sig) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] expectedSig = hmacSha256Sign(key, data);
        return Hex.toHexString(expectedSig).equals(sig);
    }
}
