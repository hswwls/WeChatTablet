package top.hookvip.wxtablet.utils

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesHelper(key: String, iv: String) {
    private val mSecretKeySpec = SecretKeySpec(normalize(key), "AES/CBC/PKCS7Padding");
    private val mCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
    private val mIvParameterSpec = IvParameterSpec(normalize(iv));

    fun encrypt(data: ByteArray): ByteArray {
        mCipher.init(Cipher.ENCRYPT_MODE, mSecretKeySpec, mIvParameterSpec)
        return mCipher.doFinal(data)
    }

    fun decrypt(data: ByteArray): ByteArray {
        mCipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec, mIvParameterSpec)
        return mCipher.doFinal(data)
    }

    /**
     * AES 只接受 16/24/32 字节的密钥，IV 必须是 16 字节。
     *
     * 旧代码直接把 15 字节的 "|aesKey&&aesIv|" 当密钥用，在 Android 17(Conscrypt) 上会抛
     * java.security.InvalidKeyException: Unsupported key size: 15 bytes，
     * 于是 FastKV 写缓存失败 → checkPadTablet / visibleLoginButton 全为 null → 模块完全不生效。
     * 这里统一补齐到合法的长度：不足 16 字节补 0，超过 32 字节截断。
     */
    private fun normalize(value: String): ByteArray {
        val raw = value.encodeToByteArray()
        return when {
            raw.size == 16 || raw.size == 24 || raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOf(32)
            raw.size > 24 -> raw.copyOf(24)
            else -> raw.copyOf(16)
        }
    }
}
