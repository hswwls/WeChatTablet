package top.hookvip.wxtablet.utils

import com.highcapable.yukihookapi.hook.log.YLog
import io.fastkv.FastKV
import io.fastkv.interfaces.FastCipher

class FastKv @JvmOverloads constructor(
    id: String = "WeChatTablet",
    password: String = globalPassword
) {
    private val kv by lazy {
        FastKV.Builder(storePath, id).cipher(Cipher(password, password)).build()
    }

    init {
        if (storePath.isEmpty()) {
            throw RuntimeException("storePath is empty(FastKv.initialize(String path)初始化")
        }
    }

    companion object {
        private var storePath = ""

        /** 必须是合法的 AES 密钥长度（16/24/32 字节），旧值只有 15 字节，Android 17 会直接抛异常。 */
        private var globalPassword = "|aesKey&&aesIv|0"

        /**
         * 初始化 传入文件夹路径
         */
        @JvmStatic
        fun initialize(path: String) {
            storePath = path
        }

        @JvmStatic
        fun setGlobalPassword(password: String) {
            globalPassword = password
        }
    }

    fun getStringPut(key: String, def: () -> String?): String? {
        // 缓存只是加速手段：读取失败（密钥不合法、文件损坏、旧版本写坏的数据）不能影响主流程
        runCatching {
            if (kv.contains(key)) {
                return kv.getString(key)
            }
        }.onFailure {
            YLog.warn("FastKv: 读取缓存 '$key' 失败，改为实时搜索: $it")
        }
        val value = def()
        if (value != null) {
            runCatching { kv.putString(key, value) }.onFailure {
                YLog.warn("FastKv: 写入缓存 '$key' 失败，本次结果仍然有效: $it")
            }
        }
        return value
    }


    /**
     * fast kv的加密实现接口
     */
    private class Cipher(key: String, iv: String) : FastCipher {
        private var helper = AesHelper(key, iv)

        override fun encrypt(src: ByteArray): ByteArray {
            return helper.encrypt(src)
        }

        override fun decrypt(dst: ByteArray): ByteArray {
            return helper.decrypt(dst)
        }

        override fun encrypt(src: Int): Int {
            return src
        }

        override fun encrypt(src: Long): Long {
            return src
        }

        override fun decrypt(dst: Int): Int {
            return dst
        }

        override fun decrypt(dst: Long): Long {
            return dst
        }
    }
}
