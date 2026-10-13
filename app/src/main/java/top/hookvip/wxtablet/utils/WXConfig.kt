package top.hookvip.wxtablet.utils

import com.highcapable.yukihookapi.hook.log.YLog
import org.luckypray.dexkit.DexKitBridge
import top.hookvip.wxtablet.data.DescriptorData
import top.hookvip.wxtablet.data.HostInfo
import top.hookvip.wxtablet.factory.toDexMethod
import java.lang.reflect.Method

object WXConfig {
    /**
     * 缓存版本号。
     *
     * 方法搜索特征发生任何变化时都必须递增，否则已经跑过一次的微信版本
     * 会直接从 FastKV 里读到旧策略缓存下来的错误方法，改动不会生效。
     */
    private const val CACHE_VERSION = "v2"

    /**
     * 平板环境判断（UIUtils.inTabletEnv）的搜索特征，按优先级排列。
     *
     * - 8.0.78 起微信把 inTabletEnv 里的「联想 P8 平板」判断抽成了独立方法
     *   （8.0.78: com.tencent.mm.ui.g9.a()），"Lenovo TB-9707F" 只出现在那个子方法里，
     *   继续用它只会 hook 到一个无关紧要的分支，平板模式因此失效。
     * - inTabletEnv 自身的日志字符串在 8.0.77 / 8.0.78 中都是一样的，而且只被
     *   inTabletEnv 引用，用它可以把总开关稳定地定位出来
     *   （8.0.77: com.tencent.mm.ui.ek.B(rq5.w0) / 8.0.78: com.tencent.mm.ui.gk.C(ou5.w0)）。
     * - 最后一档保留旧特征，用于兼容尚未出现独立子方法的低版本。
     */
    private val CHECK_PAD_TABLET_KEYWORDS = arrayOf(
        "inTabletEnv, no tablet condition matched, return false",
        "inTabletEnv, isHWTablet, return true",
        "inTabletEnv, widthDp:%s >= %s, return true",
        "Lenovo TB-9707F",
    )

    private object MethodCheckPadTablet :
        DescriptorData("WXConfig.MethodCheckPadTablet.$CACHE_VERSION")

    private object MethodVisibleLoginButton : DescriptorData("WXConfig.MethodVisibleLoginButton")

    private val config = FastKv("WXConfig")
    private val bridge by lazy {
        YLog.warn("start dexkit find config apply to cache(${HostInfo.toVerStr()})")
        System.loadLibrary("dexkit");
        DexKitBridge.create(HostInfo.appFilePath)
    }

    val checkPadTablet: Method?
        get() = config.getStringPut(MethodCheckPadTablet.mKey) {
            findDescriptor(*CHECK_PAD_TABLET_KEYWORDS)
        }?.toDexMethod()

    val visibleLoginButton: Method?
        get() = config.getStringPut(MethodVisibleLoginButton.mKey) {
            findDescriptor("loginAsOtherDeviceBtn")
        }?.toDexMethod()

    /**
     * 按顺序尝试每一个特征字符串，返回第一个命中的方法描述符。
     *
     * 用 [firstOrNull] 而不是 `single()`：一旦某个版本的匹配数量不是恰好 1 个，
     * `single()` 会抛异常，而这里的异常会向上冒泡到 [top.hookvip.wxtablet.entry.TabletHooker.doHostInit]，
     * 结果连 TinkerApplication 的 hook 都装不上，整个模块直接失效。
     */
    private fun findDescriptor(vararg keywords: String): String? =
        keywords.firstNotNullOfOrNull { keyword ->
            runCatching {
                bridge.findMethod {
                    matcher {
                        usingStrings(keyword)
                    }
                }.firstOrNull()?.descriptor
            }.onFailure {
                YLog.warn("WXConfig: dexkit search '$keyword' failed: $it")
            }.getOrNull()?.also {
                YLog.warn("WXConfig: dexkit '$keyword' -> $it")
            }
        }
}
