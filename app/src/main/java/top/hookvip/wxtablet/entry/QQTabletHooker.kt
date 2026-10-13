package top.hookvip.wxtablet.entry

import android.content.Context
import android.view.View
import com.highcapable.yukihookapi.hook.entity.YukiBaseHooker
import com.highcapable.yukihookapi.hook.factory.method
import com.highcapable.yukihookapi.hook.factory.toClass
import com.highcapable.yukihookapi.hook.log.YLog
import com.highcapable.yukihookapi.hook.factory.toClassOrNull
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean

/** Enables QQ's native tablet type in the login UI and its separate MSF login service process. */
object QQTabletHooker : YukiBaseHooker() {
    private const val QQ_PACKAGE = "com.tencent.mobileqq"
    private const val PAD_UTIL = "com.tencent.common.config.pad.PadUtil"
    private const val DEVICE_TYPE = "com.tencent.common.config.pad.DeviceType"

    @Volatile
    private var tabletModeEnabled = false

    private val tabletResultLogCount = AtomicInteger()
    private val authenticationLogCount = AtomicInteger()

    private var hostClassLoader: ClassLoader? = null
    private val installedLoaders = mutableSetOf<ClassLoader>()
    private val securityShieldInstalled = AtomicBoolean(false)

    override fun onHook() {
        if (packageName != QQ_PACKAGE) return
        // Tinker installs a replacement loader after package loading. Never resolve
        // QQ business classes until that loader is active.
        runCatching {
            "com.tencent.tinker.loader.app.TinkerApplication".toClass(appClassLoader).method {
                name("onBaseContextAttached")
                param(Context::class.java, Long::class.java, Long::class.java)
            }.hook {
                before { installForHost(instance as Context) }
            }
        }.onFailure { YLog.warn("QQTablet: Tinker lifecycle hook unavailable: $it") }
        "android.app.Application".toClass().method {
            name("attach")
            param(Context::class.java)
        }.hook {
            after { installForHost(instance as Context) }
        }
        YLog.warn("QQTablet: waiting for host application loader in $processName")
    }

    private fun installForHost(context: Context) {
        val loader = context.classLoader
        if (!installedLoaders.add(loader)) return
        hostClassLoader = loader
        YLog.warn("QQTablet: installing with active host loader=$loader process=$processName")
        installQQHooks()
    }

    private fun installQQHooks() {

        // Password/SMS login constructs its AppID in the foreground process before
        // sending it to MSF. Authentication must not depend on a welcome-page click.
        forceAuthenticationIdentity()
        forceNativeLoginIdentity()

        // 主进程与 :MSF 都要装：QQ 的设备风险（外挂/环境异常）检测结果就是在
        // 这两个进程里产生并上报的，屏蔽层必须早于任何登录/上报动作安装。
        installSecurityShield()

        // Authentication is sent by QQ's separate :MSF process. Its device type is read
        // from AppSetting's manifest parameters (phone vs. pad), independently of the
        // foreground PadUtil cache hooked below.
        if (processName == "$QQ_PACKAGE:MSF") {
            forceTabletClientParameters()
            return
        }

        // Keep QQ's initial welcome/login landing page as-is. Activate tablet detection
        // immediately before its existing Login button handler runs.
        runCatching {
            "android.view.View".toClass().method {
                name("performClick")
                emptyParam()
            }.hook {
                before {
                    val view = instance as? View ?: return@before
                    val idName = runCatching {
                        if (view.id == View.NO_ID) null else view.resources.getResourceEntryName(view.id)
                    }.getOrNull()
                    if (idName == "btn_login") {
                        tabletModeEnabled = true
                        val switched = enableCachedTabletType()
                        YLog.warn("QQTablet: tablet mode enabled after initial Login button; cacheUpdated=$switched")
                    }
                }
            }
            YLog.warn("QQTablet: hooked View.performClick")
        }.onFailure {
            YLog.warn("QQTablet: hook Login button failed: $it")
        }

        // QQ 9.3.x centralizes its native device classification here. Return its own
        // TABLET enum only after the initial landing page has been left.
        runCatching {
            val hostLoader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
            val padUtil = PAD_UTIL.toClassOrNull(hostLoader)
                ?: error("QQ PadUtil class not found")
            padUtil.method {
                name("a")
                param(Context::class.java)
            }.hook {
                after {
                    if (!tabletModeEnabled) return@after
                    val deviceType = DEVICE_TYPE.toClassOrNull(hostLoader)
                        ?: return@after
                    val tabletType = deviceType.enumConstants?.firstOrNull {
                        (it as? Enum<*>)?.name == "TABLET"
                    }
                    if (tabletType != null) {
                        // PadUtil.a(Context) caches its first physical-device result in a
                        // static DeviceType field. Replacing only this invocation's return
                        // value leaves that cache as PHONE, which QQ's login UI also reads.
                        setCachedTabletType(tabletType)
                        result = tabletType
                        if (tabletResultLogCount.incrementAndGet() <= 3) {
                            YLog.warn("QQTablet: PadUtil.a(Context) returned TABLET after login selection")
                        }
                    }
                }
            }
            YLog.warn("QQTablet: hooked PadUtil.a(Context) for QQ tablet device type")
        }.onFailure {
            YLog.warn("QQTablet: PadUtil hook failed: $it")
        }

    }

    /** Patch the client bid at the Java-to-native boundary, including cached login. */
    private fun forceNativeLoginIdentity() {
        runCatching {
            val loader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
            val configType = "com.tencent.qqnt.kernel.nativeinterface.InitLoginConfig".toClass(loader)
            val adapterType = "com.tencent.qqnt.kernel.nativeinterface.IloginAdapter".toClass(loader)
            val proxy = "com.tencent.qqnt.kernel.nativeinterface.IKernelLoginService\$CppProxy".toClass(loader)
            proxy.method {
                name("initConfig")
                param(configType, adapterType)
            }.hook {
                before {
                    val config = args(0).cast<Any>() ?: return@before
                    val context = "com.tencent.qphone.base.util.BaseApplication".toClass(loader)
                        .getMethod("getContext").invoke(null) as Context
                    val info = context.packageManager.getApplicationInfo(context.packageName, 128)
                    val padParams = info.metaData?.getString("AppSetting_params_pad")
                        ?: error("QQ pad manifest parameters missing")
                    val padId = padParams.substringBefore('#').toInt()
                    require(padId > 0)
                    val bid = configType.getDeclaredField("bid").apply { isAccessible = true }
                    val previous = bid.get(config)
                    bid.set(config, padId.toString())
                    // appid=16 is the NT business identifier; preserve it and platform.
                    YLog.warn("QQTablet: native login bid=$previous -> $padId process=$processName")
                }
            }
            YLog.warn("QQTablet: hooked native login config in $processName")
        }.onFailure {
            YLog.warn("QQTablet: native login config hook failed: $it")
        }
    }

    private fun forceAuthenticationIdentity() {
        runCatching {
            val hostLoader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
            val appSetting = "com.tencent.common.config.AppSetting".toClassOrNull(hostLoader)
                ?: error("QQ AppSetting class not found")
            val padId = appSetting.getDeclaredField("g").apply { isAccessible = true }
            val padIdentity = appSetting.getDeclaredField("j").apply { isAccessible = true }
            appSetting.method {
                name("e")
                emptyParam()
            }.hook {
                after {
                    // The original getter initializes these fields from this QQ
                    // version's AppSetting_params_pad before selecting an identity.
                    val id = padId.getInt(null)
                    if (id > 0) {
                        result = id
                        if (authenticationLogCount.incrementAndGet() <= 3) {
                            YLog.warn("QQTablet: authentication AppID=$id process=$processName")
                        }
                    }
                }
            }
            appSetting.method {
                name("i")
                emptyParam()
            }.hook {
                after {
                    val identity = padIdentity.get(null) as? String
                    if (!identity.isNullOrEmpty()) result = identity
                }
            }
            YLog.warn("QQTablet: hooked authentication identity in $processName")
        }.onFailure {
            YLog.warn("QQTablet: authentication identity hook failed: $it")
        }
    }

    /** Make the authentication process report QQ's native TABLET classification. */
    private fun forceTabletClientParameters() {
        runCatching {
            val hostLoader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
            val deviceType = DEVICE_TYPE.toClassOrNull(hostLoader)
                ?: error("QQ DeviceType class not found in MSF process")
            val tabletType = deviceType.enumConstants?.firstOrNull {
                (it as? Enum<*>)?.name == "TABLET"
            } ?: error("QQ TABLET enum value not found in MSF process")

            // AppSetting.i() selects the manifest's pad identity by calling o(Context),
            // which in turn reads PadUtil.a(Context). The old hook wrote AppSetting.v
            // before u() ran, so the manifest parser immediately overwrote it.
            val padUtil = PAD_UTIL.toClassOrNull(hostLoader)
                ?: error("QQ PadUtil class not found in MSF process")
            padUtil.method {
                name("a")
                param(Context::class.java)
            }.hook {
                after {
                    setCachedTabletType(tabletType)
                    result = tabletType
                }
            }
            val appSetting = "com.tencent.common.config.AppSetting".toClassOrNull(hostLoader)
                ?: error("QQ AppSetting class not found in MSF process")
            appSetting.method {
                name("o")
                param(Context::class.java)
            }.hook {
                after { result = true }
            }
            appSetting.method {
                name("n")
                param(Context::class.java)
            }.hook {
                after { result = true }
            }
            YLog.warn("QQTablet: forced AppSetting and PadUtil to TABLET in MSF process")
        }.onFailure {
            YLog.warn("QQTablet: MSF tablet identity hook failed: $it")
        }
    }

    /** 安装设备风险上报/环境检测屏蔽层；只在 :MSF 与主进程各装一次。 */
    private fun installSecurityShield() {
        if (!securityShieldInstalled.compareAndSet(false, true)) return
        runCatching {
            val loader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
            QQSecurityShield.install(loader, processName)
        }.onFailure { YLog.warn("QQTablet: security shield install failed: $it") }
    }

    /** Update PadUtil's cached classification and mark its one-time detection complete. */
    private fun enableCachedTabletType(): Boolean = runCatching {
        val hostLoader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
        val padUtil = PAD_UTIL.toClassOrNull(hostLoader) ?: return false
        val deviceType = DEVICE_TYPE.toClassOrNull(hostLoader) ?: return false
        val tabletType = deviceType.enumConstants?.firstOrNull {
            (it as? Enum<*>)?.name == "TABLET"
        } ?: return false
        setCachedTabletType(tabletType)
    }.getOrDefault(false)

    private fun setCachedTabletType(tabletType: Any): Boolean = runCatching {
        val hostLoader = hostClassLoader ?: appClassLoader ?: javaClass.classLoader
        val padUtil = PAD_UTIL.toClassOrNull(hostLoader) ?: return false
        val typeCache = padUtil.declaredFields.firstOrNull {
            AtomicBoolean::class.java.isAssignableFrom(it.type)
        } ?: return false
        typeCache.isAccessible = true
        (typeCache.get(null) as? AtomicBoolean)?.set(true) ?: return false

        val cachedType = padUtil.declaredFields.firstOrNull {
            it.type.name == DEVICE_TYPE
        } ?: return false
        cachedType.isAccessible = true
        cachedType.set(null, tabletType)
        true
    }.getOrDefault(false)
}
