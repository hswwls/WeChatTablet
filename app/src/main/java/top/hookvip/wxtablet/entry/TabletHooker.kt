package top.hookvip.wxtablet.entry

import android.content.Context
import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.view.Gravity
import android.widget.Button
import android.widget.FrameLayout
import android.widget.TextView
import androidx.core.view.isGone
import com.highcapable.yukihookapi.hook.entity.YukiBaseHooker
import com.highcapable.yukihookapi.hook.factory.field
import com.highcapable.yukihookapi.hook.factory.method
import com.highcapable.yukihookapi.hook.log.YLog
import com.highcapable.yukihookapi.hook.param.PackageParam
import top.hookvip.wxtablet.data.HostInfo
import top.hookvip.wxtablet.factory.toAppClass
import top.hookvip.wxtablet.utils.FastKv
import top.hookvip.wxtablet.utils.WXConfig
import java.util.concurrent.atomic.AtomicInteger

object TabletHooker : YukiBaseHooker() {

    private const val TINKER_APPLICATION = "com.tencent.tinker.loader.app.TinkerApplication"
    private const val WECHAT_APPLICATION = "com.tencent.mm.app.Application"
    private const val CHAT_CLASS = "com.tencent.mm.pluginsdk.ui.chat"

    @Volatile
    private var tabletHooksInstalled = false

    private val tabletCallCount = AtomicInteger()
    private val loginButtonLogCount = AtomicInteger()
    private val foldableLogCount = AtomicInteger()

    /** 实验开关：置 false 时只观察、不修改 inTabletEnv 的返回值（用于排查朋友圈媒体加载问题）。 */
    private const val FORCE_TABLET_ENV = true

    override fun onHook() {
        if (!isWeChat()) {
            YLog.warn("WeChatTablet: not wechat host, skip")
            return
        }
        if (!doHostInit(this)) {
            YLog.warn("WeChatTablet: host init failed, skip")
            return
        }

        YLog.warn("start hook wechat tablet(${HostInfo.toVerStr()})")

        if (!hookTinkerApplication()) {
            YLog.warn("WeChatTablet: TinkerApplication hook unavailable, fallback to $WECHAT_APPLICATION")
            hookWeChatApplication()
        }
    }

    /**
     * 优先 hook Tinker 的 onBaseContextAttached：它在 Application 生命周期里足够早。
     * 注意真正的业务 hook 必须**第一个**装，不能被后面的诊断代码挡住——
     * 旧版本把 WXConfig.apply 放在 after 回调的末尾，一旦前面读 Tinker 字段/Intent 抛异常，
     * 业务 hook 就永远不会安装（现象就是"模块完全不生效"）。
     */
    private fun hookTinkerApplication(): Boolean = runCatching {
        TINKER_APPLICATION.toClass().method {
            name("onBaseContextAttached")
            param(Context::class.java, Long::class.java, Long::class.java)
        }.hook {
            after {
                // 顺序很重要：微信下发 Tinker 热修复后，真正的实现类在补丁 dex 里，
                // 由宿主的 DelegateLastClassLoader 加载。必须先采用宿主真正的 classloader，
                // 再去解析并安装 hook；否则 hook 会挂在 base.apk 的旧类上，等于没生效。
                runCatching { adoptHostClassLoader(instance) }
                    .onFailure { YLog.warn("WeChatTablet: 获取宿主 classloader 失败: $it") }

                installTabletHooks()
                runCatching { dumpTinkerResult(instance) }
                    .onFailure { YLog.warn("WeChatTablet: dump tinker result failed: $it") }
            }
        }
        YLog.warn("WeChatTablet: hook $TINKER_APPLICATION.onBaseContextAttached ok")
        true
    }.getOrElse {
        YLog.warn("WeChatTablet: hook TinkerApplication failed: $it")
        false
    }

    /** Tinker 结构变化时的兜底入口，onCreate 一定存在且仍早于所有界面。 */
    private fun hookWeChatApplication(): Boolean = runCatching {
        WECHAT_APPLICATION.toClass().method {
            name("onCreate")
        }.hook {
            after {
                installTabletHooks()
            }
        }
        YLog.warn("WeChatTablet: hook $WECHAT_APPLICATION.onCreate ok")
        true
    }.getOrElse {
        YLog.warn("WeChatTablet: hook $WECHAT_APPLICATION failed: $it")
        false
    }

    /** 只安装一次，每一步都单独兜异常，保证一个失败不影响另一个。 */
    private fun installTabletHooks() {
        if (tabletHooksInstalled) {
            return
        }
        tabletHooksInstalled = true

        val checkPadTablet = resolve("checkPadTablet") { WXConfig.checkPadTablet }
        checkPadTablet?.let { hook ->
            runCatching {
                hook.hook {
                    after {
                        val stack = Throwable().stackTraceToString()
                        val inChatStack = stack.contains(CHAT_CLASS)
                        val inWelcomeStack = stack.contains("WelcomeActivity")
                        if (FORCE_TABLET_ENV) {
                            result = !inChatStack && !inWelcomeStack && !stack.contains("LauncherUI")
                        }
                        if (tabletCallCount.incrementAndGet() <= 3) {
                            YLog.warn("WeChatTablet: inTabletEnv called -> inChat=$inChatStack, result=${!inChatStack}")
                        }
                    }
                }
            }.onSuccess {
                val same = hook.declaringClass.classLoader === HostInfo.appClassLoader
                YLog.warn("WeChatTablet: hooked checkPadTablet = $hook (classLoader 与宿主一致=$same)")
            }.onFailure {
                YLog.warn("WeChatTablet: hook checkPadTablet failed: $it")
            }
        } ?: YLog.warn("WeChatTablet: checkPadTablet not found")

        val visibleLoginButton = resolve("visibleLoginButton") { WXConfig.visibleLoginButton }
        visibleLoginButton?.let { hook ->
            runCatching {
                hook.hook {
                    before {
                        // 注意：YukiHookAPI 的 args(index) 返回的是 ArgsModifyer 代理对象，
                        // 必须用 cast() 取值；这里先取成 Any 再安全转 View，避免强转抛异常。
                        (args(0).cast<Any>() as? View)?.let { loginButton ->
                            if (loginButtonLogCount.incrementAndGet() <= 8) {
                                YLog.warn(
                                    "WeChatTablet: updateLoginAsExdevice 进入, view=${loginButton.javaClass.name}, " +
                                            "visibility=${loginButton.visibility}"
                                )
                            }
                            if (loginButton.isGone) {
                                loginButton.visibility = View.VISIBLE
                            }
                        } ?: run {
                            if (loginButtonLogCount.incrementAndGet() <= 8) {
                                YLog.warn(
                                    "WeChatTablet: updateLoginAsExdevice 第 0 个参数不是 View: " +
                                            "${args(0).cast<Any>()?.javaClass?.name}"
                                )
                            }
                        }
                    }
                    after {
                        // 方法体内部还会再 setVisibility 一次，before 里设置的值会被覆盖，
                        // 所以必须在 after 里再强制显示，否则按钮依旧是隐藏的。
                        (args(0).cast<Any>() as? View)?.let { loginButton ->
                            val afterVisibility = loginButton.visibility
                            if (afterVisibility != View.VISIBLE) {
                                loginButton.visibility = View.VISIBLE
                            }
                            if (loginButtonLogCount.get() <= 8) {
                                YLog.warn(
                                    "WeChatTablet: updateLoginAsExdevice 返回, view=${loginButton.javaClass.name}, " +
                                            "方法体设置的可见性=$afterVisibility, 已强制为 ${loginButton.visibility}"
                                )
                            }
                        }
                    }
                }
            }.onSuccess {
                val same = hook.declaringClass.classLoader === HostInfo.appClassLoader
                YLog.warn("WeChatTablet: hooked visibleLoginButton = $hook (classLoader 与宿主一致=$same)")
            }.onFailure {
                YLog.warn("WeChatTablet: hook visibleLoginButton failed: $it")
            }
        } ?: YLog.warn("WeChatTablet: visibleLoginButton not found")

        // 登录页判断"是否显示平板登录入口"的条件是 inTabletEnv() && !isFoldableDevice()，
        // 平板上 isFoldableDevice() 可能为 true，导致入口整段逻辑被跳过（updateLoginAsExdevice 根本不被调用）。
        // 这里把它的取值打出来并强制为 false，让入口逻辑正常走到。
        // 保留微信原生的折叠设备判断；强制改写会跳过最初的地球登录页。
        runCatching {
            "com.tencent.mm.ui.gk".toClass().method { name("R") }.hook {
                after {
                    val stack = Throwable().stackTraceToString()
                    if (stack.contains("LoginPasswordUI")) {
                        result = true
                    }
                }
            }
            YLog.warn("WeChatTablet: hooked LoginPasswordUI foldable check")
        }.onFailure {
            YLog.warn("WeChatTablet: LoginPasswordUI foldable hook failed: $it")
        }

        runCatching {
            "com.tencent.mm.ui.vas.VASActivity".toClass().method {
                name("onCreate")
                param(android.os.Bundle::class.java)
            }.hook {
                after {
                    if (!instance.javaClass.name.contains("LoginPasswordUI")) return@after
                    val activity = instance as? android.app.Activity ?: return@after
                    val content = activity.findViewById(android.R.id.content) as? ViewGroup ?: return@after
                    if (content.findViewWithTag<View>("wxtablet_phone_pad") != null) return@after
                    val entry = TextView(activity).apply {
                        tag = "wxtablet_phone_pad"
                        text = "同时在手机和平板上使用"
                        gravity = Gravity.CENTER
                        setTextSize(14f)
                        setPadding(0, 18, 0, 18)
                        setOnClickListener {
                            activity.startActivity(Intent().setClassName(activity, "com.tencent.mm.plugin.account.ui.LoginSelectUI"))
                        }
                    }
                    val dp = activity.resources.displayMetrics.density
                    val loginId = activity.resources.getIdentifier("sq1", "id", activity.packageName)
                    val loginButton = activity.findViewById<View>(loginId)
                    val parent = loginButton?.parent as? ViewGroup
                    if (parent != null) {
                        val index = parent.indexOfChild(loginButton)
                        parent.addView(entry, index + 1, ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            (56 * dp).toInt()
                        ))
                    } else {
                        content.addView(entry, FrameLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            (56 * dp).toInt()
                        ))
                    }
                    YLog.warn("WeChatTablet: added LoginPasswordUI phone_and_pad entry")
                }
            }
            YLog.warn("WeChatTablet: hooked LoginPasswordUI entry")
        }.onFailure {
            YLog.warn("WeChatTablet: LoginPasswordUI entry hook failed: $it")
        }

        runCatching {
            "com.tencent.mm.ui.vas.VASActivity".toClass().method {
                name("onCreate")
                param(android.os.Bundle::class.java)
            }.hook {
                after {
                    if (!instance.javaClass.name.contains("MobileInputUI")) return@after
                    val activity = instance as? android.app.Activity ?: return@after
                    val content = activity.findViewById(android.R.id.content) as? ViewGroup ?: return@after
                    if (content.findViewWithTag<View>("wxtablet_phone_pad_mobile") != null) return@after
                    val entry = TextView(activity).apply {
                        tag = "wxtablet_phone_pad_mobile"
                        text = "同时在手机和平板上使用"
                        gravity = Gravity.CENTER
                        setTextSize(14f)
                        setPadding(0, 18, 0, 18)
                        setOnClickListener {
                            activity.startActivity(Intent().setClassName(activity, "com.tencent.mm.plugin.account.ui.LoginSelectUI"))
                        }
                    }
                    val dp = activity.resources.displayMetrics.density
                    val agreeId = activity.resources.getIdentifier("iol", "id", activity.packageName)
                    val agree = activity.findViewById<View>(agreeId)
                    val parent = agree?.parent as? ViewGroup
                    if (parent != null) {
                        parent.addView(entry, parent.indexOfChild(agree) + 1, ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT, (56 * dp).toInt()
                        ))
                    } else {
                        content.addView(entry, FrameLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT, (56 * dp).toInt()
                        ))
                    }
                    YLog.warn("WeChatTablet: added MobileInputUI phone_and_pad entry")
                }
            }
            YLog.warn("WeChatTablet: hooked MobileInputUI entry")
        }.onFailure {
            YLog.warn("WeChatTablet: MobileInputUI entry hook failed: $it")
        }

        // 新版微信的第一个选项仍然存在，但标题资源可能为空，导致界面只显示“作为手机使用”。
        // 在页面创建完成后补回明确标题，保留微信原有点击逻辑。
        runCatching {
            "com.tencent.mm.plugin.account.ui.LoginSelectUI".toClass().method {
                name("onCreate")
                param(android.os.Bundle::class.java)
            }.hook {
                after {
                    val screen = instance.javaClass.field { name("d") }.get(instance).cast<Any>() ?: return@after
                    val find = screen.javaClass.methods.firstOrNull {
                        it.name == "h" && it.parameterTypes.size == 1 && it.parameterTypes[0] == String::class.java
                    } ?: return@after
                    val pref = find.invoke(screen, "phone_and_pad") ?: return@after
                    screen.javaClass.methods.firstOrNull {
                        it.name == "l" && it.parameterTypes.size == 2 &&
                                it.parameterTypes[0] == String::class.java &&
                                it.parameterTypes[1] == Boolean::class.javaPrimitiveType
                    }?.invoke(screen, "phone_and_pad", false)
                    val setTitle = pref.javaClass.methods.firstOrNull {
                        it.name == "S" && it.parameterTypes.size == 1
                    } ?: return@after
                    setTitle.invoke(pref, "手机和平板同时登录")
                    screen.javaClass.methods.firstOrNull {
                        it.name == "notifyDataSetChanged" && it.parameterTypes.isEmpty()
                    }?.invoke(screen)
                    YLog.warn("WeChatTablet: restored phone_and_pad title")
                }
            }
            YLog.warn("WeChatTablet: hooked LoginSelectUI title restore")
        }.onFailure {
            YLog.warn("WeChatTablet: LoginSelectUI title hook failed: $it")
        }

        // 欢迎页保持原样；点击手机号登录时，把原本的手机号页改为登录方式选择页。
        runCatching {
            "com.tencent.mm.ui.MMFragmentActivity".toClass().method {
                name("startActivity")
                param(Intent::class.java)
            }.hook {
                before {
                    val host = instance.javaClass.name
                    val intent = args(0).cast<Intent>() ?: return@before
                    val target = intent.component?.className ?: return@before
                    if ((host.contains("WelcomeActivity") || host.contains("LoginPasswordUI")) &&
                        target.contains("MobileInputUI")) {
                        intent.component = android.content.ComponentName(
                            instance as Context,
                            "com.tencent.mm.plugin.account.ui.LoginSelectUI"
                        )
                        YLog.warn("WeChatTablet: WelcomeActivity login redirected to LoginSelectUI")
                    }
                }
            }
            YLog.warn("WeChatTablet: hooked WelcomeActivity login redirect")
        }.onFailure {
            YLog.warn("WeChatTablet: WelcomeActivity redirect hook failed: $it")
        }
    }

    private inline fun resolve(
        tag: String,
        block: () -> java.lang.reflect.Method?
    ): java.lang.reflect.Method? = runCatching(block)
        .onFailure { YLog.warn("WeChatTablet: resolve $tag failed: $it") }
        .getOrNull()
        .also { YLog.warn("WeChatTablet: $tag = $it") }

    private fun dumpTinkerResult(instance: Any) {
        YLog.warn("TinkerLoader.tryLoad -> classloader = ${HostInfo.appClassLoader}")
        YLog.warn("TinkerLoader.tryLoad -> instanceClassloader = ${instance.javaClass.classLoader}")

        val intent = instance.javaClass.field { name("tinkerResultIntent");superClass() }
            .get(instance).cast<Intent>()
        intent?.extras?.let {
            for (key in it.keySet()) {
                YLog.warn("TinkerLoader.tryLoad -> ResultIntent($key = ${it.get(key)})")
            }
        }
    }

    /** 采用宿主当前真正的 classloader（可能是 Tinker 热修复的 DelegateLastClassLoader）。 */
    private fun adoptHostClassLoader(instance: Any) {
        val classloader = instance.javaClass.method { name = "getClassLoader";superClass() }
            .get(instance).invoke<ClassLoader>() ?: return
        if (classloader !== HostInfo.appClassLoader) {
            HostInfo.appClassLoader = classloader
            YLog.warn("WeChatTablet: 采用宿主 classloader = $classloader")
        }
    }

    private fun isWeChat(): Boolean {
        return WECHAT_APPLICATION.toClassOrNull(appClassLoader) != null
    }

    /** 任何一项宿主信息读失败都不应该阻断 hook，缺失时退化成 unknown。 */
    private fun doHostInit(packageParam: PackageParam): Boolean = runCatching {
        FastKv.initialize("${appInfo.dataDir}/files/WeChatTablet/")
        HostInfo.apply {
            modulePath = packageParam.moduleAppFilePath
            appPackageName = packageParam.packageName
            appFilePath = packageParam.appInfo.sourceDir
            appClassLoader = packageParam.appClassLoader
                ?: this@TabletHooker.appClassLoader
                ?: ClassLoader.getSystemClassLoader()

            val buildConfigClass = runCatching { "com.tencent.mm.boot.BuildConfig".toAppClass() }.getOrNull()
            isPlay = runCatching {
                buildConfigClass!!.field { name = "BUILD_TAG" }.get().string().contains("_GP_")
            }.getOrDefault(false)
            verName = runCatching {
                buildConfigClass!!.field { name = "VERSION_NAME" }.get().string()
            }.getOrDefault("unknown")
            verCode = runCatching {
                buildConfigClass!!.field { name = "VERSION_CODE" }.get().int()
            }.getOrDefault(0)
            clientVer = runCatching {
                buildConfigClass!!.field { name = "CLIENT_VERSION_ARM64" }.get().string()
            }.getOrDefault("unknown")
        }
        true
    }.getOrElse {
        YLog.warn("WeChatTablet: doHostInit failed: $it")
        false
    }
}
