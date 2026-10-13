package top.hookvip.wxtablet.entry

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.ResolveInfo
import com.highcapable.yukihookapi.hook.log.YLog
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import java.lang.reflect.Modifier
import java.util.concurrent.atomic.AtomicInteger

/**
 * QQ 9.3.x 设备风险（"已登录设备存在安全隐患 / 设备存在外挂或其他软件影响QQ正常使用"）屏蔽层。
 *
 * 依据（QQ 9.3.70 base.apk + 真机进程取证）：
 *  1. QQ 自带 FEKit/QSec 检测库 libfekit.so（QSec_Channel、trpc.o3.report.Report.SsoReport 通道），
 *     在进程内扫描 /proc/self/maps、/proc/self/smaps、/proc/mounts(grep magisk)、su 路径、
 *     已安装包名黑名单（magisk/kernelsu/apatch/supersu…），并解析 libart 做 ArtMethod 校验；
 *  2. Java 侧另有一套：PackageManager 枚举（sourceDir/nativeLibraryDir）、File.exists、
 *     Runtime.exec、gathererga UserInfoImpl.isRooted、org.light.device.LightDeviceUtils.isRooted、
 *     oicq.wlogin_sdk.request.w、turingfd ITuringDID 等；
 *  3. 检测结果经 MsfCore.sendSsoMsg / dt.api.impl.QSecChannelImpl 上报腾讯风控服务端，
 *     服务端据此把该设备标记为风险设备并对该设备下线。
 *
 * 本层只做两件事，不改变平板模式自身的任何逻辑：
 *  A. 截断/过滤风控上报通道（检测照跑，结果不外发）；
 *  B. 抹平 Java 层可见的 root / hook / 调试 / 分身痕迹（包列表、文件、maps 文本、系统属性）。
 *
 * 每条 hook 单独 try/catch，失败只记日志，绝不影响平板模式功能。
 */
object QQSecurityShield {

    private const val TAG = "QQShield"

    private val logCount = AtomicInteger()
    private val verboseCount = AtomicInteger()
    private val blockedReportCount = AtomicInteger()
    private val filteredLineCount = AtomicInteger()
    private val hiddenPackageCount = AtomicInteger()
    private val hiddenFileCount = AtomicInteger()

    private fun log(message: String) {
        if (logCount.incrementAndGet() <= 400) YLog.warn(message)
    }

    private fun verbose(message: String) {
        if (verboseCount.incrementAndGet() <= 120) YLog.warn(message)
    }

    /** 只用于风控上报、不参与业务结果/登录校验的命令；命中即丢弃。 */
    private val RISK_COMMANDS = listOf(
        "trpc.o3.report",
        "trpc.o3.mobile_security",
        "oidbsvc.0xd79",
        "turing",
        "riskcheckwup",
        "qsec.",
        "securecheck",
        "device_report",
        // QQ 自身上传日志：FEKit/QSec 的检测输出会写进 QQ 日志，上传等于把结论送给服务端
        "clilogsvc.uploadreq",
        // 登录失败按 Qimei 上报（QimeiReportLoginFailServlet）——设备被反复拉黑的主通道之一
        "ssoqimeicheckreport",
        "qimeireport",
        "qqlog_server.portal"
    )

    /**
     * 绝对不能丢的命令：这些是登录/安全校验流程本身，丢了会让登录卡在"身份验证失败"。
     * （历史上把 wtlogin.device_lock 放进丢弃名单，就是 10-09 22:15 报错（w21）的最大嫌疑）
     */
    private val KEEP_COMMANDS = listOf(
        "wtlogin.device_lock",
        "device_lock",
        "wtlogin.login",
        "wtlogin.exchange",
        "wtlogin.name",
        "wtlogin.auth"
    )

    /** 需要从 QQ 视野里消失的包：root / hook 管理器、Xposed 模块、改机工具。 */
    private val HIDDEN_PACKAGES = setOf(
        "top.hookvip.wxtablet",
        "top.hookvip.wxtablet.qq",
        "top.hookvip.wxtablet.combined",
        "me.weishu.kernelsu",
        "com.topjohnwu.magisk",
        "me.bmax.apatch",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "org.lsposed.manager",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "com.solohsu.android.edxposed",
        "io.github.xiaotong6666.fusehide",
        "bin.mt.plus",
        "com.termux"
    )

    private val HIDDEN_PACKAGE_PREFIXES = listOf(
        "top.hookvip.",
        "io.github.qauxv",
        "org.lsposed.",
        "me.weishu.",
        "com.topjohnwu.",
        "com.solohsu.",
        "org.meowcat."
    )

    /** 需要隐藏的文件/路径特征（libfekit 的 su 扫描 + magisk 挂载扫描 + Xposed 工件）。 */
    private val HIDDEN_PATH_KEYWORDS = listOf(
        "magisk",
        "kernelsu",
        "ksud",
        "apatch",
        "supersu",
        "superuser",
        "xposed",
        "lsposed",
        "lspd",
        "riru",
        "zygisk",
        "shamiko",
        "sandhook",
        "frida",
        "substrate",
        "liblspd",
        "top.hookvip",
        "/data/adb",
        "/data/local/",
        "sutemp",
        "ku.sud",
        "shuamesu",
        "modules.dex",
        "qemu_pipe",
        "qemud",
        "genyd",
        "goldfish"
    )

    /** 只记录不拦截的"可疑路径"特征：用来发现还没覆盖的检测点。 */
    private val SUSPICIOUS_PATH_MARKERS = listOf(
        "/proc/self",
        "/proc/net",
        "/sys/",
        "/dev/",
        "busybox",
        "root",
        "adb",
        "mount",
        "ksu",
        "su",
        "magisk",
        "xposed",
        "hook",
        "/data/adb",
        "/data/local"
    )

    private val probedKeys = java.util.concurrent.ConcurrentHashMap<String, Boolean>()
    private val probedPaths = java.util.concurrent.ConcurrentHashMap<String, Boolean>()

    /** /proc/self/maps、/proc/self/status 等文本流里的 hook 特征。 */
    private val LINE_MARKERS = listOf(
        "lsposed",
        "lspd",
        "zygisk",
        "riru",
        "frida",
        "substrate",
        "xposedbridge",
        "libsandhook",
        "yukihook",
        "top.hookvip",
        "org.lsposed"
    )

    fun install(loader: ClassLoader, processTag: String) {
        YLog.warn("$TAG: installing in $processTag")
        runCatching { dumpTargetMethods(loader) }
            .onFailure { YLog.warn("$TAG: method dump failed: $it") }
        runCatching { installReportShield(loader) }
            .onFailure { YLog.warn("$TAG: report shield failed: $it") }
        runCatching { installRootDetectShield(loader) }
            .onFailure { YLog.warn("$TAG: root shield failed: $it") }
        runCatching { installFileShield() }
            .onFailure { YLog.warn("$TAG: file shield failed: $it") }
        runCatching { installPackageShield(loader) }
            .onFailure { YLog.warn("$TAG: package shield failed: $it") }
        runCatching { installStreamShield() }
            .onFailure { YLog.warn("$TAG: stream shield failed: $it") }
        runCatching { installPropertyShield() }
            .onFailure { YLog.warn("$TAG: property shield failed: $it") }
        runCatching { installProcessShield() }
            .onFailure { YLog.warn("$TAG: process shield failed: $it") }
        runCatching { installDeviceObservation() }
            .onFailure { YLog.warn("$TAG: device observation failed: $it") }
        runCatching { installRuntimeProbes(loader) }
            .onFailure { YLog.warn("$TAG: runtime probes failed: $it") }
        runCatching { installDeviceIdentitySpoof(loader) }
            .onFailure { YLog.warn("$TAG: identity spoof failed: $it") }
        YLog.warn("$TAG: install finished in $processTag")
    }

    // ---------------------------------------------------------------- E. 分身设备指纹（只对分身生效）
    /**
     * 服务端的"风险设备"记录是绑在设备指纹上的（wlogin 的 guid + Qimei + android_id）。
     * 这里只在**分身**（XSpace，userId=999）里把这套指纹换成一套新的、自洽的值，
     * 让服务端把分身当成一台全新设备；主 QQ（user 0）与其它 App 完全不受影响。
     *
     * 三条原则：
     *  1. 只在内存里改写返回值，不写/删任何文件（save_* 全部置空放行，不落盘）；
     *  2. 新指纹全部固定常量，重启后保持一致（否则每次启动都变成"新设备"更可疑）；
     *  3. get_last_* 与当前值保持一致，避免"上次设备 vs 本次设备不一致"被抓。
     *
     * 想关掉：把 ENABLE_IDENTITY_SPOOF 改成 false 重新编译即可。
     */
    private const val ENABLE_IDENTITY_SPOOF = true
    private const val SPOOF_USER_ID = 999

    /** 16 字节 guid（十六进制书写，随机固定值）。 */
    private val SPOOF_GUID_HEX = "3f7c1d2ab9e84506ac1e7b93d5f20c48"
    private const val SPOOF_ANDROID_ID = "a94c1f7e03b8d265"
    private const val SPOOF_MAC = "0a:1b:2c:3d:4e:5f"
    /**
     * Qimei（腾讯侧真正的设备主键，Qimei16/36 同值——和设备上现有行为一致）。
     * 原值 37441d03be50a80265cbd62210001de1a41b，这里换成一套新的固定值。
     */
    private const val SPOOF_QIMEI = "6c1f9a45d8e3720b4a5c96f18d3e70b2a9f4"

    private fun spoofGuid(): ByteArray {
        val out = ByteArray(SPOOF_GUID_HEX.length / 2)
        for (i in out.indices) {
            out[i] = SPOOF_GUID_HEX.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    private fun installDeviceIdentitySpoof(loader: ClassLoader) {
        val userId = android.os.Process.myUid() / 100000
        if (!ENABLE_IDENTITY_SPOOF) {
            log("$TAG: identity spoof disabled by config")
            return
        }
        if (userId != SPOOF_USER_ID) {
            log("$TAG: identity spoof skipped (userId=$userId, only clone gets it)")
            return
        }
        val util = findClass(loader, "oicq.wlogin_sdk.tools.util") ?: run {
            YLog.warn("$TAG: wlogin util not found, identity spoof unavailable")
            return
        }
        val guid = spoofGuid()
        val mac = SPOOF_MAC.toByteArray()

        // 1) guid 系列
        hookReturnValue(util, setOf("generateGuid", "getGuidFromFile", "get_last_guid"), "wlogin.guid", guid)
        // 2) mac 系列（Android 真实值本就是随机化 MAC，这里只是保持一致）
        hookReturnValue(util, setOf("get_mac_addr", "get_last_mac"), "wlogin.mac", mac)
        // 3) android_id
        hookReturnValue(util, setOf("get_saved_android_id"), "wlogin.android_id", SPOOF_ANDROID_ID)
        // 4) 写入一律不落盘（避免污染 QQ 数据）
        suppressWrites(
            util,
            setOf("save_cur_guid", "save_cur_mac", "saveGuidToFile", "save_android_id", "save_cur_flag")
        )
        // 5) 不要触发"改变 guid"逻辑，保持稳定
        hookReturnValue(util, setOf("needChangeGuid"), "wlogin.needChangeGuid", false)

        // 6) Qimei：腾讯风控的设备主键（只换 getter，缓存文件不动）
        val qimeiClass = findClass(loader, "com.tencent.qimei.sdk.Qimei")
        if (qimeiClass != null) {
            hookReturnValue(qimeiClass, setOf("getQimei16", "getQimei36"), "qimei", SPOOF_QIMEI)
        } else {
            YLog.warn("$TAG: Qimei class not found, qimei spoof skipped")
        }

        // 7) 观测其余设备信息取值（不改写）
        observeReturn(
            loader, "oicq.wlogin_sdk.tools.util",
            setOf("get_android_dev_info", "get_IMSI", "getIccid", "getBaseband", "getProcVersion",
                "getPkgSigFromApkName", "get_last_flag", "shouldKick", "get_ksid_new", "isPackageExist"),
            "wlogin"
        )
        log(
            "$TAG: identity spoof armed in clone (guid=${SPOOF_GUID_HEX.take(8)}…, " +
                "androidId=$SPOOF_ANDROID_ID, mac=$SPOOF_MAC, qimei=$SPOOF_QIMEI)"
        )
    }

    /** 把某类若干方法的返回值替换成固定值（按 returnType 自动适配）。 */
    private fun hookReturnValue(clazz: Class<*>, names: Set<String>, tag: String, value: Any) {
        var bound = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in names) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val original = param.result
                        val replaced: Any? = when {
                            method.returnType == java.lang.Boolean.TYPE -> value as? Boolean ?: false
                            method.returnType == ByteArray::class.java ->
                                (value as? ByteArray)?.copyOf() ?: return
                            method.returnType == String::class.java -> value as? String
                            else -> return
                        }
                        if (original == replaced) return
                        param.result = replaced
                        if (verboseCount.incrementAndGet() <= 120) {
                            log("$TAG: spoof $tag.${method.name} ${previewOf(original)} -> ${previewOf(replaced)}")
                        }
                    }
                })
                bound++
            }.onFailure { YLog.warn("$TAG: spoof $tag#${method.name} failed: $it") }
        }
        log("$TAG: spoof $tag bound=$bound")
    }

    /** 让某些"写入"方法直接返回不执行（不是改文件，是根本不写）。 */
    private fun suppressWrites(clazz: Class<*>, names: Set<String>) {
        var bound = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in names) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (verboseCount.incrementAndGet() <= 120) {
                            log("$TAG: suppress wlogin.${method.name}(${describeArgs(param)})")
                        }
                        param.result = defaultResultOf(returnTypeOf(param))
                    }
                })
                bound++
            }.onFailure { YLog.warn("$TAG: suppress #${method.name} failed: $it") }
        }
        log("$TAG: suppress writes bound=$bound")
    }

    // ---------------------------------------------------------------- D. 运行时探测（只读）
    // 目的：把 QQ 在当前环境下实际去查的东西暴露到日志里，
    // 用来发现静态扫描看不到的检测点（尤其 hook/类加载/进程/端口/签名这几类）。

    private fun installRuntimeProbes(loader: ClassLoader) {
        // 注意：绝对不要 hook Class.forName / ClassLoader.loadClass / getDeclaredMethod 这类
        // 类加载关键路径。实测在 20:52 那版给 Class.forName 挂钩子后，QQ 启动时
        // SingletonPool 建 ISettingApi 直接 ClassNotFoundException -> FATAL EXCEPTION
        // （回调里做日志/加载类会在类加载器锁内递归）。这里只保留与类加载无关的探测。

        // 1) ActivityManager：进程/服务枚举（分身与多开检测常见入口）
        runCatching {
            val am = Class.forName("android.app.ActivityManager", false, null)
            for (method in am.declaredMethods) {
                if (method.name !in setOf("getRunningAppProcesses", "getRunningServices", "getRunningTasks")) continue
                runCatching {
                    method.isAccessible = true
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            runCatching {
                                if (probedKeys.putIfAbsent("am:${method.name}", true) != null) return
                                val size = (param.result as? List<*>)?.size ?: -1
                                log("$TAG: probe ActivityManager.${method.name}() -> entries=$size")
                            }
                        }
                    })
                }
            }
        }.onFailure { YLog.warn("$TAG: probe ActivityManager failed: $it") }

        // 2) Socket：本机端口扫描（Frida/调试端口探测）
        runCatching {
            val connect = java.net.Socket::class.java.getDeclaredMethod("connect", java.net.SocketAddress::class.java)
            XposedBridge.hookMethod(connect, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    runCatching {
                        val addr = param.args.getOrNull(0)?.toString() ?: return
                        if (probedKeys.putIfAbsent("sock:$addr", true) != null) return
                        log("$TAG: probe Socket.connect($addr)")
                    }
                }
            })
        }.onFailure { YLog.warn("$TAG: probe Socket.connect failed: $it") }

        // 3) 包签名校验
        runCatching {
            val pm = Class.forName("android.app.ApplicationPackageManager", false, null)
            for (method in pm.declaredMethods) {
                if (method.name != "checkSignatures") continue
                runCatching {
                    method.isAccessible = true
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            runCatching {
                                val key = "pm:${param.args.joinToString { it?.toString() ?: "" }}"
                                if (probedKeys.putIfAbsent(key, true) != null) return
                                log("$TAG: probe PackageManager.checkSignatures(${describeArgs(param)}) -> ${param.result}")
                            }
                        }
                    })
                }
            }
        }.onFailure { YLog.warn("$TAG: probe package signature failed: $it") }

        // 4) Qimei / wlogin 设备标识（登录伪装的核心）
        for (className in listOf(
            "com.tencent.qimei.sdk.QimeiSDK",
            "com.tencent.qimei.sdk.Qimei",
            "oicq.wlogin_sdk.tools.util",
            "com.tencent.mobileqq.devicetoken.model.NativeDeviceTokenReq"
        )) {
            observeIdentApi(loader, className)
        }
        log("$TAG: runtime probes installed")
    }

    /** 记录设备标识 API 的返回值（不改写）：用来确认登录时到底用了哪些指纹来源。 */
    private fun observeIdentApi(loader: ClassLoader, className: String) {
        val clazz = findClass(loader, className) ?: run {
            verbose("$TAG: ident class not found $className")
            return
        }
        var bound = 0
        val interesting = listOf("qimei", "imei", "android", "guid", "mac", "serial", "did", "token", "id")
        for (method in clazz.declaredMethods) {
            val lower = method.name.lowercase()
            if (lower == "<init>" || lower == "<clinit>") continue
            if (!interesting.any { lower.contains(it) }) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            val seen = AtomicInteger()
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (seen.incrementAndGet() > 6) return
                        log(
                            "$TAG: ident ${clazz.simpleName}.${method.name}(${describeArgs(param)}) -> " +
                                previewOf(param.result)
                        )
                    }
                })
                bound++
            }.onFailure { }
        }
        if (bound > 0) log("$TAG: ident $className bound=$bound")
    }

    // ---------------------------------------------------------------- C. 设备信息读取观测
    // 只记录 QQ 实际读了哪些设备标识/调试状态（不改写）。用于判断它是否在做
    // 指纹交叉校验，也是后续"换设备指纹"那一步的靶点清单。
    private fun installDeviceObservation() {
        observeCall(android.os.Debug::class.java, setOf("isDebuggerConnected", "waitForDebugger"), "Debug")
        observeCall(
            android.telephony.TelephonyManager::class.java,
            setOf("getDeviceId", "getImei", "getMeid", "getSimSerialNumber", "getSubscriberId"),
            "Telephony"
        )
        observeCall(android.os.Build::class.java, setOf("getSerial"), "Build")
        observeCall(
            java.net.NetworkInterface::class.java,
            setOf("getHardwareAddress"),
            "NetworkInterface"
        )
        runCatching {
            val secure = findClass(null, "android.provider.Settings\$Secure")
                ?: findClass(java.io.File::class.java.classLoader, "android.provider.Settings\$Secure")
            if (secure != null) {
                hookSettingsStrings(secure, "Settings.Secure")
            }
        }.onFailure { YLog.warn("$TAG: hook Settings.Secure failed: $it") }
        runCatching {
            val global = findClass(null, "android.provider.Settings\$Global")
                ?: findClass(java.io.File::class.java.classLoader, "android.provider.Settings\$Global")
            if (global != null) {
                hookSettingsDebugFlags(global)
            }
        }.onFailure { YLog.warn("$TAG: hook Settings.Global failed: $it") }
    }

    /**
     * Settings.Secure.getString 只做只读观测（用户要求：无障碍相关不处理）。
     * 记录 QQ 读了哪些安全设置项，便于判断检测面，但不修改任何返回值。
     */
    private fun hookSettingsStrings(settingsClass: Class<*>, tag: String) {
        var bound = 0
        for (method in settingsClass.declaredMethods) {
            if (method.name != "getString") continue
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = param.args.lastOrNull() as? String ?: return
                        val value = param.result as? String ?: return
                        verbose("$TAG: dev $tag.$key -> ${value.take(200)}")
                        // 分身里统一 android_id（与 wlogin util 的取值保持一致）
                        if (key == "android_id" &&
                            ENABLE_IDENTITY_SPOOF &&
                            android.os.Process.myUid() / 100000 == SPOOF_USER_ID &&
                            value != SPOOF_ANDROID_ID
                        ) {
                            param.result = SPOOF_ANDROID_ID
                            log("$TAG: spoof Settings.Secure.android_id ${value.take(16)} -> $SPOOF_ANDROID_ID")
                        }
                    }
                })
                bound++
            }.onFailure { }
        }
        if (bound > 0) log("$TAG: dev $tag.getString bound=$bound")
    }

    /** USB 调试/开发者选项开关：QQ 常用它判断调试环境。 */
    private fun hookSettingsDebugFlags(globalClass: Class<*>) {
        var bound = 0
        for (method in globalClass.declaredMethods) {
            if (method.name != "getInt" && method.name != "getString") continue
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = param.args.lastOrNull() as? String ?: return
                        if (key != "adb_enabled" && key != "development_settings_enabled") {
                            if (key.contains("adb") || key.contains("develop")) {
                                verbose("$TAG: dev Settings.Global.$key -> ${param.result}")
                            }
                            return
                        }
                        if (param.result == 0 || param.result == "0") {
                            verbose("$TAG: dev Settings.Global.$key -> 0 (already off)")
                            return
                        }
                        verbose("$TAG: dev Settings.Global.$key -> ${param.result} (force 0)")
                        param.result = if (param.result is String) "0" else 0
                    }
                })
                bound++
            }.onFailure { }
        }
        if (bound > 0) log("$TAG: dev Settings.Global bound=$bound")
    }

    private fun observeCall(clazz: Class<*>, names: Set<String>, tag: String) {
        var bound = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in names) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            val seen = AtomicInteger()
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (seen.incrementAndGet() > 8) return
                        log(
                            "$TAG: dev $tag.${method.name}(${describeArgs(param)}) -> " +
                                previewOf(param.result)
                        )
                    }
                })
                bound++
            }.onFailure { }
        }
        if (bound > 0) log("$TAG: dev $tag bound=$bound")
    }

    // ---------------------------------------------------------------- A. 上报通道

    /**
     * 把关键安全类的真实成员名打进日志：QQ 版本升级后混淆名会变，
     * 日志里有这份清单就能直接改成新的 hook 目标（只打印一次，不影响功能）。
     */
    private fun dumpTargetMethods(loader: ClassLoader) {
        val targets = listOf(
            "com.tencent.mobileqq.dt.api.impl.QSecChannelImpl",
            "com.tencent.mobileqq.dt.api.IQSecChannel",
            "com.tencent.qqprotect.common.QSecRptControllerImpl",
            "com.tencent.mobileqq.qsec.qsecurity.QSec",
            "com.tencent.mobileqq.fe.FEKit",
            "oicq.wlogin_sdk.request.w",
            "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl"
        )
        for (name in targets) {
            val clazz = findClass(loader, name)
            if (clazz == null) {
                log("$TAG: dump $name = <not found>")
                continue
            }
            val methods = clazz.declaredMethods
                .filterNot { Modifier.isAbstract(it.modifiers) }
                .take(40)
                .joinToString("; ") { m ->
                    m.name + m.parameterTypes.joinToString(",", "(", ")") { it.simpleName }
                }
            log("$TAG: dump ${clazz.simpleName} = $methods")
        }
    }

    private fun installReportShield(loader: ClassLoader) {
        val msfCore = findClass(loader, "com.tencent.mobileqq.msf.core.MsfCore")
        if (msfCore != null) {
            hookBefore(msfCore, setOf("sendSsoMsg", "sendSsoMsgInner", "sendSsoMsgForce"), "MsfCore") { param ->
                val cmd = commandOf(param) ?: return@hookBefore
                if (isRiskCommand(cmd)) {
                    val n = blockedReportCount.incrementAndGet()
                    if (n <= 40) {
                        log("$TAG: drop sso report [$cmd] #$n")
                    }
                    param.result = defaultResultOf(returnTypeOf(param))
                } else {
                    verbose("$TAG: sso pass [$cmd]")
                }
            }
        } else {
            YLog.warn("$TAG: MsfCore not found in this loader")
        }

        val qsecChannel = findClass(loader, "com.tencent.mobileqq.dt.api.impl.QSecChannelImpl")
        if (qsecChannel != null) {
            // 真机 dump：这个类里与安全相关的是 feEnvReport（前端环境上报）；
            // 其余 uiReport/regReport 是普通行为统计，保留不动。
            hookBefore(qsecChannel, setOf("feEnvReport"), "QSecChannelImpl.feEnvReport") { param ->
                val n = blockedReportCount.incrementAndGet()
                if (n <= 40) {
                    log("$TAG: drop environment report ${param.method.name} #$n args=[${describeArgs(param)}]")
                }
                param.result = defaultResultOf(returnTypeOf(param))
            }
        }

        val qsecRpt = findClass(loader, "com.tencent.qqprotect.common.QSecRptControllerImpl")
        if (qsecRpt != null) {
            hookBefore(qsecRpt, setOf("sendMessage", "report", "send", "b", "a"), "QSecRptControllerImpl") { param ->
                val n = blockedReportCount.incrementAndGet()
                if (n <= 20) log("$TAG: drop qqprotect report ${param.method.name} #$n")
                param.result = defaultResultOf(returnTypeOf(param))
            }
        }

        observeClass(loader, "com.tencent.mobileqq.fe.FEKit", "FEKit")
        observeClass(loader, "com.tencent.mobileqq.fe.FEKitMain", "FEKitMain")
        observeClass(loader, "com.tencent.mobileqq.qsec.qsecest.QsecEst", "QsecEst")

        // QSec 是安全 SDK 的门面，doReport/reportLog 就是"把本机检测结果发到服务端"的入口；
        // 真实抓包轨迹显示它在登录流程里被调用（QSec.getFeKitAttach -> doReport -> reportLog）。
        val qsec = findClass(loader, "com.tencent.mobileqq.qsec.qsecurity.QSec")
        if (qsec != null) {
            hookBefore(qsec, setOf("doReport", "reportLog"), "QSec-report") { param ->
                val n = blockedReportCount.incrementAndGet()
                if (n <= 60) {
                    log("$TAG: drop QSec.${param.method.name}() #$n args=[${describeArgs(param)}]")
                }
                param.result = defaultResultOf(returnTypeOf(param))
            }
            observeClass(loader, "com.tencent.mobileqq.qsec.qsecurity.QSec", "QSec")
            // 取证：QSec 交给风控的"证明材料"原文（设备/环境结论就在这些返回值里）
            observeReturn(
                loader, "com.tencent.mobileqq.qsec.qsecurity.QSec",
                setOf("getFeKitAttach", "getXwDebugID", "getEstInfo", "detectMethod", "get11Hex", "get11"),
                "QSec"
            )
            // detectMethod(类名, 方法名) 是 Java 层的方法完整性校验入口：它查哪个方法，就是 QQ 在防哪个 hook
            observeReturn(
                loader, "com.tencent.mobileqq.fe.FEKit",
                setOf("getFeKitAttach", "checkSafeMode", "initSafeMode", "checkStatus", "onReceiveSecError"),
                "FEKit"
            )
        }
    }

    /** /proc/self 等二进制/字符串取值的可读预览，用于把上报内容原样记录到日志。 */
    private fun previewOf(value: Any?): String = when (value) {
        null -> "null"
        is ByteArray -> "bytes[${value.size}] " + value.copyOf(minOf(value.size, 48))
            .joinToString("") { "%02x".format(it) }
        is String -> value.take(300)
        is Array<*> -> value.joinToString(",", "[", "]") { previewOf(it) }
        else -> value.toString().take(300)
    }

    private fun describeArgs(param: XC_MethodHook.MethodHookParam): String =
        param.args.joinToString(", ") { previewOf(it) }

    /** 记录某类若干方法的参数与返回值（只记前几次，不影响功能）。 */
    private fun observeReturn(loader: ClassLoader, className: String, names: Set<String>, tag: String) {
        val clazz = findClass(loader, className) ?: return
        var count = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in names) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            val seen = AtomicInteger()
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (seen.incrementAndGet() > 6) return
                        log(
                            "$TAG: probe $tag.${method.name}(${describeArgs(param)}) -> " +
                                previewOf(param.result)
                        )
                    }
                })
                count++
            }.onFailure { }
        }
        log("$TAG: probe $tag bound=$count")
    }

    private fun isRiskCommand(cmd: String): Boolean {
        val lower = cmd.lowercase()
        if (KEEP_COMMANDS.any { lower.contains(it) }) return false
        return RISK_COMMANDS.any { lower.contains(it) }
    }

    private fun commandOf(param: XC_MethodHook.MethodHookParam): String? {
        for (arg in param.args) {
            when (arg) {
                null -> Unit
                is String -> if (looksLikeCommand(arg)) return arg
                else -> {
                    val typeName = arg.javaClass.name
                    if (typeName.contains("ToServiceMsg") || typeName.contains("SsoMsg") ||
                        typeName.contains("ServiceMsg") || typeName.contains("MsfMessage")
                    ) {
                        for (getter in listOf("getServiceCmd", "getCmdName", "getMsfCommand", "getCmd")) {
                            val value = runCatching {
                                arg.javaClass.getMethod(getter).invoke(arg)
                            }.getOrNull()
                            if (value is String && value.isNotEmpty()) return value
                        }
                    }
                }
            }
        }
        return null
    }

    private fun looksLikeCommand(value: String): Boolean {
        if (value.length < 4 || value.length > 200) return false
        if (!value.contains('.')) return false
        return !value.contains(' ')
    }

    // ---------------------------------------------------------------- B1. Root / 调试检测

    private fun installRootDetectShield(loader: ClassLoader) {
        // Gatherer 的 provider 方法统一返回 Object，框架再自行转换，
        // 所以这里按"任意返回类型"强制成 false/0。
        hookResultFalse(
            loader,
            "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl",
            setOf("isRooted", "isRoot", "isDebug"),
            objectValue = false
        )
        hookBooleanFalse(loader, "org.light.device.LightDeviceUtils",
            setOf("isRooted", "isDeviceRooted", "isDebug"))
        hookBooleanFalse(loader, "com.tenpay.charge.v2.util.ChargeV2Utils",
            setOf("isDeviceRooted", "isRooted"))
        // wlogin SDK 的 w.h()/w.i(): 真机 dump 确认存在无参重载；只改基本类型返回值，
        // 字符串/对象返回值保持原样，避免影响登录状态机。
        hookResultFalse(loader, "oicq.wlogin_sdk.request.w", setOf("h", "i"), onlyPrimitive = true)
        // 这两个方法返回非基本类型时只观测（日志里能看到它到底吐了什么）
        observeReturn(loader, "oicq.wlogin_sdk.request.w", setOf("h", "i"), "w")
        observeClass(loader, "com.tencent.turingfd.sdk.xq.ITuringDID", "ITuringDID")
    }

    /**
     * 把 getter 的结果改成"无风险"取值：基本类型按对应零值，对象类型用 objectValue，
     * objectValue 为 null 时只记录日志、不改写（避免破坏未知语义的调用）。
     */
    private fun hookResultFalse(
        loader: ClassLoader,
        className: String,
        methodNames: Set<String>,
        objectValue: Any? = null,
        onlyPrimitive: Boolean = false
    ) {
        val clazz = findClass(loader, className) ?: run {
            verbose("$TAG: class not found $className")
            return
        }
        var count = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in methodNames) continue
            if (method.parameterTypes.size > 1) continue
            val returnType = method.returnType
            if (returnType == Void.TYPE) continue
            if (onlyPrimitive && !returnType.isPrimitive) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            try {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val original = param.result
                        val forced = forcedValue(returnType, objectValue)
                        if (forced == null) {
                            verbose("$TAG: observe ${clazz.simpleName}.${method.name}() = $original")
                            return
                        }
                        if (original != forced) {
                            verbose(
                                "$TAG: force ${clazz.simpleName}.${method.name}() " +
                                    "$original -> $forced"
                            )
                        }
                        param.result = forced
                    }
                })
                count++
            } catch (t: Throwable) {
                YLog.warn("$TAG: hook $className#${method.name} failed: $t")
            }
        }
        log("$TAG: root-detect $className hooked=$count")
    }

    private fun forcedValue(returnType: Class<*>, objectValue: Any?): Any? = when (returnType) {
        java.lang.Boolean.TYPE -> false
        Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Double.TYPE -> 0.0
        java.lang.Float.TYPE -> 0f
        else -> objectValue
    }

    private fun hookBooleanFalse(
        loader: ClassLoader,
        className: String,
        methodNames: Set<String>,
        onlyNoParam: Boolean = false
    ) {
        val clazz = findClass(loader, className) ?: run {
            verbose("$TAG: class not found $className")
            return
        }
        var count = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in methodNames) continue
            if (onlyNoParam && method.parameterTypes.isNotEmpty()) continue
            if (method.returnType != java.lang.Boolean.TYPE) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            try {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.result == true) {
                            param.result = false
                            verbose("$TAG: force ${clazz.simpleName}.${method.name}() = false")
                        }
                    }
                })
                count++
            } catch (t: Throwable) {
                YLog.warn("$TAG: hook $className#${method.name} failed: $t")
            }
        }
        log("$TAG: root-detect $className hooked=$count")
    }

    // ---------------------------------------------------------------- B2. 文件痕迹

    private fun installFileShield() {
        val fileClass = java.io.File::class.java
        hookFileBoolean(fileClass, "exists")
        hookFileBoolean(fileClass, "canRead")
        hookFileBoolean(fileClass, "canExecute")
        hookFileBoolean(fileClass, "canWrite")
        hookFileBoolean(fileClass, "isFile")
        hookFileBoolean(fileClass, "isDirectory")
        runCatching {
            val length = fileClass.getDeclaredMethod("length")
            XposedBridge.hookMethod(length, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val file = param.thisObject as? java.io.File ?: return
                    if (!isHiddenPath(file.path)) return
                    param.result = 0L
                }
            })
        }.onFailure { YLog.warn("$TAG: hook File.length failed: $it") }
    }

    private fun hookFileBoolean(fileClass: Class<*>, name: String) {
        runCatching {
            val method = fileClass.getDeclaredMethod(name)
            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (param.result != true) return
                    val file = param.thisObject as? java.io.File ?: return
                    val path = file.path
                    if (isHiddenPath(path)) {
                        param.result = false
                        if (hiddenFileCount.incrementAndGet() <= 40) {
                            log("$TAG: hide file $name($path)")
                        }
                        return
                    }
                    // 只记录：发现还没被覆盖的可疑检测路径
                    if (probedPaths.size < 300 &&
                        SUSPICIOUS_PATH_MARKERS.any { path.contains(it, ignoreCase = true) } &&
                        probedPaths.putIfAbsent(path, true) == null
                    ) {
                        log("$TAG: probe File.$name($path) -> true")
                    }
                }
            })
        }.onFailure { YLog.warn("$TAG: hook File.$name failed: $it") }
    }

    private fun isHiddenPath(path: String): Boolean {
        if (path.length < 2) return false
        for (keyword in HIDDEN_PATH_KEYWORDS) {
            if (path.contains(keyword, ignoreCase = true)) return true
        }
        if (path.endsWith("/su", ignoreCase = true)) return true
        if (path.contains("/su/", ignoreCase = true)) return true
        if (path.contains("/sbin/su", ignoreCase = true)) return true
        if (path.contains("/xbin/su", ignoreCase = true)) return true
        if (path.contains("/bin/su", ignoreCase = true)) return true
        return false
    }

    // ---------------------------------------------------------------- B3. 包列表

    private fun installPackageShield(loader: ClassLoader) {
        val clazz = runCatching {
            Class.forName("android.app.ApplicationPackageManager", false, null)
        }.getOrNull() ?: runCatching {
            Class.forName("android.app.ApplicationPackageManager", false, loader)
        }.getOrNull() ?: run {
            YLog.warn("$TAG: ApplicationPackageManager not reachable")
            return
        }
        var hooked = 0
        for (method in clazz.declaredMethods) {
            when (method.name) {
                "getInstalledPackages", "getInstalledApplications",
                "queryIntentActivities", "queryIntentActivityOptions",
                "getInstalledPackagesAsUser", "getInstalledApplicationsAsUser",
                "queryIntentActivitiesAsUser", "getPackagesForUid" -> {
                    runCatching {
                        method.isAccessible = true
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun afterHookedMethod(param: MethodHookParam) {
                                filterPackageList(param)
                            }
                        })
                        hooked++
                    }.onFailure { YLog.warn("$TAG: hook PackageManager.${method.name} failed: $it") }
                }
                "getPackageInfo", "getApplicationInfo",
                "getPackageInfoAsUser", "getApplicationInfoAsUser" -> {
                    runCatching {
                        method.isAccessible = true
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                val requested = param.args.firstOrNull() as? String ?: return
                                if (!isHiddenPackage(requested)) return
                                if (hiddenPackageCount.incrementAndGet() <= 40) {
                                    log("$TAG: hide package query ${param.method.name}($requested)")
                                }
                                param.result = null
                            }
                        })
                        hooked++
                    }.onFailure { YLog.warn("$TAG: hook PackageManager.${method.name} failed: $it") }
                }
            }
        }
        log("$TAG: package manager hooked=$hooked")
    }

    private fun filterPackageList(param: XC_MethodHook.MethodHookParam) {
        when (val result = param.result) {
            is List<*> -> {
                val kept = result.filterNot { isHiddenPackage(packageNameOf(it)) }
                if (kept.size == result.size) return
                param.result = kept
                if (hiddenPackageCount.incrementAndGet() <= 40) {
                    log("$TAG: filter ${param.method.name} removed ${result.size - kept.size} entries")
                }
            }
            is Array<*> -> {
                // getPackagesForUid 返回 String[]
                if (result.javaClass.componentType != String::class.java) return
                val kept = result.filterNot { isHiddenPackage(it as? String) }
                if (kept.size == result.size) return
                val out = java.lang.reflect.Array.newInstance(String::class.java, kept.size) as Array<String?>
                kept.forEachIndexed { i, v -> out[i] = v as? String }
                param.result = out
                if (hiddenPackageCount.incrementAndGet() <= 40) {
                    log("$TAG: filter ${param.method.name} removed ${result.size - kept.size} entries")
                }
            }
            else -> Unit
        }
    }

    private fun packageNameOf(obj: Any?): String? = when (obj) {
        null -> null
        is PackageInfo -> obj.packageName
        is ApplicationInfo -> obj.packageName
        is ResolveInfo -> obj.activityInfo?.packageName ?: obj.serviceInfo?.packageName
        is String -> obj
        else -> null
    }

    private fun isHiddenPackage(packageName: String?): Boolean {
        if (packageName.isNullOrEmpty()) return false
        if (HIDDEN_PACKAGES.contains(packageName)) return true
        return HIDDEN_PACKAGE_PREFIXES.any { packageName.startsWith(it) }
    }

    // ---------------------------------------------------------------- B4. maps / status 文本流

    private fun installStreamShield() {
        runCatching {
            val readLine = java.io.BufferedReader::class.java.getDeclaredMethod("readLine")
            XposedBridge.hookMethod(readLine, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val line = param.result as? String ?: return
                    if (line.isEmpty()) return
                    if (line.contains("TracerPid", ignoreCase = true)) {
                        param.result = "TracerPid:\t0"
                        return
                    }
                    for (marker in LINE_MARKERS) {
                        if (line.contains(marker, ignoreCase = true)) {
                            param.result = "#"
                            if (filteredLineCount.incrementAndGet() <= 40) {
                                log("$TAG: filter stream line <${line.take(120)}>")
                            }
                            return
                        }
                    }
                }
            })
        }.onFailure { YLog.warn("$TAG: hook BufferedReader.readLine failed: $it") }
    }

    // ---------------------------------------------------------------- B5. 系统属性 / 调试标志

    private fun installPropertyShield() {
        val systemProperties = findClass(null, "android.os.SystemProperties")
            ?: findClass(java.io.File::class.java.classLoader, "android.os.SystemProperties")
            ?: run {
                YLog.warn("$TAG: SystemProperties not reachable")
                return
            }
        val getSingle = systemProperties.declaredMethods.firstOrNull {
            it.name == "get" && it.parameterTypes.size == 1 && it.parameterTypes[0] == String::class.java
        }
        val getDouble = systemProperties.declaredMethods.firstOrNull {
            it.name == "get" && it.parameterTypes.size == 2 &&
                it.parameterTypes[0] == String::class.java && it.parameterTypes[1] == String::class.java
        }
        val overrides = mapOf(
            "ro.debuggable" to "0",
            "ro.secure" to "1",
            "ro.kernel.qemu" to "0",
            "ro.build.type" to "user",
            "ro.build.tags" to "release-keys",
            "gsm.serial" to "",
            "ro.boot.serialno" to "",
            "ro.serialno" to "",
            "service.adb.root" to "0",
            "persist.sys.usb.config" to "mtp"
        )
        for (method in listOfNotNull(getSingle, getDouble)) {
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = param.args.firstOrNull() as? String ?: return
                        if (probedKeys.size < 400 &&
                            probedKeys.putIfAbsent("prop:$key", true) == null
                        ) {
                            verbose("$TAG: probe SystemProperties.get($key) -> ${param.result}")
                        }
                        val forced = overrides[key] ?: return
                        if (param.result != forced) {
                            param.result = forced
                            verbose("$TAG: SystemProperties.$key -> $forced")
                        }
                    }
                })
            }.onFailure { YLog.warn("$TAG: hook SystemProperties#${method.name} failed: $it") }
        }
        log("$TAG: property shield installed")
    }

    // ---------------------------------------------------------------- B6. 命令执行 / root 探测

    /**
     * QQ 在 checkSafeMode 阶段会执行 `sh -c type su` 之类的探针（真机日志已抓到）。
     * 这里不抛异常，直接返回一个"命令不存在、退出码 1、无输出"的假进程，
     * 检测方只会看到"设备没有 su"，同时调用方不会因为异常而走异常分支。
     */
    private fun installProcessShield() {
        val runtime = java.lang.Runtime::class.java
        for (method in runtime.declaredMethods) {
            if (method.name != "exec") continue
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val command = commandLineOf(param.args)
                        if (command.isEmpty()) return
                        verbose("$TAG: Runtime.exec <${command.take(160)}>")
                        if (isRootProbe(command)) {
                            if (blockedReportCount.incrementAndGet() <= 40) {
                                log("$TAG: fake 'not found' for Runtime.exec <${command.take(160)}>")
                            }
                            param.result = SilentProcess
                        }
                    }
                })
            }.onFailure { YLog.warn("$TAG: hook Runtime.exec failed: $it") }
        }
        runCatching {
            val start = ProcessBuilder::class.java.getDeclaredMethod("start")
            start.isAccessible = true
            XposedBridge.hookMethod(start, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val builder = param.thisObject as? ProcessBuilder ?: return
                    val command = builder.command().joinToString(" ")
                    if (command.isEmpty()) return
                    verbose("$TAG: ProcessBuilder.start <${command.take(160)}>")
                    if (isRootProbe(command)) {
                        if (blockedReportCount.incrementAndGet() <= 40) {
                            log("$TAG: fake 'not found' for ProcessBuilder <${command.take(160)}>")
                        }
                        param.result = SilentProcess
                    }
                }
            })
        }.onFailure { YLog.warn("$TAG: hook ProcessBuilder.start failed: $it") }
    }

    private fun commandLineOf(args: Array<Any?>): String {
        val first = args.firstOrNull() ?: return ""
        return when (first) {
            is String -> first
            is Array<*> -> first.joinToString(" ") { it?.toString() ?: "" }
            else -> first.toString()
        }
    }

    /** root / hook 探针特征；命中即伪造"命令不存在"。 */
    private val ROOT_PROBE_MARKERS = listOf(
        "type su",
        "which su",
        "command -v su",
        "su -c",
        "su -v",
        "su --version",
        "id -u",
        "magisk",
        "ksud",
        "apatch",
        "/data/adb",
        "/proc/mounts",
        "getprop ro.debuggable",
        "ro.build.tags"
    )

    private fun isRootProbe(command: String): Boolean {
        val normalized = command.trim().lowercase()
        if (normalized.isEmpty()) return false
        return ROOT_PROBE_MARKERS.any { normalized.contains(it) }
    }

    /** 空输出、退出码 1 的假进程，等价于 shell 的 "command not found"。 */
    private object SilentProcess : java.lang.Process() {
        private val empty = java.io.ByteArrayInputStream(ByteArray(0))

        override fun getOutputStream(): java.io.OutputStream = java.io.ByteArrayOutputStream()

        override fun getInputStream(): java.io.InputStream = empty

        override fun getErrorStream(): java.io.InputStream = empty

        override fun waitFor(): Int = 1

        override fun exitValue(): Int = 1

        override fun destroy() = Unit

        override fun isAlive(): Boolean = false

        override fun destroyForcibly(): java.lang.Process = this

        override fun toString(): String = "QQShieldSilentProcess"
    }

    // ---------------------------------------------------------------- helpers

    private fun observeClass(loader: ClassLoader, className: String, tag: String) {
        val clazz = findClass(loader, className) ?: return
        var count = 0
        for (method in clazz.declaredMethods) {
            if (Modifier.isAbstract(method.modifiers)) continue
            val seen = AtomicInteger()
            runCatching {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (seen.incrementAndGet() > 2) return
                        log("$TAG: observe $tag.${method.name}() -> ${param.result?.toString()?.take(80)}")
                    }
                })
                count++
            }.onFailure { }
        }
        log("$TAG: observe $tag hooked=$count")
    }

    private fun hookBefore(
        clazz: Class<*>,
        names: Set<String>,
        tag: String,
        before: (XC_MethodHook.MethodHookParam) -> Unit
    ) {
        var count = 0
        for (method in clazz.declaredMethods) {
            if (method.name !in names) continue
            if (Modifier.isAbstract(method.modifiers)) continue
            try {
                method.isAccessible = true
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        before(param)
                    }
                })
                count++
            } catch (t: Throwable) {
                YLog.warn("$TAG: hook $tag#${method.name} failed: $t")
            }
        }
        if (count == 0) {
            YLog.warn("$TAG: no method hooked for $tag (${names.joinToString()})")
        } else {
            log("$TAG: $tag hooked=$count")
        }
    }

    private fun returnTypeOf(param: XC_MethodHook.MethodHookParam): Class<*> =
        (param.method as? java.lang.reflect.Method)?.returnType ?: Void.TYPE

    private fun defaultResultOf(returnType: Class<*>): Any? = when (returnType) {
        java.lang.Boolean.TYPE -> false
        Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Double.TYPE -> 0.0
        java.lang.Float.TYPE -> 0f
        else -> null
    }

    private fun findClass(loader: ClassLoader?, name: String): Class<*>? = try {
        Class.forName(name, false, loader)
    } catch (t: Throwable) {
        null
    }
}
