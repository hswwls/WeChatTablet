# WeChatTablet · QQTablet

<div align="center">

**微信 / QQ 平板模式（Xposed / LSPosed 模块）**
附 **QQ 设备风险对抗层**（对抗"已登录设备存在安全隐患 / 设备存在外挂或其他软件影响QQ正常使用"）

<sub>基于 YukiHookAPI 构建 · 适配微信 8.0.40+ 与 QQ 9.x（NT 架构）</sub>

</div>

---

## 一、功能总览

| 模块 | 功能 |
|---|---|
| **微信** | 强制平板模式；登录页显示「同时在手机和平板上使用」入口；无视 Tinker 热更新（热修后依然生效）；不卡启动页 |
| **QQ** | 伪装成平板客户端（界面 + 认证双路径）；聊天/主界面正常；**手机端不被顶号** |
| **QQ 设备风险对抗** | 屏蔽 QQ 的环境检测结果与风控上报，让平板模式登录不再被判为"外挂/环境异常" |

> 三个变体：`wechat`（仅微信）、`qq`（仅 QQ）、`combined`（二合一），包名互不冲突，可同时安装。

---

## 二、背景：为什么需要"设备风险对抗层"

QQ 9.x（NT 架构）在客户端内置了一整套环境检测 + 风控上报：

* 原生库 `libfekit.so`（FEKitSDK / QSec）：扫描 `/proc/self/maps`、`/proc/self/smaps`、`su` 路径、`/proc/mounts`，内置 root/hook 管理器包名黑名单，并解析 libart 做方法校验；
* 原生库 `libnative-memory-library-lib.so`：自带 `native_hook_monitor`，读 maps 找 so 基址、检测"文件已删除"的映射，并 hook `OpenDexFile` / `Runtime.nativeLoad` 监控 dex 加载；
* `libturingxq.so` / `libturingmfa.so`（Turing 风控）、`libqimei.so`（设备指纹）；
* Java 层：`type su` 探针、`PackageManager` 枚举（Xposed/Magisk/root 管理器）、`/proc/self/maps` 文本读取、`gathererga.UserInfoImpl.isRooted`、`LightDeviceUtils.isRooted`、`wlogin` 的 root 判定等；
* 上报通道：`MsfCore.sendSsoMsg` → `trpc.o3.report.Report.SsoReport`、`trpc.gc_indust.device_report.*`、`CliLogSvc.UploadReq`、`QimeiReportLoginFailServlet`（登录失败按 Qimei 上报）、`QSec.reportLog/doReport`。

一旦这些结果被上报，腾讯风控会把**设备**标记为风险设备并对该设备下线，QQ 安全中心随即显示"设备存在外挂或其他软件影响QQ正常使用"。

本模块在 QQ 进程内（仅对 QQ 生效，不影响微信与其它应用）做了三层针对性处理，**不修改 QQ 的任何文件、不修改系统设置**。

---

## 三、代码结构

```
app/src/main/java/top/hookvip/wxtablet/
├── HookEntry.kt                 # 入口：按宿主包名分发（com.tencent.mm / com.tencent.mobileqq）
├── entry/
│   ├── TabletHooker.kt          # 微信平板模式
│   ├── QQTabletHooker.kt        # QQ 平板模式（界面 + :MSF 认证身份）
│   └── QQSecurityShield.kt      # ★ QQ 设备风险对抗层（1.0.5 新增）
├── utils/                       # WXConfig（DexKit 定位）、FastKv 缓存、AesHelper
├── factory/HookExt.kt           # 反射扩展
└── data/                        # HostInfo / DescriptorData
```

### QQSecurityShield 的七层

| 层 | 内容 | 关键目标 |
|---|---|---|
| A 上报拦截 | 丢弃风控类 SSO 命令与上报入口 | `MsfCore.sendSsoMsg*`（`trpc.o3.report` / `trpc.o3.mobile_security` / `OidbSvc.0xd79` / `turing` / `riskCheckWup` / `qsec.` / `device_report` / `CliLogSvc.UploadReq` / `qqlog_server.portal` / `qimeiReport`）、`QSec.doReport`、`QSec.reportLog`、`QSecChannelImpl.feEnvReport` |
| B1 root 检测 | 让检测返回"无风险" | `gathererga…UserInfoImpl.isRooted`、`org.light.device.LightDeviceUtils.isRooted`、`tenpay…ChargeV2Utils.isDeviceRooted`、`oicq.wlogin_sdk.request.w` |
| B2 文件痕迹 | su / magisk / xposed 工件不可见 | `File.exists / canRead / canExecute / canWrite / isFile / isDirectory / length` 路径过滤 |
| B3 包列表 | root/hook 管理器与本模块自身不可见 | `ApplicationPackageManager` 25 个查询方法（含 `*AsUser`、`getPackagesForUid` 数组过滤） |
| B4 文本流 | maps / status 里的 hook 特征被清洗 | `BufferedReader.readLine`：命中特征行替换为 `#`，`TracerPid` 归零 |
| B5 系统属性 | 调试态不可见 | `SystemProperties.get`：`ro.debuggable` / `ro.secure` / `ro.kernel.qemu` / `ro.build.type` / `ro.build.tags` / 序列号等 |
| B6 命令探测 | root 探针变成"命令不存在" | `Runtime.exec` / `ProcessBuilder.start`：命中 `type su`、`which su`、`magisk`、`/proc/mounts` 等 → 返回空输出、退出码 1 的假进程（不抛异常） |
| C 分身设备指纹 | 只用新设备身份登录（**仅 user 999 分身**） | `oicq.wlogin_sdk.tools.util` 的 guid/mac/android_id 读写 + `com.tencent.qimei.sdk.Qimei` 的 `getQimei16/36`；`save_*` 全部不落盘 |

---

## 四、实测检测点清单（QQ 9.3.70 / 真机验证）

### 4.1 Java 层

| 检测点 | 位置 | 状态 |
|---|---|---|
| `sh -c type su` | `Runtime.exec` / `ProcessBuilder` | ✅ 伪造为"没有 su"（单次运行拦到 40+ 次） |
| su 路径表 | `/system/bin/su`、`/system/xbin/su`、`/sbin/su`、`/su/bin`、`/data/local/{su,bin/su,xbin/su}`、`Superuser` | ✅ 文件接口隐藏 |
| Xposed / Magisk / KernelSU 包查询 | `getPackageInfo(...)` | ✅ 实测拦到 `de.robv.android.xposed.installer`、`com.topjohnwu.magisk` 等 |
| maps 里的模块映射行 | `/proc/self/maps`（Java 读） | ✅ 命中行清洗 |
| 调试检测 | `Debug.isDebuggerConnected()`、`/proc/self/status`、`ro.debuggable` | ✅ 天然 false + 属性伪装 |
| 模拟器检测 | `init.svc.qemud/droid4x/noxd/ttVM_x86-setup/vbox86-setup`、`microvirt.vbox_dpi`、goldfish/qemu 串 | ⚪ 真机为空，无需处理（已观测确认） |
| 无障碍 / 输入法列表 | `Settings.Secure.getString` | ⚪ 仅只读观测（按需可改） |
| 进程/任务枚举 | `ActivityManager.getRunning*` | ⚪ 仅观测（只能看到自身） |
| 方法完整性校验 | `QSec.detectMethod(类, 方法)` | ✅ 实测从未被调用 |
| 悬浮窗 / 网络能力 / 代理 | `canDrawOverlays`、`SYSTEM_ALERT_WINDOW`、`getNetworkCapabilities`、`http.proxyHost` | ⚪ 仅观测 |

### 4.2 native 层（Java hook 覆盖不到，需 native 方案）

| 库 | 行为 |
|---|---|
| `libfekit.so` | 自读 maps/smaps/mounts/su 路径；内含 `parse_libart.cpp`（ArtMethod 校验）、`detection_libfekit_file.cpp`（自校验） |
| `libnative-memory-library-lib.so` | `native_hook_monitor`：GOT hook 检测、deleted-so 检测、`OpenDexFile`/`Runtime.nativeLoad` 监控 |
| `libqimei.so` / `libturingxq.so` | 设备指纹与风控 SDK（Turing 侧含 ArtField/ArtMethod 反射校验） |

### 4.3 分身设备指纹链（登录时实际读取）

```
oicq.wlogin_sdk.tools.util.getGuidFromFile()   -> 设备 guid（落盘持久化）
                             .generateGuid()   -> 同上
                             .get_last_guid()  -> 上一次的 guid（改机检测的比对项）
                             .get_mac_addr() / .get_last_mac()
                             .get_saved_android_id() / save_android_id()
                             .needChangeGuid() / save_cur_guid() / save_cur_mac()
com.tencent.qimei.sdk.Qimei.getQimei16() / getQimei36()   -> 腾讯风控侧的设备主键
```

实测确认：QSec 风控上报的第 4 个参数就是 wlogin guid，说明服务端把"设备"绑定在 guid + Qimei 上；更换后 QQ 会自行把**新 Qimei** 写进自己的标记文件（`files/PToolFile/CD/RP_I/Q_I__I_<qimei>`），可作为生效验证。

---

## 五、构建

### 环境

* JDK **21**
* Android SDK（compileSdk 36 / targetSdk 36 / minSdk 27）
* Gradle 8.14.x（自带 wrapper）

### 步骤

> ⚠️ **AGP 硬性要求：工程路径不能包含非 ASCII 字符**（中文目录会直接报
> `Your project path contains non-ASCII characters`）。请把工程放在纯英文路径下。

```bash
# 1. 指定 SDK 路径（local.properties 不入库）
echo "sdk.dir=/path/to/Android/Sdk" > local.properties

# 2. 构建三个变体
./gradlew :app:assembleWechatDebug     # 仅微信
./gradlew :app:assembleQqDebug         # 仅 QQ
./gradlew :app:assembleCombinedDebug   # 二合一
```

产物在 `app/build/outputs/apk/<变体>/debug/`。

### 签名

仓库**不包含**签名密钥。若要发布可覆盖安装的版本，请用自己的 keystore：

```bash
apksigner sign --ks your.keystore --ks-key-alias yourAlias \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --out QQTablet.apk app/build/outputs/apk/qq/debug/WeChatTablet-1.0.5-debug.apk
```

`prebuilt/` 内的 APK 由作者私钥签名，仅供直接安装体验，自行编译的版本需自备密钥。

---

## 六、安装使用

1. 设备需 Root + LSPosed（Zygisk 模式推荐）；
2. 安装对应变体 APK；
3. 在 LSPosed 管理器中启用模块，作用域勾选：
   * `wechat` 变体 → 微信
   * `qq` 变体 → QQ
   * `combined` 变体 → 微信 + QQ
4. 重启目标应用（QQ 建议连同 `:MSF` 进程一起重启，即强制停止后重新打开）。

> 新版 QQ 会把业务类放进 Tinker 热更新补丁（`DelegateLastClassLoader`）。模块在 `TinkerApplication.onBaseContextAttached` 才解析宿主类，因此热修后依然生效。

---

## 七、可调参数

`entry/QQSecurityShield.kt` 顶部：

| 参数 | 说明 |
|---|---|
| `ENABLE_IDENTITY_SPOOF` | 是否启用分身设备指纹替换（默认开启，仅对 XSpace 分身 `userId=999` 生效） |
| `SPOOF_USER_ID` | 生效的用户 ID，默认 `999`（小米/红米 XSpace 分身） |
| `SPOOF_GUID_HEX` / `SPOOF_ANDROID_ID` / `SPOOF_MAC` / `SPOOF_QIMEI` | 新指纹取值，建议自行改随机值后重新编译 |
| `HIDDEN_PACKAGES` / `HIDDEN_PACKAGE_PREFIXES` | 需要从 QQ 视野隐藏的包名 |
| `HIDDEN_PATH_KEYWORDS` | 需要隐藏的路径特征 |
| `RISK_COMMANDS` / `KEEP_COMMANDS` | 丢弃 / 绝不丢弃的 SSO 命令（`KEEP_COMMANDS` 用于保护登录校验类命令，误拦会导致"身份验证失败"） |

---

## 八、已知限制

1. **native 层未覆盖**：`libfekit.so`、`libnative-memory-library-lib.so` 等自读 maps / mounts / su 路径，Java hook 拦不到；需 native 方案（PLT hook `open/openat/fopen/read` + 直接改 native 缓存）才能进一步收紧。
2. **模块 APK 在目标进程内的映射真实存在**（`/proc/self/maps` 可见）：Java 读取已被清洗，native 读取无法处理。
3. **服务端记录不计入本地可控范围**：设备/账号在服务端的历史风险记录不受客户端影响；更换设备指纹只影响"后续以什么身份登录"。
4. **不上报本身也可能是一种信号**：本模块是"拦截上报"而非"让检测无从发现"。
5. QQ/微信版本更新后类名与方法名会变化，需按日志中 `QQShield: dump ...` 输出的真实成员名更新 hook 目标。

---

## 九、诊断日志

模块通过 LSPosed 日志输出（tag 前缀 `QQShield:` / `QQTablet:` / `WeChatTablet:`）：

```bash
# 设备上的日志位置
/data/adb/lspd/log/modules_*.log

# 只看本模块
grep -a 'QQShield' /data/adb/lspd/log/modules_*.log
```

关键行示例：

```
QQShield: identity spoof armed in clone (guid=…, androidId=…, mac=…, qimei=…)
QQShield: spoof qimei.getQimei36 <旧值> -> <新值>
QQShield: fake 'not found' for Runtime.exec </system/bin/sh -c type su>
QQShield: hide package query getPackageInfo(com.topjohnwu.magisk)
QQShield: filter stream line <7ae8b1c000-… /data/app/…/top.hookvip…/base.apk>
QQShield: drop sso report [trpc.o3.report.Report.SsoReport] #3
QQShield: dump QSec / FEKit = <该类全部成员名，便于版本适配>
```

`tools/` 下附带本次分析用的脚本（Dex 扫描 / 方法清单 / 原生库字符串扫描），使用时按需修改其中的 APK 路径。

---

## 十、更新日志

### 1.0.5
* 新增 `QQSecurityShield`（七层设备风险对抗，见第三节）；仅对 QQ 生效
* QQ 平板模式补充：`:tool`/`:qzone` 等子进程同样安装屏蔽层
* 修正：**不得拦截** `wtlogin.device_lock` 等登录校验类命令（误拦会导致"身份验证失败 (w21)"）
* 修正：**不得** hook `Class.forName` / `ClassLoader.loadClass` 等类加载关键路径（实测会导致 QQ 启动 `ClassNotFoundException` → FATAL）
* 新增分身设备指纹替换（guid / mac / android_id / Qimei16 / Qimei36），全部内存内改写、不落盘
* 新增登录失败上报拦截（`QimeiReportLoginFailServlet` → `trpc.qqlog.qqlog_server.Portal.SsoGetQimeiCheckReport`）与 QQ 日志上传拦截（`CliLogSvc.UploadReq`）

### 1.0.4 及以前
* 微信平板模式、QQ 平板模式基础实现（Tinker 兼容、双进程认证身份、三变体打包）

---

## 十一、致谢

| 项目 | 链接 |
|---|---|
| YukiHookAPI | https://github.com/HighCapable/YukiHookAPI |
| DexKit | https://github.com/LuckyPray/DexKit |
| FastKV | https://github.com/BillyWei01/FastKV |
| 上游平板模块（WeChatTablet by hswwls） | https://github.com/Xposed-Modules-Repo/top.hookvip.wxtablet |

## 十二、许可

MIT License，见 [LICENSE](LICENSE)。

仅供学习研究与个人设备调试使用，使用造成的任何后果由使用者自行承担。
