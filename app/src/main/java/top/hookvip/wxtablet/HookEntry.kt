package top.hookvip.wxtablet

import com.highcapable.yukihookapi.annotation.xposed.InjectYukiHookWithXposed
import com.highcapable.yukihookapi.hook.factory.configs
import com.highcapable.yukihookapi.hook.factory.encase
import com.highcapable.yukihookapi.hook.xposed.proxy.IYukiHookXposedInit
import top.hookvip.wxtablet.entry.QQTabletHooker
import top.hookvip.wxtablet.entry.TabletHooker

@InjectYukiHookWithXposed
class HookEntry : IYukiHookXposedInit {

    override fun onInit() = configs {
        debugLog {
            tag = "WeChatTablet"
            isEnable = true
        }
        isDebug = BuildConfig.DEBUG
    }

    override fun onHook() = encase {
        // QQ authentication runs in a separate :MSF process. Each injected process
        // needs its own hooker instance; restricting initialization to the first
        // application process silently leaves MSF with no tablet identity hook.
        when (packageName) {
            "com.tencent.mm" -> if (isFirstApplication) loadHooker(TabletHooker)
            // QQ authentication runs in a separate :MSF process, so load the QQ
            // hooker in every matching process, including the login service.
            "com.tencent.mobileqq" -> loadHooker(QQTabletHooker)
        }
    }
}
