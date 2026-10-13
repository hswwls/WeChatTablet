"""Report which needles occur in which QQ dex file (decompressed)."""
import sys
import zipfile
from pathlib import Path

APK = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\qq_base.apk")
OUT = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\needles.txt")

NEEDLES = [
    "MsfCore", "sendSsoMsg", "ChannelProxyExt", "sendMessageInner",
    "com/tencent/mobileqq/fe/FEKit", "com.tencent.mobileqq.fe.FEKit",
    "gathererga", "UserInfoImpl", "isRooted", "LightDeviceUtils",
    "oicq/wlogin_sdk/request/w", "oicq.wlogin_sdk.request.w",
    "turingfd", "TuringFD", "riskCheckWup", "OidbSvc.0xd79", "trpc.o3.report",
    "trpc.o3.mobile_security", "wtlogin.device_lock", "device_lock",
    "qsec", "QSec", "FEKit", "fekit", "libfekit",
    "Pandora", "RuntimeMonitor", "DeviceInfoMonitor", "MonitorReporter",
    "com/tencent/mobileqq/qsec", "SecDetect", "SecurityCheck",
    "/proc/self/maps", "/proc/self/status", "TracerPid",
    "com/tencent/mobileqq/fe", "qqperf/monitor/crash",
    "com/topjohnwu", "kernelsu", "KernelSU", "magisk",
    "com/tencent/mobileqq/statistics", "BeaconIdInfo",
    "GetSafetyInfo", "safeinfo", "SafeInfo",
]


def main() -> int:
    lines = []
    with zipfile.ZipFile(APK) as zf:
        dex_names = sorted(n for n in zf.namelist() if n.endswith(".dex"))
        data = {n: zf.read(n) for n in dex_names}
        for needle in NEEDLES:
            nb = needle.encode()
            where = [n for n, d in data.items() if nb in d]
            lines.append(f"{needle!r}: {len(where)} -> {', '.join(where) if len(where) < 12 else str(len(where)) + ' files'}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
