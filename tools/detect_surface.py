"""Broad detection-surface scan over QQ 9.3.70 dex + native libs."""
import re
import struct
import zipfile
from pathlib import Path

APK = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\qq_base.apk")
OUT = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\detect_surface.txt")

DEX_NEEDLES = {
    "root": [
        "isRooted", "isDeviceRooted", "checkRoot", "rooted", "isRoot", "hasRoot",
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin", "busybox",
        "magisk", "supersu", "Superuser", "KernelSU", "kernelsu", "apatch",
    ],
    "hook": [
        "de.robv.android.xposed", "XposedBridge", "XposedHelpers", "xposedmodule",
        "lsposed", "LSPosed", "EdXposed", "substrate", "frida", "SandHook",
        "isXposed", "checkXposed", "hasXposed", "hookMethod", "entry_point",
        "ArtMethod", "art_method", "instrumentation", "Instrumentation",
    ],
    "debug": [
        "isDebuggerConnected", "TracerPid", "ro.debuggable", "FLAG_DEBUGGABLE",
        "/proc/self/status", "waitForDebugger", "Debug.isDebuggerConnected",
    ],
    "emulator": [
        "goldfish", "ranchu", "qemu", "genymotion", "bluestacks", "microvirt",
        "noxt", "ttVM", "emulator", "ro.kernel.qemu", "isEmulator", "isVirtualDevice",
    ],
    "multi": [
        "xspace", "XSpace", "dualapp", "clone", "multiapp", "virtualapp",
        "isClone", "分身", "多开", "双开", "isSecondSpace", "getUserId",
        "Process.myUid", "/999/", "vm_", "VirtualCore",
    ],
    "deviceid": [
        "android_id", "ANDROID_ID", "getDeviceId", "getImei", "getMeid",
        "getSerial", "getSimSerialNumber", "getSubscriberId", "getMacAddress",
        "getHardwareAddress", "qimei", "Qimei", "Qimei36", "Qimei16",
    ],
    "signature": [
        "GET_SIGNATURES", "GET_SIGNING_CERTIFICATES", "checkSignature",
        "verifySignature", "signatureMd5", "apkSignature",
    ],
    "safemode": [
        "safeMode", "SafeMode", "安全模式", "checkSafeMode", "initSafeMode",
        "onReceiveSecError", "SecError", "secError", "风险", "riskDevice",
    ],
}

CLASS_PATTERN = re.compile(
    rb"L[a-zA-Z0-9_/$]*(?:Root|Xposed|Hook|Emulator|Virtual|Clone|MultiApp|Risk|SafeMode|SecMode|SecError|FingerPrint|Fingerprint|AntiCheat|Tamper|Integrity)[a-zA-Z0-9_/$]*;"
)


def elf_strings(data: bytes, needles):
    found = {}
    for m in re.finditer(rb"[\x20-\x7e]{5,300}", data):
        s = m.group()
        for needle in needles:
            if needle.encode() in s:
                found.setdefault(needle, []).append(m.start())
    return found


def main() -> int:
    lines = []
    lib_needles = [
        "lsposed", "LSPosed", "zygisk", "riru", "magisk", "kernelsu", "apatch",
        "frida", "substrate", "xposed", "Xposed", "gdb", "hook", "Hook",
        "root", "Root", "su", "detect", "Detect", "risk", "Risk", "emulator",
        "qemu", "goldfish", "/proc/self", "/proc/", "maps", "smaps", "TracerPid",
        "clone", "virtual", "multi", "userid", "xspace", "signature",
    ]
    with zipfile.ZipFile(APK) as zf:
        names = zf.namelist()
        dex_names = sorted(n for n in names if n.endswith(".dex"))
        lib_names = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))

        # 每个 dex 只解压一次，避免 60+ 关键字重复解压
        dex_data = {n: zf.read(n) for n in dex_names}
        cache_file = OUT.with_suffix(".dexcache")
        if not cache_file.exists():
            import pickle
            cache_file.write_bytes(pickle.dumps(dex_data))
            print(f"dex cache written: {cache_file}")

        lines.append("### DEX 命中（每个关键字命中的 dex 文件）")
        for group, needles in DEX_NEEDLES.items():
            lines.append(f"\n--- {group}")
            for needle in needles:
                nb = needle.encode()
                hits = [n for n, d in dex_data.items() if nb in d]
                if hits:
                    lines.append(f"  {needle}: {len(hits)} -> {', '.join(hits[:6])}")

        lines.append("\n\n### 类名匹配（Root/Xposed/Hook/Emulator/Virtual/Clone/Risk/SafeMode/Tamper…）")
        for n, data in dex_data.items():
            for m in sorted(set(CLASS_PATTERN.findall(data))):
                lines.append(f"  {n} :: {m.decode('utf-8', 'ignore')}")

        lines.append("\n\n### 原生库命中概览")
        for n in lib_names:
            data = zf.read(n)
            stats = elf_strings(data, lib_needles)
            interesting = {
                k: len(v) for k, v in stats.items()
                if k in ("lsposed", "LSPosed", "zygisk", "riru", "magisk", "kernelsu",
                         "apatch", "frida", "substrate", "xposed", "Xposed", "gdb",
                         "TracerPid", "xspace", "clone")
            }
            detect_words = {k: len(v) for k, v in stats.items() if k in ("detect", "Detect", "risk", "Risk")}
            if interesting or detect_words:
                lines.append(f"  {n}: {interesting} {detect_words}")

        # 重点库：libnative-memory-library-lib.so 全量关键字
        target = "lib/arm64-v8a/libnative-memory-library-lib.so"
        if target in names:
            data = zf.read(target)
            stats = elf_strings(data, lib_needles)
            lines.append(f"\n### {target} 命中详情")
            for k in sorted(stats, key=lambda x: -len(stats[x]))[:30]:
                offs = stats[k][:6]
                lines.append(f"  {k}: {len(stats[k])} @ {offs}")
                for off in offs[:3]:
                    lo = max(0, off - 80)
                    hi = min(len(data), off + 120)
                    chunk = "".join(chr(c) if 32 <= c < 127 else "." for c in data[lo:hi])
                    lines.append(f"      {chunk}")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"lines={len(lines)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
