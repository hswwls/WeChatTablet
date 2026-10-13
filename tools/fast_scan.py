"""Fast scan of QQ dex files for class descriptors / member names of interest."""
import re
import zipfile
from pathlib import Path

APK = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\qq_base.apk")
OUT = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\fast_scan.txt")

PATTERNS = [
    rb"L[a-zA-Z0-9_/$]*ChannelProxy[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*MsfCore[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*FEKit[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*QSec[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*qsec[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*TuringFD[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*Turing[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*UserInfoImpl[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*LightDeviceUtils[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*Pandora[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*SecurityCheck[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*SafeInfo[a-zA-Z0-9_/$]*;",
    rb"L[a-zA-Z0-9_/$]*Gatherer[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/gathererga/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/mobileqq/fe/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/mobileqq/qsec/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/mobileqq/sec[a-zA-Z0-9_/$]*;",
    rb"Loicq/wlogin_sdk/request/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/mobileqq/msf/core/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/qphone/base/remote/[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/qqnt/kernel/nativeinterface/[a-zA-Z0-9_/$]*(Sec|sec|Risk|risk|Report)[a-zA-Z0-9_/$]*;",
    rb"Lcom/tencent/mobileqq/pluginsdk/[a-zA-Z0-9_/$]*;",
]

MEMBER_NAMES = [
    b"sendSsoMsg", b"sendSsoMsgInner", b"sendMessage", b"sendMessageInner",
    b"isRooted", b"isDeviceRooted", b"isXposed", b"checkXposed",
    b"getInstalledPackages", b"getApplicationInfo", b"getPackageInfo",
    b"readLine", b"getStackTrace", b"toString", b"start", b"exec",
]


def main() -> int:
    lines = []
    with zipfile.ZipFile(APK) as zf:
        for name in sorted(n for n in zf.namelist() if n.endswith(".dex")):
            data = zf.read(name)
            found = {}
            for pat in PATTERNS:
                for m in set(re.findall(pat, data)):
                    found.setdefault(pat, set()).add(m.decode("utf-8", "ignore"))
            for pat, vals in found.items():
                key = pat.decode("utf-8", "ignore")
                for v in sorted(vals):
                    lines.append(f"{name} {key} {v}")
            present = [m.decode() for m in MEMBER_NAMES if m in data]
            if present:
                lines.append(f"{name} MEMBERS {','.join(present)}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"lines={len(lines)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
