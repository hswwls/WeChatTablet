"""Minimal DEX parser: list classes / methods whose names match keywords.

Usage: python dex_classes.py <keyword> [<keyword> ...]
"""
import io
import struct
import sys
import zipfile
from pathlib import Path

APK = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\qq_base.apk")
OUT = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\dex_classes.txt")


def read_uleb(buf: io.BytesIO) -> int:
    result = 0
    shift = 0
    while True:
        b = buf.read(1)
        if not b:
            return result
        b = b[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result
        shift += 7


class Dex:
    def __init__(self, data: bytes):
        self.data = data
        self.string_ids_size, self.string_ids_off = struct.unpack_from("<II", data, 0x38)
        self.type_ids_size, self.type_ids_off = struct.unpack_from("<II", data, 0x40)
        self.method_ids_size, self.method_ids_off = struct.unpack_from("<II", data, 0x58)
        self.class_defs_size, self.class_defs_off = struct.unpack_from("<II", data, 0x60)

    def string(self, idx: int) -> str:
        if idx < 0 or idx >= self.string_ids_size:
            return ""
        off = struct.unpack_from("<I", self.data, self.string_ids_off + 4 * idx)[0]
        buf = io.BytesIO(self.data[off:])
        read_uleb(buf)  # utf16 length
        p = buf.tell()
        end = self.data.index(b"\x00", off + p)
        return self.data[off + p:end].decode("utf-8", "ignore")

    def type_name(self, idx: int) -> str:
        if idx < 0 or idx >= self.type_ids_size:
            return ""
        str_idx = struct.unpack_from("<I", self.data, self.type_ids_off + 4 * idx)[0]
        return self.string(str_idx)

    def method_name(self, idx: int) -> str:
        if idx < 0 or idx >= self.method_ids_size:
            return f"<bad:{idx}>"
        cls, proto, name = struct.unpack_from("<HHI", self.data, self.method_ids_off + 8 * idx)
        return self.string(name)

    def classes(self):
        for i in range(self.class_defs_size):
            off = self.class_defs_off + 32 * i
            vals = struct.unpack_from("<IIIIIIII", self.data, off)
            yield self.type_name(vals[0]), vals[1], vals[6]

    def class_methods(self, class_data_off: int):
        if class_data_off == 0:
            return []
        buf = io.BytesIO(self.data[class_data_off:])
        n_static = read_uleb(buf)
        n_instance = read_uleb(buf)
        n_direct = read_uleb(buf)
        n_virtual = read_uleb(buf)
        for _ in range(n_static + n_instance):
            read_uleb(buf)
            read_uleb(buf)
        out = []
        for _ in range(n_direct + n_virtual):
            diff = read_uleb(buf)
            read_uleb(buf)
            read_uleb(buf)
            out.append(diff)
        # rebuild absolute indexes
        idx = 0
        abs_idx = []
        for d in out:
            idx += d
            abs_idx.append(idx)
        return abs_idx


def main() -> int:
    argv = sys.argv[1:]
    dex_filter = None
    if argv and argv[0].startswith("--dex="):
        dex_filter = argv[0][len("--dex="):].split(",")
        argv = argv[1:]
    keywords = [k.lower() for k in argv] or ["qsec", "fekit"]
    lines = []
    with zipfile.ZipFile(APK) as zf:
        for name in sorted(n for n in zf.namelist() if n.endswith(".dex")):
            if dex_filter and name not in dex_filter:
                continue
            dex = Dex(zf.read(name))
            for class_name, _super, data_off in dex.classes():
                low = class_name.lower()
                if not any(k in low for k in keywords):
                    continue
                methods = [dex.method_name(i) for i in dex.class_methods(data_off)]
                lines.append(f"{name} :: {class_name}")
                lines.append(f"    methods: {', '.join(methods) if methods else '(none)'}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"classes matched: {sum(1 for l in lines if l.startswith('classes'))} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
