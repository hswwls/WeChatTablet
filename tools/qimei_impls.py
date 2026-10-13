"""Find every class that declares getQimei16 / getQimei36 / getQimei (impls included)."""
import io
import pickle
import struct
from pathlib import Path

CACHE = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\detect_surface.dexcache")
OUT = Path(r"D:\20825\Documents\deepseek-harness\default-workspace\qq_sec\qimei_impls.txt")

ACC_INTERFACE = 0x0200
TARGETS = {"getQimei16", "getQimei36", "getQimei", "getQimeiAsync", "getQimeiAsyncV2", "initQimei"}


def uleb(b: io.BytesIO) -> int:
    r = 0
    s = 0
    while True:
        x = b.read(1)
        if not x:
            return r
        x = x[0]
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r
        s += 7


class D:
    def __init__(self, data: bytes):
        self.d = data
        self.ss, self.so = struct.unpack_from("<II", data, 0x38)
        self.ts, self.to = struct.unpack_from("<II", data, 0x40)
        self.ms, self.mo = struct.unpack_from("<II", data, 0x58)
        self.cs, self.co = struct.unpack_from("<II", data, 0x60)

    def st(self, i):
        if i < 0 or i >= self.ss:
            return ""
        o = struct.unpack_from("<I", self.d, self.so + 4 * i)[0]
        if o < 0 or o >= len(self.d):
            return ""
        b = io.BytesIO(self.d[o:])
        uleb(b)
        p = b.tell()
        try:
            e = self.d.index(b"\x00", o + p)
        except ValueError:
            return ""
        return self.d[o + p:e].decode("utf-8", "ignore")

    def tn(self, i):
        if i < 0 or i >= self.ts:
            return ""
        return self.st(struct.unpack_from("<I", self.d, self.to + 4 * i)[0])

    def mn(self, i):
        if i < 0 or i >= self.ms:
            return ""
        _c, _p, n = struct.unpack_from("<HHI", self.d, self.mo + 8 * i)
        return self.st(n)

    def classes(self):
        for i in range(self.cs):
            try:
                v = struct.unpack_from("<IIIIIIII", self.d, self.co + 32 * i)
                yield self.tn(v[0]), v[1], v[6]
            except Exception:
                continue

    def methods(self, off):
        if off == 0 or off >= len(self.d):
            return []
        try:
            b = io.BytesIO(self.d[off:])
            n1, n2, n3, n4 = uleb(b), uleb(b), uleb(b), uleb(b)
            for _ in range(n1 + n2):
                uleb(b)
                uleb(b)
            out, idx = [], 0
            for _ in range(n3 + n4):
                idx += uleb(b)
                uleb(b)
                uleb(b)
                out.append(idx)
            return out
        except Exception:
            return []


def main() -> int:
    dex_data = pickle.loads(CACHE.read_bytes())
    lines = []
    for name, data in sorted(dex_data.items()):
        dex = D(data)
        for cls, access, off in dex.classes():
            try:
                ms = {dex.mn(i) for i in dex.methods(off)}
            except Exception:
                continue
            hit = ms & TARGETS
            if hit:
                kind = "interface" if access & ACC_INTERFACE else "class"
                lines.append(f"{name} [{kind}] :: {cls}  ->  {', '.join(sorted(hit))}")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
