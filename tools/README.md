# tools/ 分析脚本

本次逆向分析用的辅助脚本（Python 3，仅依赖标准库 + `pickle` 缓存）。

| 脚本 | 用途 |
|---|---|
| `dex_classes.py` | 极简 DEX 解析器：按关键字列出类名与方法名（`python dex_classes.py --dex=classes2.dex qimei wlogin`） |
| `fast_scan.py` | 在全部 dex 中按正则批量搜索类描述符 / 成员名 |
| `detect_surface.py` | 全量检测面扫描：root / hook / debug / 模拟器 / 多开 / 设备标识 / 签名 / 安全模式 + 原生库字符串概览 |
| `qimei_impls.py` | 找出所有声明 `getQimei16/36/getQimei` 的类（含接口/实现） |
| `needles.py` | 按关键字列表统计命中分布（用于快速确认某个 API 是否存在于 Java 层） |

## 使用

1. 从设备拉取目标 APK：

```bash
adb pull /data/app/~~xxxx==/com.tencent.mobileqq-xxxx==/base.apk ./qq_base.apk
```

2. 修改脚本顶部的 `APK` 路径（以及 `detect_surface.py` 的 `OUT` 输出路径）。
3. 首次运行 `detect_surface.py` 会在同目录生成 `*.dexcache`（pickle 缓存，加速后续脚本）。

> 脚本只做只读分析，不会修改 APK。
