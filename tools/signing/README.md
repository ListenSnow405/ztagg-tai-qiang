# 手机版 APK 打包 / 签名

## 为什么必须有这一步

`tools/repack_mobile_apk.py` 的产物天生是**未签名**的中间件：脚本会把原 APK 的
`META-INF/` 整段剥掉（因为资源被替换后旧签名本来就失效了），所以它**不能直接安装** ——
安卓安装器读不到签名，就会报 `PackageInfo is null` / 「解析包时出现问题」。

而这个包的 `targetSdkVersion = 34`，安卓 11 以上**只认 APK Signature Scheme v2/v3**，
v1（`jarsigner`）会被拒。本机没有 `apksigner`（没有 Android SDK），所以 v2 签名块由
`tools/apk_v2_sign.py` 自己实现 —— 它已经用你原有的、能正常安装的 APK 做过反向校验：
`verify` 能重算出 apksigner 当年写进去的内容摘要（逐字节相同），说明分块 / 前缀 / 分段逻辑正确。

## 本机签名密钥（本地测试用）

| 项 | 值 |
| --- | --- |
| 文件 | `tools/signing/ily-local-test.p12` （PKCS#12，RSA-2048） |
| 口令 | 保存在本机，不写入仓库；运行前设置 `ILY_P12_PASS` 环境变量 |
| 主体 | `O=I.L.Y, CN=I.L.Y local test` |
| SHA-256 指纹 | `bdebd596eb2f64d7033dd5034b077a7c6ed4fd1d140d81002818406873dc4553` |

> ⚠️ **请把这个 .p12 备份好。** 它以「签名身份」决定能不能覆盖升级：以后每次重打包都必须用
> 同一个密钥签名，否则安卓会拒绝安装（签名不一致），只能先卸载旧版、连带清掉游戏存档。
>
> ⚠️ 这个密钥**不是**你原来那个（原来的在另一台电脑上，这台机器上找不到，也没有 keystore）。
> 所以**第一次安装必须先在手机上卸载旧的 I.L.Y**，游戏内存档（WebView 的 localStorage，属于应用私有目录）会一起被清掉。
> 如果哪天找回原来的 keystore，就改用它签名，那样可以原地覆盖升级、不丢存档。

## 完整流程

```powershell
cd C:\Users\tonganvalley\Desktop\I.L.Y\I.L.Y

# 1) 用工作区里最新的网页资源重打包（剥掉旧签名，输出 I.L.Y-mobile-unsigned.apk）
python tools\repack_mobile_apk.py --source ..\I.L.Y-mobile-testkey-fixed.apk

# 2) 做 APK Signature Scheme v2 签名（输出可安装的 APK）
python tools\apk_v2_sign.py sign `
  ..\I.L.Y-mobile-unsigned.apk ..\I.L.Y-mobile-signed.apk `
  --p12 tools\signing\ily-local-test.p12 --p12-pass $env:ILY_P12_PASS

# 3) 校验签名 + 内容摘要
python tools\apk_v2_sign.py verify ..\I.L.Y-mobile-signed.apk
```

`verify` 正常输出应包含：

```
      content digest sha256 (alg 0x101): MATCH
      signature alg 0x101 over signed data: VALID
    => SIGNED, v2 integrity OK
```

## 换用自己的密钥

`apk_v2_sign.py` 支持三种密钥来源，任选其一：

```powershell
# PKCS#12（.p12 / .pfx）—— 和 apksigner 用的是同一种容器，推荐
python tools\apk_v2_sign.py sign in.apk out.apk --p12 key.p12 --p12-pass <口令>

# PEM 私钥 + PEM 证书（有 cryptography 包时用它，否则回退到 openssl 命令行）
python tools\apk_v2_sign.py sign in.apk out.apk --key key.pem --cert cert.pem

# 新建一个自用密钥
python tools\apk_v2_sign.py keygen --out my-release.p12 --cn "I.L.Y"
```

如果你更想用官方 `apksigner`（在有 Android SDK 的机器上），把
`tools/apk_v2_sign.py` 这一步换成：

```bash
apksigner sign --ks key.jks --ks-key-alias ILY --v1-signing-enabled false \
  --v2-signing-enabled true --v3-signing-enabled true \
  --out I.L.Y-mobile-signed.apk I.L.Y-mobile-unsigned.apk
```

注意：**不要再对已签名的 APK 跑一遍 repack**（repack 会剥掉签名）；正确顺序永远是
先 `repack` 再 `sign`，`apk_v2_sign.py` 也会拒绝给已带签名块的 APK 二次签名。
