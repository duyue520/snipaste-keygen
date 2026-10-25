# Snipaste 2.11.3 离线授权逆向分析记录

样本: 官方 `Snipaste-2.11.3-x64.zip`(2026-01-18 发布)
SHA-1: `F6E14360D0F5AF8E4DD93B798F0B8C33B5C23430` (Snipaste.exe, 7,008,768 B)
环境: Windows 11 x64, Python 3.13, IDA Pro 9.4 / capstone 辅助定位

## 1. 授权链路总览

```
用户输入授权码 (0X-Base64)
  │ setLicenseKey: len>3 && code[2]=='-' ; code[1] 与载荷校验字符比对
  │ base64 变体自动探测(载荷含 +/ → 标准, 否则 urlsafe)
  │ postProcessBody: data<65B 弃; sig=data[0:64]; body^=sig; gunzip(wbits=31); body^=sig
  │ verify prep: body^=sig  → message = gunzip(body^sig) = 明文 JSON
  │ Ed25519 验签 (sub_140250020, CryptoPP; 公钥 AES-128-CTR 懒解密)
  │ LicenseInfo::fromJson → set_info
  ▼
validate (sub_140245880): eml 非空 + platform==1 + dom(可空) + machineid + iat/exp
```

三次 XOR 细节: postProcess 在 gzip 前后各 XOR 一次, 验签前再 XOR 一次;
后两次相抵, **生成端只需在 gzip 之后做一次 XOR**。

## 2. 补丁点定位方法(可复用到新版本)

1. **锚点**: Ed25519 依赖 SHA-512, 在 `.rdata` 搜常量 `22 AE 28 D7 98 2F 8A 42`
   (0x428a2f98d728ae22 LE) → 本样本命中 `0x14042FCE0`, 证明 CryptoPP Ed25519 在链路里。
2. **验签调用点**: 反汇编定位 2.11.3 的 Ed25519 verify 调用（`sub_140250020`），
   返回值保存点在 VA `0x14024B880`（`movzx ebx,al`）。
3. **实测确认**: 官方包该处字节为 `0F B6 D8 4C 89 6C 24 48 48 8D 05`
   (存 **r13**)。同版本不同 build 可能有微编译差异（寄存器选择不同），套硬编码特征前先核对。
4. 特征码全 .text 扫描唯一命中 → 文件偏移 `0x24AC80` → 3 字节补丁 `B3 01 90`。
5. 反汇编确认上下文:
   ```
   0x14024b876: lea rcx, [rsp + 0x48]
   0x14024b87b: call 0x140250020      ; Ed25519 verify
   0x14024b880: movzx ebx, al         ; ← 补丁这里
   0x14024b883: mov qword ptr [rsp+0x48], r13
   0x14024b888: lea rax, [rip + 0x1dbcb1]
   ...
   0x14024b89e: movzx eax, bl         ; 函数返回值
   ```

新版本适配流程: 搜 SHA-512 常量锚点 → 定位验签函数 → 找 `call verify` 后紧跟的
`movzx reg, al`(或 `sete reg`) → 以"call 后 2 字节内取 al 到局部寄存器"为特征重建 PATTERN。

## 3. 公钥与公钥自检(为什么选 patch 返回值而不是换公钥)

- 官方公钥 `86a6313855512c692b7f44a7041a86d02890544923714acaeeb29e52883c9060`
  以 AES-128-CTR 密文内嵌(`sub_140249FA0`, 8 个 mov 立即数, 58B)。
- 换公钥 = 已知明文+密文 XOR 得 keystream → 加密自己的公钥 → 回写。但程序启动/激活后
  有 **x_check_pubkey / pubkey1 / pubkey2** 三处自检(比对内嵌常量与运行时公钥),
  换了密文还得逐一处理, 改动面远大于 3 字节。
- patch 验签返回值不动公钥 → 自检天然通过。

## 4. 设备码两种形态(易混)

| 形态 | 生成 | 用途 |
|---|---|---|
| UI 展示码 `3-XXXXX-XXXXX-XXXXX-XXXXX` | 01 + blake2s(MachineGuid)[-4:] + blake2s(工作组)[-5:] → hex + 校验字符 → 字符映射"3679EFHKMNPRTWXY" → 1-5-5-5-5 分段 | 给用户看/复制 |
| 比较用明文 `XXXX-XXXXXXXX-XXXXXXXX?1` | blake2s('Snipaste 2'+'1'+MachineGuid)[-10:] → hex → 4-8-8 分段 + 校验字符 + '1' | JSON hwi.machineid, validate 实际比对 |

实测交叉验证: 展示码机器段解码 = `556F1512` == blake2s('Snipaste 2'+'1'+MachineGuid)[-4:].hex().upper() ✓

注意: 展示码工作组段实测 5 字节, 仅影响展示码复刻, 不影响激活。

## 5. 时间字段

- 格式: `Qt::ISODateWithMs` = `yyyy-MM-ddTHH:mm:ss.zzz`, 本地时间无时区后缀
- iat: 失败条件 `now < iat - 1200s`(状态码 8), 即 iat 不得早于 now 20 分钟以上 → 取 now-5min
- exp: 失败条件 `exp < now`(状态码 31) → 取 now+10y
- exx: "License expires on" 展示; ref: refreshActivation 定时器下次校验时间, 置远期免触发在线刷新

## 6. 状态码表(x_code)

```
0 成功 | 8 系统时间错误 | 0xa 无效授权码 | 0xc 无效凭证 | 0x15 授权被吊销
0x16 已过期 | 0x1e 达到设备上限 | 0x1f 本设备激活已过期
```

## 7. 端到端实测记录

- 激活弹窗文案: `Snipaste 2 专业版已激活 / 授权给: YG / 个人版 (3 设备)`
- 重启后托盘: `Snipaste 2.11.3 专业版 (桌面版)`(持久化)
- 整目录搬迁到其他盘后仍专业版 → 激活状态与安装目录无关(机器级存储, 未落在 config.ini;
  config.ini 仅 `first_run=false`, 注册表无 Snipaste 键, 具体凭据存储未定位, 不影响使用)
- 旧 2.8.3 Beta 与补丁 2.11.3 可并存(2.8.3 无离线激活入口, 离线激活自 2.10.3 引入)
