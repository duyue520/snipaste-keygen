# Snipaste 2.11.3 离线激活补丁 + 注册机

对 Snipaste 2.11.3 (x64) 离线授权体系的完整逆向实现：一个 3 字节特征码补丁 + 一个自包含注册机，
在本机真实 UI 上完成离线激活并重启持久化为专业版。

> 本项目为授权环境下的逆向研究记录，样本与产物仅用于本地兼容性分析。Snipaste 是优秀的产品，
> 商用请[购买正版授权](https://zh.snipaste.com/download.html)。

## 效果

```
Snipaste 2 专业版已激活
授权给: YG
个人版 (3 设备)
感谢您的支持！现在重启即可享受专业版~
```

重启后托盘显示 `Snipaste 2.11.3 专业版 (桌面版)`。

## 原理

### 授权码结构

```
明文 JSON(license info)
  │  Ed25519 私钥签名 → sig(64B)
  │  body = gzip(JSON) ^ sig        ← 生成端只做这一次 XOR（gzip 之后）
  │  data = sig(64B) + body
  │  Base64(标准表)
  │  前缀: '0' + 校验字符 + '-'
  ▼
授权码字符串 (形如 07-SHSpe6Cw...)
```

- 校验字符 = 载荷相邻字符 ASCII 差绝对值之和 `% len` 取该位置字符（防手误，无密码学强度）
- 客户端验签 message = `gunzip(body ^ sig)`（客户端内部三次 XOR，后两次抵消）
- Ed25519 公钥硬编码于客户端（AES-128-CTR 懒解密），私钥在官方手里 → 无法伪造签名 → 必须补丁验签

### 补丁点（本仓库实测，官方 2.11.3 x64）

```
VA 0x14024B880  文件偏移 0x24AC80
原: 0F B6 D8          movzx ebx, al        ; call sub_140250020 (Ed25519 verify) 的返回值
    4C 89 6C 24 48    mov [rsp+48], r13
    48 8D 05          lea rax, ...
改: B3 01 90          mov bl, 1 ; nop      ; 验签恒真
```

特征码：`0F B6 D8 4C 89 6C 24 48 48 8D 05`（在 .text 中唯一命中）。

### 与 52pojie 帖子 (tid=2114393) 的差异

帖子针对的 2.11.3 样本特征码是 `0F B6 D8 48 89 6C 24 48 48 8D 05`（存 rbp），
官方现行 2.11.3 x64 下载包中该指令存 **r13**（`4C 89 6C 24 48`）。
直接套帖子特征码会 0 命中——本项目按 VA 定位后修正了特征码，一次补丁成功。

### 授权 JSON

```json
{
  "nam": "YG", "eml": "yg@local.test", "lic": "SNIPASTE-KG-0001",
  "dev": 3, "pln": "Personal", "dom": "WORKGROUP", "api": 0,
  "iat": "2026-10-25T15:19:24.161", "exp": "2036-10-22T15:24:24.161",
  "exx": "...", "ref": "...",
  "hwi": {"machineid": "29D1-B6EA3E40-556F151241", "platform": 1, "domain": ""}
}
```

validate()（`sub_140245880`）逐项校验：

| 字段 | 约束 | 注册机取值 |
|---|---|---|
| eml | 非空 | 任意邮箱 |
| hwi.platform | 必须 == 1 | 1 |
| dom | 空或 == 本机工作组明文/其 blake2s hex | NetWkstaGetInfo level 100 实取 |
| hwi.machineid | == 本机 genId(L) | blake2s 见下 |
| iat | ≤ now+20min | now-5min |
| exp | ≥ now | now+10 年 |
| nam/lic/dev/pln/api | **不检查**（仅展示） | 任意 |

machineid（比较用明文）= `genId(10)`：

```python
h = blake2s(digest_size=16)
h.update(b'Snipaste 2'); h.update(b'1'); h.update(MachineGuid)
hx = h.digest()[-10:].hex().upper()          # 20 hex 字符
s  = hx[:4] + '-' + hx[4:12] + '-' + hx[12:] # 4-8-8 分段
s += adjacent_check(hx)                       # 追加校验字符（对无横线 hex 计算）
s += '1'                                      # 追加版本位
# 自洽约束: (len(s) - 横线数 - 2) // 2 == 10
```

MachineUniqueId 来源：`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`（缺省回退 SQMClient\MachineId）。

设备码展示形式（UI 上那个 `3-6FFHY-...`）与 machineid 是**两种形态**，展示码机器段
`blake2s('Snipaste 2'+'1'+MachineGuid)[-4:]` 可用于人工核对算法对齐（本项目实测一致）。

## 复现步骤

依赖：Python 3.10+，`pip install pynacl pefile`（UI 自动化另需 `pywinauto pywin32 pillow`）。

```powershell
# 1. 下载官方包（约 19MB）
curl.exe -L -o Snipaste-2.11.3-x64.zip https://download.snipaste.com/archives/Snipaste-2.11.3-x64.zip
Expand-Archive Snipaste-2.11.3-x64.zip -DestinationPath Snipaste-2.11.3-x64

# 2. 打补丁（自动备份 Snipaste.exe.orig）
python patch/patch_2113.py   # 内部路径按需修改，或看源码 12 行

# 3. 生成本机授权码（自动读 MachineGuid + 工作组，含客户端模拟自检）
python keygen/kg.py --name YG --email yg@local.test --devices 3
#    输出 JSON + 授权码，存 license_code.txt，末行 [模拟客户端 validate] = 0 (OK) 才算数

# 4. 启动补丁版，托盘菜单 → 解锁专业版 → 离线激活 → 粘贴授权码 → 激活
# 5. 重启 Snipaste，托盘显示「专业版」即持久化成功

# （可选）全自动：UI 自动化一条龙（需上面的依赖）
python e2e/activate_auto.py
```

## 激活方案对比（"还有啥更好的办法"）

| 方案 | 改动 | 优点 | 缺点 |
|---|---|---|---|
| **A. patch 验签返回值（本项目）** | 3 字节 | 特征码定位稳、唯一命中、注册机照常工作 | 每个版本特征码可能微调 |
| B. 替换硬编码公钥密文 | 64 字节 | 逻辑上更"正统"（用自己密钥对） | 需已知明文推 AES-CTR keystream 再加密自己的公钥；且启动有公钥自检（x_check_pubkey*），替换后还要处理自检，工作量大 |
| C. patch validate() 恒真 | ~6 字节 | 连授权码都不用对字段 | 返回值写入点带栈布局上下文，跨版本特征更脆；且授权码格式层(长度/校验符/gzip)仍要合法，省不了注册机 |
| D. Frida 动态 hook | 0 字节 | exe 不动 | 每次要起 frida；对便携分发不友好 |

结论：A 是当前最稳的最小改动。若未来版本特征码漂移，用 `docs/analysis.md` 的定位方法
（SHA-512 常量表锚点 + 验签 call 上下文）重新定位即可。

## 二开方向

- **新版本适配**：跑 `docs/analysis.md` 的定位流程 → 更新 `patch/PATTERN`；JSON 层近几版稳定
- **注册机参数**：`kg.py` 已参数化（姓名/邮箱/设备数/方案/年限）；pln 支持 Personal/Business/Trial
- **工作组段**：UI 展示码中工作组段实测为 5 字节（非帖子的 4 字节），只影响展示码复刻，不影响激活
- **跨机授权码**：换机器重跑 `kg.py` 即可（machineid 绑定 MachineGuid）；也可以做"收集目标机
  设备码 → 异地生成 → 回贴"的离线分发流
- **Mac/Linux**：授权体系同源（platform 字段区分），补丁点需按平台重新定位

## 项目结构

```
├── README.md
├── keygen/kg.py            # 注册机（含客户端 validate 模拟自检）
├── patch/patch_2113.py     # 特征码补丁器
├── e2e/activate_auto.py    # UI 自动化全流程（托盘→离线激活→粘码→验证）
├── docs/analysis.md        # 逆向分析记录（定位方法 + 差异点）
└── docs/references.md      # 参考资料索引
```

## 致谢

- [52pojie tid=2114393《snipaste V2.11.3 Pro》](https://www.52pojie.cn/forum.php?mod=viewthread&tid=2114393)（yzy1226357697）
- [博客园 DirWangK《Snipaste-2.10.8-x64 离线激活记录》](https://www.cnblogs.com/DirWang/p/19258416)

## License

MIT

## 直接下载(免动手)

到 [Releases](../../releases) 页下载任一:

| 资产 | 说明 |
|---|---|
| Snipaste-2.11.3-Pro-Portable.zip | 全套便携包: 已打补丁的 Snipaste 2.11.3 + SnipasteKeygen.exe + 快速使用说明.txt, 解压即用 |
| SnipasteKeygen.exe | 免 Python 的注册机单文件(零依赖, 在你的机器上运行生成本机授权码) |
| Snipaste-2.11.3-x64-patched.exe | 已打补丁的 Snipaste.exe 单文件, 替换官方包同名文件即可 |

三步走: 解压 → 跑 SnipasteKeygen.exe(确认末行 alidate = 0 (OK)) → Snipaste 托盘菜单
「解锁专业版 → 离线激活」粘贴授权码 → 重启。授权码绑定本机, 换机重跑 keygen。
