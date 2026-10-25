# -*- coding: utf-8 -*-
"""Snipaste 2.11.3 离线授权码生成器

用法:
    python kg.py [--name YG] [--email a@b.c] [--devices 3] [--plan Personal]
                 [--years 10] [--lic SNIPASTE-KG-0001] [--out license_code.txt]

依赖: pip install pynacl
原理见仓库 README.md。生成端编码链:
    sig = ed25519_sign(json)
    body = gzip(json) ^ sig          # 唯一一次 XOR, 在 gzip 之后
    code = '0' + check(b64) + '-' + b64(sig + body)
"""
import argparse
import base64
import datetime
import hashlib
import json
import sys
import zlib

try:
    from nacl.signing import SigningKey
except ImportError:
    sys.exit("[-] 需要 pynacl: pip install pynacl")

# 自签 Ed25519 私钥(固定便于复现; 验签已被补丁恒真, 任意 32B 均可)
PRIVATE_KEY = bytes.fromhex(
    "951743f1381818ec1af9a32a2eafce42c6261f5089468ef863e7b903c183b3f6")

WORKGROUP_FALLBACK = "WORKGROUP"


# ---------------------------------------------------------------- 本机环境
def get_machine_unique_id() -> bytes:
    """QSysInfo::machineUniqueId 的 Windows 取值顺序"""
    import winreg
    for path, name in [(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
                       (r"SOFTWARE\Microsoft\SQMClient", "MachineId")]:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            v, _ = winreg.QueryValueEx(k, name)
            winreg.CloseKey(k)
            if v:
                return str(v).encode()
        except OSError:
            pass
    raise SystemExit("[-] MachineUniqueId 取值失败")


def get_workgroup() -> str:
    """客户端用 netapi32!NetWkstaGetInfo(level=100) 取 wki100_langroup"""
    import ctypes
    from ctypes import wintypes

    class WKSTA_INFO_100(ctypes.Structure):
        _fields_ = [("platform_id", ctypes.c_int),
                    ("computername", wintypes.LPWSTR),
                    ("langroup", wintypes.LPWSTR),
                    ("ver_major", ctypes.c_int),
                    ("ver_minor", ctypes.c_int)]

    netapi32 = ctypes.WinDLL("netapi32")
    buf = ctypes.POINTER(WKSTA_INFO_100)()
    if netapi32.NetWkstaGetInfo(None, 100, ctypes.byref(buf)) != 0:
        return WORKGROUP_FALLBACK
    wg = buf.contents.langroup or WORKGROUP_FALLBACK
    netapi32.NetApiBufferFree(buf)
    return wg


# ---------------------------------------------------------------- 校验字符
def adjacent_check(s: str) -> str:
    """相邻字符 ASCII 差绝对值之和 % len → 取该位置字符 (sub_140288C00)"""
    if not s:
        return "0"
    if len(s) == 1:
        return s
    total = sum(abs(ord(s[i]) - ord(s[i - 1])) for i in range(1, len(s)))
    return s[total % len(s)]


# ---------------------------------------------------------------- 设备码
def blake2s_128(data: bytes, take: int) -> bytes:
    h = hashlib.blake2s(digest_size=16)
    h.update(b"Snipaste 2")
    h.update(b"1")
    h.update(data)
    return h.digest()[-take:]


def gen_machine_id(unique: bytes, length: int = 10) -> str:
    """比较用明文设备码 genId: blake2s[-L:] → hex大写 → 4-8-8 分段 → 校验字符 → '1'
    自洽约束: (strlen - 横线数 - 2) // 2 == length"""
    hx = blake2s_128(unique, length).hex().upper()
    parts, i = [], 0
    while i < len(hx):
        step = 4 if i == 0 else 8
        parts.append(hx[i:i + step])
        i += step
    s = "-".join(parts)
    s += adjacent_check(s.replace("-", ""))
    s += "1"
    assert (len(s) - s.count("-") - 2) // 2 == length, (s, length)
    return s


# ---------------------------------------------------------------- 编解码
def gzip_comp(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, 31)  # wbits=31 → gzip
    return co.compress(data) + co.flush()


def s_xor(key: bytes, data: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def iso_qt(dt: datetime.datetime) -> str:
    """Qt::ISODateWithMs: yyyy-MM-ddTHH:mm:ss.zzz 本地时间无时区后缀"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


# ---------------------------------------------------------------- 生成
def make_code(nam, eml, lic, dev, pln, years):
    unique = get_machine_unique_id()
    wg = get_workgroup()
    now = datetime.datetime.now()
    exp = now + datetime.timedelta(days=365 * years)

    js = {
        "nam": nam, "eml": eml, "lic": lic, "dev": dev, "pln": pln,
        "dom": wg, "api": 0,
        "iat": iso_qt(now - datetime.timedelta(minutes=5)),
        "exp": iso_qt(exp), "exx": iso_qt(exp), "ref": iso_qt(exp),
        "hwi": {"machineid": gen_machine_id(unique, 10), "platform": 1, "domain": ""},
    }
    json_bytes = json.dumps(js, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    sig = SigningKey(PRIVATE_KEY).sign(json_bytes).signature
    body = s_xor(sig, gzip_comp(json_bytes))
    b64 = base64.standard_b64encode(sig + body).decode()
    return "0" + adjacent_check(b64) + "-" + b64, js


# ---------------------------------------------------------------- 客户端模拟自检
def emulate_client(code: str) -> int:
    """按逆向出的 validate/sub_140245880 模拟, 0=通过"""
    if len(code) <= 3 or code[2] != "-":
        return 12
    check, payload = code[1], code[3:]
    if adjacent_check(payload) != check:
        return 12
    try:
        data = base64.standard_b64decode(payload)
    except Exception:
        return 12
    if len(data) < 65:
        return 12
    sig, body = data[:64], data[64:]
    body = s_xor(sig, body)
    try:
        body = zlib.decompress(body, 31)
    except Exception:
        return 12
    msg = s_xor(sig, s_xor(sig, body))  # 客户端三次 XOR 中后两次抵消
    lic = json.loads(msg.decode("utf-8"))
    now = datetime.datetime.now()

    def qdt(s):
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")

    if not lic["eml"] or lic["hwi"]["platform"] != 1:
        return 12
    if lic["dom"] and lic["dom"] != get_workgroup():
        return 12
    mid = lic["hwi"]["machineid"]
    want = gen_machine_id(get_machine_unique_id(),
                          (len(mid) - mid.count("-") - 2) // 2)
    if mid != want:
        return 12
    if now < qdt(lic["iat"]) - datetime.timedelta(seconds=1200):
        return 8
    if qdt(lic["exp"]) < now:
        return 31
    return 0


def main():
    ap = argparse.ArgumentParser(description="Snipaste 2.11.3 离线授权码生成器")
    ap.add_argument("--name", default="YG")
    ap.add_argument("--email", default="yg@local.test")
    ap.add_argument("--lic", default="SNIPASTE-KG-0001")
    ap.add_argument("--devices", type=int, default=3)
    ap.add_argument("--plan", default="Personal",
                    choices=["Personal", "Business", "Trial"])
    ap.add_argument("--years", type=int, default=10)
    ap.add_argument("--out", default="license_code.txt")
    a = ap.parse_args()

    code, js = make_code(a.name, a.email, a.lic, a.devices, a.plan, a.years)
    print(json.dumps(js, ensure_ascii=False, indent=2))
    print("\n[授权码]")
    print(code)
    rc = emulate_client(code)
    print(f"\n[模拟客户端 validate] = {rc} ({'OK' if rc == 0 else 'FAIL'})")
    if a.out:
        open(a.out, "w", encoding="utf-8").write(code + "\n")
        print(f"[*] written -> {a.out}")
    sys.exit(0 if rc == 0 else 1)


if __name__ == "__main__":
    main()
