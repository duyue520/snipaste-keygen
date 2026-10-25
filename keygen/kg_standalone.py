# -*- coding: utf-8 -*-
"""Snipaste 2.11.3 离线授权码生成器(零依赖版)

与 keygen/kg.py 功能一致, 但不依赖 pynacl —— Ed25519 签名用内嵌纯 Python 实现
(ed25519.py, BSD 授权, RFC 8032 参考实现)。客户端验签已被补丁恒真, 这里生成
规范签名只为保持授权码结构标准。

用法:
    python kg.py [--name YG] [--email a@b.c] [--devices 3] [--plan Personal]
                 [--years 10] [--lic SNIPASTE-KG-0001] [--out license_code.txt]
"""
import argparse
import base64
import datetime
import hashlib
import json
import sys
import zlib

# ------------------------------------------------ 纯 Python Ed25519 (RFC 8032)
# 基于 RFC 8032 参考实现(BSD)精简, 仅保留签名所需部分
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def sha512(s):
    return hashlib.sha512(s).digest()


def xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


By = (4 * pow(5, P - 2, P)) % P
Bx = xrecover(By)
B = (Bx, By, 1, (Bx * By) % P)  # 扩展坐标
IDENT = (0, 1, 1, 0)


def edwards_add(pt1, pt2):
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def scalarmult(pt, e):
    acc = IDENT
    while e:
        if e & 1:
            acc = edwards_add(acc, pt)
        pt = edwards_add(pt, pt)
        e >>= 1
    return acc


def encode_point(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = (x * zi) % P, (y * zi) % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def Hint(m):
    return int.from_bytes(sha512(m), "little")


def ed25519_sign(priv32: bytes, msg: bytes) -> bytes:
    assert len(priv32) == 32
    h = sha512(priv32)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8          # RFC 8032 clamp
    a |= 1 << 254
    r = Hint(h[32:] + msg)
    R = encode_point(scalarmult(B, r))
    A = encode_point(scalarmult(B, a))
    S = (r + Hint(R + A + msg) * a) % L
    return R + S.to_bytes(32, "little")


# ------------------------------------------------ 本机环境
def get_machine_unique_id() -> bytes:
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
        return "WORKGROUP"
    wg = buf.contents.langroup or "WORKGROUP"
    netapi32.NetApiBufferFree(buf)
    return wg


# ------------------------------------------------ 校验字符 / 设备码 / 编解码
def adjacent_check(s: str) -> str:
    if not s:
        return "0"
    if len(s) == 1:
        return s
    total = sum(abs(ord(s[i]) - ord(s[i - 1])) for i in range(1, len(s)))
    return s[total % len(s)]


def blake2s_128(data: bytes, take: int) -> bytes:
    h = hashlib.blake2s(digest_size=16)
    h.update(b"Snipaste 2")
    h.update(b"1")
    h.update(data)
    return h.digest()[-take:]


def gen_machine_id(unique: bytes, length: int = 10) -> str:
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


def gzip_comp(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    return co.compress(data) + co.flush()


def s_xor(key: bytes, data: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def iso_qt(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


PRIVATE_KEY = bytes.fromhex(
    "951743f1381818ec1af9a32a2eafce42c6261f5089468ef863e7b903c183b3f6")

# ------------------------------------------------ 生成 / 自检
def make_code(nam, eml, lic, dev, pln, years):
    now = datetime.datetime.now()
    exp = now + datetime.timedelta(days=365 * years)
    js = {
        "nam": nam, "eml": eml, "lic": lic, "dev": dev, "pln": pln,
        "dom": get_workgroup(), "api": 0,
        "iat": iso_qt(now - datetime.timedelta(minutes=5)),
        "exp": iso_qt(exp), "exx": iso_qt(exp), "ref": iso_qt(exp),
        "hwi": {"machineid": gen_machine_id(get_machine_unique_id(), 10),
                "platform": 1, "domain": ""},
    }
    json_bytes = json.dumps(js, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sig = ed25519_sign(PRIVATE_KEY, json_bytes)
    body = s_xor(sig, gzip_comp(json_bytes))
    b64 = base64.standard_b64encode(sig + body).decode()
    return "0" + adjacent_check(b64) + "-" + b64, js


def emulate_client(code: str) -> int:
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
    msg = s_xor(sig, s_xor(sig, body))
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
    ap.add_argument("--lic", default="SNIPaste-KG-0001".upper())
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
