# -*- coding: utf-8 -*-
"""Snipaste 2.11.3 x64 验签补丁（特征码定位, 唯一命中, 自动备份）

用法: 修改下方 EXE 路径后直接运行; 依赖 pip install pefile

定位目标(52pojie tid=2114393, 本仓库按官方 2.11.3 x64 实测修正):
  VA 0x14024B880
  0F B6 D8          movzx ebx, al      ; call sub_140250020 (Ed25519 verify) 返回值
  4C 89 6C 24 48    mov [rsp+48], r13  ; 注意: 官方包存 r13, 帖子样本存 rbp
  48 8D 05          lea rax, ...
改写: B3 01 90  (mov bl,1 ; nop) → 验签恒真
"""
import os
import shutil
import sys

import pefile

EXE = r"Snipaste-2.11.3-x64\Snipaste.exe"   # ← 按需修改
PATTERN = bytes.fromhex("0FB6D84C896C2448488D05")
REPL = b"\xB3\x01\x90"


def main():
    data = open(EXE, "rb").read()
    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(base + s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
            for s in pe.sections]

    def off2va(off):
        for va, vs, pr, sr in secs:
            if pr <= off < pr + sr:
                return va + (off - pr)
        return None

    hits, i = [], data.find(PATTERN)
    while i != -1:
        hits.append(i)
        i = data.find(PATTERN, i + 1)

    print(f"[*] pattern hits: {len(hits)}")
    if not hits:
        sys.exit("[-] 特征码未命中: 样本不是官方 2.11.3 x64, 或该版本指令布局有变."
                 "参见 docs/analysis.md 的重新定位方法")
    if len(hits) > 1:
        print("[!] 多处命中, 逐一补丁:")
        for o in hits:
            print(f"    off {o:#x}  VA {off2va(o):#x}")

    bak = EXE + ".orig"
    shutil.copy2(EXE, bak)
    print(f"[*] backup -> {bak}")

    buf = bytearray(data)
    for o in hits:
        buf[o:o + 3] = REPL
        print(f"[+] patched off {o:#x}  VA {off2va(o):#x}: 0FB6D8 -> B30190")
    tmp = EXE + ".new"
    open(tmp, "wb").write(bytes(buf))
    os.replace(tmp, EXE)
    print("[+] done:", EXE)


if __name__ == "__main__":
    main()
