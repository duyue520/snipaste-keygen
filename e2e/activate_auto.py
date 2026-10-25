# -*- coding: utf-8 -*-
"""Snipaste 2.11.3 离线激活全自动流程（Windows UI 自动化）

一条龙: 启动补丁版 → 托盘菜单打开「解锁专业版」→ 切离线激活页 → 粘贴授权码
       → 点激活 → 截图取证 → 重启验证托盘显示「专业版」

依赖: pip install pywinauto pywin32 pillow
用法: python activate_auto.py [Snipaste.exe 所在目录] [license_code.txt 路径]
注意: Win11 托盘溢出区适配; 若图标已固定在任务栏需微调 chevron 逻辑。
"""
import subprocess
import sys
import time

import win32clipboard
import win32con
from PIL import ImageGrab
from pywinauto import Application, Desktop
from pywinauto import keyboard

APP_DIR = sys.argv[1] if len(sys.argv) > 1 else r"Snipaste-2.11.3-x64"
EXE = APP_DIR.rstrip("\\") + r"\Snipaste.exe"
CODE_FILE = sys.argv[2] if len(sys.argv) > 2 else "license_code.txt"
CODE = open(CODE_FILE, encoding="utf-8").read().strip()


def tray_overflow_buttons(desk):
    """展开溢出区并返回按钮列表"""
    tray = desk.window(class_name="Shell_TrayWnd")
    chev = [b for b in tray.descendants(control_type="Button")
            if "显示隐藏的图标" in (b.window_text() or "")][0]
    chev.click_input()
    time.sleep(1.5)
    fly = desk.window(class_name="TopLevelWindowForOverflowXamlIsland")
    return tray, fly.descendants(control_type="Button")


def main():
    subprocess.Popen([EXE], cwd=APP_DIR)
    time.sleep(6)
    proc = [p for p in subprocess.run(["tasklist", "/FO", "CSV"],
                                      capture_output=True, text=True).stdout.splitlines()
            if p.startswith('"Snipaste.exe"')]
    assert proc, "Snipaste 未启动"

    app = Application(backend="uia").connect(title_re="解锁专业版.*", timeout=15) \
        if Desktop(backend="uia").windows(title_re="解锁专业版.*") else None

    if app is None:
        # 托盘 → 菜单 → 解锁专业版
        desk = Desktop(backend="uia")
        _, btns = tray_overflow_buttons(desk)
        btn = [b for b in btns if "Snipaste" in (b.window_text() or "")][0]
        btn.click_input()
        time.sleep(1.5)
        unlock = None
        for _ in range(10):
            time.sleep(0.5)
            for w in Desktop(backend="uia").windows():
                if w.element_info.class_name == "UnlockProDialog":
                    unlock = w
            if unlock:
                break
        assert unlock, "解锁对话框未弹出"

    app = Application(backend="uia").connect(title_re="解锁专业版.*", timeout=10)
    dlg = app.window(class_name="UnlockProDialog")
    dlg.set_focus()
    time.sleep(0.8)

    # 若在在线页, 切到离线页
    off = [b for b in dlg.descendants(control_type="Button")
           if (b.window_text() or "").strip() == "离线激活"]
    if off:
        off[0].click_input()
        time.sleep(1.5)

    # 多行码框 = 最高的编辑控件
    box = max([c for c in dlg.descendants()
               if c.element_info.control_type in ("Document", "Edit")],
              key=lambda c: c.rectangle().height())
    dev = [c for c in dlg.descendants(control_type="Edit")
           if "-" in (c.window_text() or "") and c.element_info.class_name == "QLineEdit"]
    if dev:
        print("[*] UI 设备码:", dev[0].window_text())

    box.click_input()
    time.sleep(0.4)
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardText(CODE, win32con.CF_UNICODETEXT)
    win32clipboard.CloseClipboard()
    keyboard.send_keys("^a^v")
    time.sleep(1.5)

    act = [b for b in dlg.descendants(control_type="Button")
           if (b.window_text() or "").strip() == "激活"]
    assert act and act[0].is_enabled(), "激活按钮不可用(授权码格式层未过?)"
    act[0].click_input()
    print("[*] 已点击激活, 等待结果...")
    time.sleep(6)

    r = dlg.rectangle()
    ImageGrab.grab(bbox=(r.left - 8, r.top - 8, r.right + 8, r.bottom + 8)).save("activated.png")
    texts = [c.window_text() for c in dlg.descendants()
             if c.element_info.control_type == "Text" and c.window_text()]
    print("[*] 结果:", texts)
    ok = any("已激活" in t for t in texts)
    print("[*] 激活成功 ✓" if ok else "[!] 未检测到成功文案, 看 activated.png")

    ok_btn = [b for b in dlg.descendants(control_type="Button")
              if (b.window_text() or "").strip() == "好的"]
    if ok_btn:
        ok_btn[0].click_input()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
