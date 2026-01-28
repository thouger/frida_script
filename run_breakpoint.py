#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 断点式 Hook 启动器
使用方法:
  python run_breakpoint.py -o 0x1B98F4 -r x1,x0,x2
  python run_breakpoint.py -o 1B98F4 -r x1 -s libmetasec_ml.so
"""

import frida
import sys
import argparse
import time


# 固定配置
DEVICE_ID = "2B16166D4AA2EB"
PACKAGE_NAME = "com.ss.android.ugc.aweme"
DEFAULT_SO = "libmetasec_ml.so"


def on_message(message, data):
    """处理 Frida 消息"""
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] 错误: {message['stack']}")


def main():
    parser = argparse.ArgumentParser(description='Frida 断点式 Hook 工具')
    parser.add_argument('-o', '--offset', required=True, help='偏移地址 (如: 0x1B98F4 或 1B98F4)')
    parser.add_argument('-r', '--registers', default=None, help='要监控的寄存器,逗号分隔 (默认: 打印全部寄存器)')
    parser.add_argument('-s', '--soname', default=DEFAULT_SO, help=f'SO 库名称 (默认: {DEFAULT_SO})')
    parser.add_argument('--script', default='breakpoint.js', help='Frida 脚本路径 (默认: breakpoint.js)')

    args = parser.parse_args()

    # 规范化偏移地址
    offset = args.offset.strip()
    if not offset.startswith('0x'):
        offset = '0x' + offset.lstrip('0xX')


    try:
        # 连接指定设备
        device = frida.get_device(DEVICE_ID, timeout=5)

        # 启动应用 (固定使用 spawn 模式)
        pid = device.spawn([PACKAGE_NAME])
        session = device.attach(pid)

        # 加载脚本
        with open(args.script, 'r', encoding='utf-8') as f:
            script_code = f.read()

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        # 初始化 Hook
        init_params = {
            'offset': offset,
            'soname': args.soname,
        }

        # 只有在指定了 -r 参数时才传入 registers
        if args.registers is not None:
            init_params['registers'] = args.registers

        script.exports_sync.init(init_params)

        # 恢复应用
        device.resume(pid)

        # 保持脚本运行
        sys.stdin.read()

    except frida.InvalidArgumentError:
        print(f"[!] 错误: 找不到设备 {DEVICE_ID}")
        print("[!] 提示: 使用 'frida-ls-devices' 查看可用设备")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] 错误: 找不到脚本文件 {args.script}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
