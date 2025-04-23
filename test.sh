#!/bin/bash

adb shell am force-stop com.mobilechess.gp
# 启动应用
adb shell am start -n com.mobilechess.gp/com.moba.unityplugin.MobaGameUnityActivity

# 死循环等待第二个端口进程
while true; do
    # 获取应用进程的第二个端口PID
    pid=$(adb shell ps -ef | grep mobilechess | awk 'NR==2 {print $2}')
    
    # 如果找到PID，则退出循环
    if [ -n "$pid" ]; then
        echo "找到进程PID: $pid"
        break
    fi

    # 如果没有找到PID，输出等待信息并继续等待
    echo "未找到第二个端口进程，继续等待..."
done

# 使用frida命令附加到该进程
/home/thouger/Desktop/softdown/miniconda3/envs/py3.9/bin/frida -U -F $pid -l _agent.js