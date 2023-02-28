# frida_script

## 安装
运行npm install安装<br>
每次用时先运行npm run watch,作用是将项目内的typescript文件编译成_agent.js,具体可以看package.json。然后入口文件是index.ts,运行是运行命令frida -U -f 包名 --no-pause -l _agent.js

## 注
新版的frida可以直接运行ts文件
包名可以用adb shell dumpsys window | grep mCurrentFocus查看最前端的app
