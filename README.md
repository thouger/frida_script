# frida_script
运行npm install安装<br>
每次用时先运行npm run watch然后改代码改index.ts文件,运行时运行命令frida -U -f 包名 --no-pause -l _agent.js

包名可以用adb shell dumpsys window | grep mCurrentFocus查看最前端的app
