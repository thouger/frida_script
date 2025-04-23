# frida_script

## 编译
每次用时先运行npm run watch然后改代码改index.ts文件,运行时运行命令frida -U -f 包名 --no-pause -l _agent.js

## 运行
新版的frida可以直接运行ts文件
包名可以用adb shell dumpsys window | grep mCurrentFocus查看最前端的app

### 如果是多进程的app
```shell
pid=$(frida-ps -U | rg -i Mobile | awk 'NR==1 {print $1}') && [ -n "$pid" ] && frida -U $pid -l _agent.js
```
NR==1是第一个进程，NR==2是第二个进程，frida-ps -U | rg -i Mobile，是查看包含Mobile关键字的进程，可以根据自己的需求修改

1. dump.so.py 运行:python .\dump_so.py libsgmainso-6.5.75.so
2. java/findClass.ts 有一些dex会延迟加载，这样无论在什么时候进行hook
3. encryption.ts java层自吐加密算法
4. one_instance.ts hook一个类的实例化时候
5. stringBuilder.ts 和JsonObject.ts 两个类，对有时候没有思路hook一下有奇效
6. so_method.ts 输出所有 so 的方法
7. all_java.ts 输出所有 java 的方法，包括隐藏的，真正解决一代壳加载的问题
8. stalker.ts stalker函数输出所有调用与被调用的函数地址,native_trace函数输出一段内存所有寄存器变化的值
9. 增加sktrace native层的trace
10. child_gating.py 适用于子进程的hook
11. findAllJavaClasses方法，对于读取内存的jar文件的精准定位
12. abstract.ts 增加hook抽象类下所有子类的功能