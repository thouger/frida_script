# frida_script

## 介绍几个常用的脚本

1.   anti_frida.js,最基础的模块,建议复制这个模块再去写新的脚本,一个对frida的检测,一个对ida调试的检测,还有console.颜色输出功能
2.   HashMap.js,hook map类,追踪常用
3.   StringBuffer.js,也是追踪常用,构造加密参数时前的参数常常会用StringBuffer.append
4.   encrypts.js,也是追踪用(没上面两个好用),追踪常见的aes/base/md5加密方法
5.   Okhttp3.js,hook没有混淆的okhttp3框架抓包
6.   popen.js,hook so层的libc.so的popen函数
7.   so.js,忘记了,比较重要
8.   vpn.js,绕过vpn检测
9.   show-all-classes-methods.js,输出所有类名(包含壳里面的),非常多,建议一次性输出并保存
10.   all_method_hook.js,由r0tracer.js改进,删了黑白名单和一些不需要的输出,第一行填hook的类,以及增加了antifrida和一个功能:printHashMap(r0tracer.js输出函数参数是map时有问题).
11.   one_method_hook.js,模糊匹配类下指定的一个方法