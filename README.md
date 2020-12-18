# process-defender
 进程防护软件



## 环境

系统：windows10 64位

语言：C++

IDE：vs2013

工具集：.netframework v120



## 基本思想

先通过调用CreateToolhelp32Snapshot函数获得进程快照，然后调用GetProcessFullPath得到进程的完整路径，最后调用VerifyEmbeddedSignature判断进程的签名是否存在以及是否可信，而具体执行信任验证操作的是windows提供的api WinVerifyTrust。

并建立黑名单和白名单，对于已经被用户选择信任的进程加入白名单，否则加入黑名单，之后对于白名单的进程不用再校验签名，而黑名单中的进程可以直接终止。只有都不是的情况下才进行签名校验。

同时，设置间隔时间，一次遍历完成后，每隔固定时间再获得进程快照并监控是否有可疑进程，以此来使计算机一直处于被保护状态。



## 效果图

![image-20201218110009296](C:\Users\scorpion\AppData\Roaming\Typora\typora-user-images\image-20201218110009296.png)



![image-20201218110024668](C:\Users\scorpion\AppData\Roaming\Typora\typora-user-images\image-20201218110024668.png)