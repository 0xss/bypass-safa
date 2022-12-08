# bypass 360-Windows Defender-Kaspersky Lab 
思路很简单就是远程加载shellcode 到内存中执行
shellcode base64编码 使用分段加载 绕过内存扫描 执行
测试cs 4.7 无阶段载荷 360 全免 执行操作无问题
defender 命令执行，文件上传下载，进程查看无问题，截图被杀
Kaspersky Lab 文件上传下载 无问题 命令执行被杀 
测试自写远控 所有操作均无问题


代码参考 
https://blog.csdn.net/weixin_44747030/article/details/127894742
https://github.com/CitrusIce/shellcodecat
