之前写过很多次阿里系的的算法内容的文章，一直都是停留在某一点，或者某些研究到关键位置处理方法和策略。
这一次，写写某鱼的x-sign生成的过程，以及Native层的一些关键位置的数据。

## unidbg跑通
要想探究native层的奥秘，现在最方便的无非是Frida和unidbg。frida倾向于现写现用，unidbg倾向于对于底层函数的逆向分析。
可能还有人说XPosed，虽然在Hook持久性上面，XPosed的优势明显，但对于Native层的灵活调试和算法研究，XPosed还是有非常明显的不足之处的。

unidbg的代码以前写过很多次了，基本很容易通过。这里就不再展开说了。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1a728c08f7da410fb4a3a174e3d147fd.png#pic_center)
相关内容可以看我以前的文章：
[念念不忘，必有回响。研究阿里系签名，获益良多——unidbg/idlefish/taobao/damai](https://blog.csdn.net/John_Lenon/article/details/138280982)
[用Unidbg实现阿里系x-sign签名, 成功实现长x-mini-wua](https://blog.csdn.net/John_Lenon/article/details/136977632)
[unidbg实现淘宝请求参数算法，实现脱离模拟器/手机请求淘宝、闲鱼](https://blog.csdn.net/John_Lenon/article/details/129572217)

## 根据生成签名的位置，追踪x-sign的读和写。
如下方这次生成的x-sign，trace这块内存的写入
```
azU7Bc002xAAJ1j6L+zCsGD9Ijno51j3Wp3y0dj3WPdbxnL/4W9aBqSdKkp+fh5TrmXZo0wH1f8o/Z+DCO2f8wlDDmdY51j3WOdY91

最后3次写入为：
// 开始写入x-sign
[23:00:48 332] Memory WRITE at 0x4051e260, data size = 4, data value = 0x37557a61, PC=RX@0x401335d0[libmain.so]0x1335d0, LR=RX@0x40132c68[libmain.so]0x132c68
[23:00:48 332] Memory WRITE at 0x4051e264, data size = 4, data value = 0x30306342, PC=RX@0x401337e8[libmain.so]0x1337e8, LR=RX@0x40132c68[libmain.so]0x132c68
[23:00:48 332] Memory WRITE at 0x4051e268, data size = 4, data value = 0x41417832, PC=RX@0x401337e8[libmain.so]0x1337e8, LR=RX@0x40132c68[libmain.so]0x132c68

0x37557a61
小端序字符即为：azU7
0x30306342
小端序字符即为：Bc00
0x41417832
小端序字符即为：2xAA

```
然后去查看当前函数，发现是最终的JNI函数，(*env)->NewStringUTF
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d2f85270aa5e456297030790c6ee7c8b.png#pic_center)
修改一下参数类型，就可以看出这个函数的作用
![修改一下参数类型，就可以看出这个函数的作用](https://i-blog.csdnimg.cn/direct/1677d7a7ffb94d06ac8b2ad39555e90b.png#pic_center)
方法是对了，就是有点笨。当然，如果你可以大胆地猜测使用算法中使用的函数，或许可以直接到中间去命中要害。

比如我们猜一个MD5， 那你就可以使用MD5函数的关键位置/信息/魔数，等去查找关键信息，再过滤掉无用的数据，多试几次，或许就可以找到真正的函数位置了。

## 大杀器 unidbg trace
上面已经使用过trace写入了， 这里就完整地说一下trace这个大杀器。

如果说unidbg有什么对于静态逆向跟踪最友好的工具，那一定是trace了。
traceCode: 可以把特定位置的机器码完整的记录下来，以及该位置的寄存器信息，对于静态阅读，非常地有用。
traceRead: 可以把特定位置内存的读取记录下来，包括读取函数位置/读取内存地址/读取数据内容。
traceWrite：和traceRead正好相关，可以把写内存的记录保存下来。
配合上面三个大杀器的使用，再加上setRedirect方法保存记录到本地。不要太友好，不要太方便了。

traceCode记录
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0fc77de673fc4c45b313a0432ad4243f.png#pic_center)

traceWrite记录
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/6cbc2018e940401c81d91f8338f33ca3.png#pic_center)
traceRead记录
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2ae0ad07e8c44af8b28dea84e7edc5ea.png#pic_center)
## 然后，关键位置Debugger hook
就这样一直追到关键的函数位置，就可以查看函数入参的内容了。
比如我想查看某个函数位置的参数，或者寄存器信息，可以用Debugger来Hook.

```java
attach.addBreakPoint(breakPoint, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long l) {
                count++;
                logger.debug("Hit 0x{} - {} 次",Long.toHexString(point), count);
                RegisterContext context = emulator.getContext();
                int intByRegR0 = context.getIntByReg(Arm_const.ARM_REG_R0);
                int intByRegR1 = context.getIntByReg(Arm_const.ARM_REG_R1);
                int intByRegR2 = context.getIntByReg(Arm_const.ARM_REG_R2);
```

比如我获取到x-sign的入参为： 前面某个函数16个字节的结果 + 41个字节的byte拼接 + ...
然后我们需要获取这个关键位置的字符拼接了，就可以写Debugger代码来获取：

```java
byte[] bytes = UnidbgPointer.pointer(emulator, intByReg).getByteArray(0, 112);
Inspector.inspect(bytes, "x-sign");
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/3c4c8fa341584ab28c4360ac81f523d6.png#pic_center)
这样，经过很长时间的学习，将关键函数全部摸清，终于成了：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a02e87432b604cde95fd52f5526f5645.png#pic_center)


