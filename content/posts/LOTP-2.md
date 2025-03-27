+++
title = "2. Land Of The PEB - Running from the debugger"
date = 2025-03-26T20:59:35-04:00
draft = false
author = "codeneverdies"
+++

Welcome to the second installment of "Land Of The PEB". Last post we talked about what the PEB was and some
ways it could be used to ones advantage. You can't run from it trust me.. You can find it in your nearest neighborhood even the 
one you're using to read this post (If you're on windows), but one thing we may be able to run from is the debugger. Using 
the PEB for **Anti-Debugging** purposes is a fairly known technique but don't let that fool you it's still a good thing to know.

---

> ## "You must learn to walk before you can run"

So.. you wan't to learn how to detect debuggers? There are a couple of ways to do so the two simplest ways I've found are:

+ Check the **BeingDebugged** member in the PEB
+ Check **NtGlobalFlag** in the PEB **(To see if the process was created by a debugger)**

these two don't do much justice compared to other **Anti-Debugging** methods but they sure are robust. We will start with the second method first.
If you've followed my previous post you should already have some way of getting a pointer to the PEB so I will be going off that. I will be doing this in C/ASM.

Here is my assembly code to get a pointer to the PEB [^1]

```asm

get_peb:
    push rdi
    mov rdi, rsp
    sub rsp, 0x20
    xor rax, rax
    mov rax, gs:[0x60]
    mov rsp, rdi
    pop rdi
    ret
```
---

> ## Running to the (NtGlobal)Flag

Before we move on we should talk about what **NtGlobalFlag** is and how we can get to it.

In the windows registry we can see that the "GlobalFlag" key's value is set to 0
This tells us that this is the default value.

> ![registry-globalflag](/registry-globalflag.png)

This can be confirmed by starting any process like notepad.exe, attaching a debugger to it and looking
at the **NtGlobalFlag** in the PEB. Notice how I said to start a process then attach, it will make much sense later.

Once notepad is open click "attach" in x64dbg and find notepad.exe in the list of processes.

> ![x64dbg-attach](/x64dbg-attach.png)

Once you're in x64dbg hit run until notepad is fully functional. This should look familiar, we are going to
index `0x60` bytes into the TEB (`gs`) using this command. 

`mov rax, gs:[0x60]`

Now the address of the PEB should be in the RAX register.

> ![PEB-RAX](/PEB-RAX.png)

Can be confirmed if you right click on that address in the RAX register and click "Follow in Memory Map"

> ![MMAP-PEB](/MMAP-PEB.png)

With this pointer we can grab the **NtGlobalFlag** value in the PEB which is at offset
`0xBC` on 64-bit systems with this command.

`mov al, [rax+0xBC]`

If you followed correctly earlier, the value in the RAX register should NOT change due to the fact
that the notepad process was not created by a debugger we only started notepad and then attached the debugger to it.

Now we will write a small program to check this flag and we will start it with a debugger. [^2]

```asm
    ... snip ...
    
    xor rax, rax
    mov rax, gs:[0x60]
    
    mov al, [rax+0xBC]
    and al, 0x70
    cmp al, 0x70
    jz goodbye
    xor rax, rax

    ... snip ...
``` 

```
goodbye:
    xor rax, rax
    add al, 1
    mov rsp, rdi
    pop rdi
    ret
```



Once the binary is loaded into x64dbg we can see our function

> ![Func](/Func.png)


Right before we execute the instruction `mov al,byte ptr ds:[rax+BC]` we can see again that a pointer to the PEB
is in the RAX.

> ![RAX-PEB2](/RAX-PEB2.png)


After that instruction is executed we can see that the `al` register changed which is the lowest byte of the RAX register
it is now `0x70` why?

> ![FLAGS-SET](/FLAGS-SET.png)

This is because when a process is created by a debugger three flags will be set:

+ **FLG_HEAP_ENABLE_TAIL_CHECK** = 0x10
+ **FLG_HEAP_ENABLE_FREE_CHECK** = 0x20
+ **FLG_HEAP_VALIDATE_PARAMETERS** = 0x40

It's a good idea to check against these flags explicitly because just checking if **NtGlobalFlag**
is not 0 shouldn't mean there is a debugger running. In short we should only check for a combination of
ALL of these flags `0x70` to prevent false positives.

Once that value is saved into the `al` register we do a bitwise AND on `0x70` and `al`, then
we compare `al` and `0x70` to check if the combination of flags are set. We can see that
after we execute `cmp al, 0x70` the Zero flag (ZF) gets set (if the result of an operation
is zero the Zero flag gets set to 1) this means that the value of **NtGlobalFlag**, was equal to `0x70`. 
that most likely means this process was created by a debugger (we know it was).

> ![ZERO-FLAG](/ZERO-FLAG.png)

---

> ## I hate Being (De)bugged!!

The good ol' **BeingDebugged** if the last technique was too much for you, this is one of the most 
trivial **Anti-Debugging** techniques out there. The **BeingDebugged** member of the PEB is used to check if 
the current process is being debugged or not. We can be see it in WinDbg using two commands `r $peb` -> `dt [address] ntdll!_peb`

> ![BD](/BD.png)

We can see that it's located at offset `0x02` and the value is set to `0x1` (true). With this information
we can write a function to do this for us.

I'm going to stick to ASM because I think it's good practice, we know we must do two things:

+ Get a pointer to the PEB
+ Get the **BeingDebugged** value

```asm
    ... snip ...

    mov rax, gs:[0x60]  // You should know this by now
    mov al, [rax+0x02]  // Grabbing the BeingDebugged value
    and rax, 0x000000FF // Clearing out everything except for al
   
    ... snip ...
```

Back to x64dbg! Again right after we execute the instruction `mov rax,qword ptr gs:[60]` 
we can see that a pointer to the PEB is in the RAX. If we right click on this address in RAX
and select "Follow in Dump" we can see there's an `0x1` two bytes in

> ![0x1-Dump](/0x1-Dump.png)

Stepping two more times does the following:

1. Moves the **BeingDebugged** value to the `al` register
2. Clears the remaning bits except the lowest 8
3. After these steps RAX should contain `0000000000000001`

> ![Clean-ret](/Clean-ret.png)

> ## Remarks

Those were two ways malware may detect if it's being debugged there are numerous ways to do so. If you're doing malware analysis
It should also be known that these two methods can easily be bypassed by simply changing the values to 0 in memory before they are accessed, like so.

> ![anti-debugging-bypass1](/anti-debugging-bypass1.png)

Click "Ok" and the value will change

> ![Changed](/Changed.png)

The **BeingDebugged** value was changed to `0x0` (false)

> ![Done](/Done.png)

---

> ## References

[^1]: https://github.com/codeneverdies/ws-loader/blob/main/asm/init.asm#L23
[^2]: https://github.com/codeneverdies/ws-loader/blob/main/asm/init.asm#L36

[aldeid.com - NtGlobalFlag](https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag)

[mahaloz - NtGlobalFlag bypass](https://ctf-wiki.mahaloz.re/reverse/windows/anti-debug/ntglobalflag/#manual-bypass-example)

[msdn - heap-parameter-checking](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/enable-heap-parameter-checking)

[msdn - heap-free-checking](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/enable-heap-free-checking)

[msdn - heap-tail-checking](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/enable-heap-tail-checking)

[checkpoint research <3 - NtGlobalFlag](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag)

[geoffchappell - peb](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)

[malgamy - Anti-debugging 0x03 ](https://malgamy.github.io/revese%20enginnering/Anti-debugging-and-anti-tracing-techniques-part3/)