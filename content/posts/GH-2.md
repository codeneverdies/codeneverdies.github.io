+++
title = "4. Game Hacking - Valve Anti-Cheat (VAC)"
date = 2025-04-17T19:05:10-04:00
draft = false
author = "codeneverdies"
+++

---

> ## Intro

In 2002 Valve created an Anti-Cheat solution called "Valve Anti-Cheat" aka **VAC**. 
The first game they implemented VAC into was Counter-Strike. When **VAC** was introduced it only operated in 
User Mode (Still does) meaning it runs entirely in user space [^1] and has no kernel component.

Below is a list of games that use **VAC**..  [^2]

    Call of Duty: Modern Warfare 2
    Call of Duty: Modern Warfare 3
    Counter-Strike (video game)
    Counter-Strike: Condition Zero
    Counter-Strike: Source
    Counter-Strike 2
    Day of Defeat
    Day of Defeat: Source
    Deathmatch Classic
    Half-Life 2: Deathmatch
    Half-Life Deathmatch: Source
    Ricochet
    Team Fortress
    Team Fortress Classic

A longer list can be found here [^3].

---

> ## VAC-cident?

So.. if you don't know **VAC** has been around for quite a while, at the time of writing it'll be 23 years. 
Over the time they've made some mistakes but who doesn't? (Taken from wikipedia) [^4] [^5]

    - In July 2010, [snip] Approximately 12,000 owners of Call of Duty: Modern Warfare 2 were 
    banned when Steam updated a DLL file on disk after it had been loaded into memory by the 
    game, causing a false positive detection. These bans were revoked and those affected received 
    a free copy of Left 4 Dead 2 or an extra copy to send as a gift. 

    - In October 2023, certain users of AMD graphics cards were banned from Counter-Strike 2 
    after AMD added support for their "Anti-Lag+" feature via a driver update, which the game 
    flagged as a cheat due to it detouring certain DLL functions. AMD subsequently withdrew the 
    driver update and Valve pledged to unban any affected users.

This post isn't created to bash Valve they clean up after their mistakes and listen to their community, 
gotta love devs when they do that. I also commend them because getting **VAC** banned isn't such a slap 
on the wrist. Getting **VAC** banned has some stipulations such as:

- Having the **VAC** ban show on your Steam profile
- Being banned from all **"GoldSrc"** games
- Being banned from all **"Source engine"** games (The Counter-Strike serise)
- Not being able to **refund** the game you're **VAC** banned on

Knowing what'll happen if you get **VAC** banned is important to know because regardless if 
you're cheating or not false bans are no good. People in the community took it upon themselves
to reverse engineer the Anti-Cheat and understand what it does (some did it just to cheat).

---

> ## VAC what?

The previous section brings us to a term you may have heard before, the infamous **"VAC Bypass"**.
Searching online for information about bypassing **VAC** brings many blogs and repos that all seem to do/talk about something
similar and that's "Dumping the **VAC** modules". Let me explain, **VAC** is **NOT** just one executable on the system it streams it's 
Anti-Cheat modules (DLLs) from a server, once a module is recieved by some routine in **steamservice.dll** inside **steamservice.exe** 
(or **steam.exe** if **ran as admin**) it will be loaded using one of the two methods below. [^6] [^7] [^8] [^9] [^10] [^11] [^12] [^13]
 
- **Reflectively load** the DLL into memory
- Use the WinAPI function **LoadLibrary**

By default the Anti-Cheat modules are reflectively loaded into memory. The goal is to force **LoadLibrary** into being used, 
then someone can hook that function and dump the modules (DLLs) to disk, allowing someone to analyse the dumped DLLs and understand 
what they're doing to detect cheating.

---

> ## Dumping VAC Modules in the big '25

To kick start the journey on dumping the **VAC** modules load **steamservice.dll** into **Binary Ninja**. Once the binary is fully analyzed
go to "Triage Summary"

> ![VAC-1](/VAC-1.png)

It is **VERY** important to take note that this is a 32-bit process, so all pointers will be 32-bits in size you'll see why this is important later.

Next we'll search for calls to **LoadLibrary\*** I'll save the reader some time and tell you that we should be looking
for calls to **LoadLibraryW** it will be called in a very important function that we can use to back track.

> ![VAC-2](/VAC-2.png)

Following the reference takes us to an interesting function **sub_10086f80**

> ![VAC-3](/VAC-3.png)

Judging by the return value **HMODULE** and the calls to LoadLibrary* it's safe to say this function's job is to load
some kind of module and return a handle to it. Following references to where this function is called leads us to another interesting
function **sub_10086c40**.

> ![VAC-4](/VAC-4.png)

The beginning of the **sub_10086c40** function didn't look too important (at the time) but we should remember that this function also returns a handle to a module.
I looked at the references and it shows that this function is called once in the function **sub_10059040**.

> ![VAC-17](/VAC-17.png)


We can see **sub_10086c40** being called if we trace back the **first** argument passed to that function,
we'll see that it was used by another function **sub_100859d0**. If that function call is successful 
execution carries on, so it's safe to say it's important. Let's take a look at this function.

> ![VAC-5](/VAC-18.png)

This function makes two WinAPI calls

- **GetTempPathW**
    : Retrieves the path of the directory designated for temporary files.

- **GetTempFileNameW**
    : Creates a name for a temporary file. If a unique file name is generated, an empty file is created and the handle to it is released; otherwise, only a file name is generated.

The combination of these calls tells us that we need to be looking for any `.TMP` files being accessed, the names are usually in this format `<uuuu>.TMP`.

Now there's a path to a DLL floating in memory how does it get used? Look no more.

> ![VAC-5](/VAC-5.png)

```
100591f7   HMODULE eax_13 = sub_10086c40(edi_1, 0)
100591ff   *(esi + 4) = eax_13
100591ff   
10059204   if (eax_13 != 0)
10059215       int32_t eax_14 = sub_10086c20(eax_13, "_runfunc@20")
1005921d       *(esi + 0xc) = eax_14
```

The path `edi_1` is used by **sub_10086c40**, this function is used to get a handle to a module `eax_13` then it's passing that handle to **sub_10086c20**.
**sub_10086c20** takes two arguments we know the first is a handle to a module the second is from what we can see here a string `_runfunc@20`, the return value
`int32_t` looks a little weird but this is a 32-bit process remember ;) so this could be a pointer to something dont ya think? Here's the function prototype

```
int32_t sub_10086c20(HMODULE arg1, PSTR arg2)
```

Place your bets on it being a GetProcAddress wrapper.. Drum roll please... It is...

> ![VAC-6](/VAC-6.png)

So with this bit of information we know **steamservice.dll** recieves the **VAC** modules, it's using a function **sub_10086c40** which calls
**sub_10086f80** to load the Anti-Cheat module and return a handle, then that handle is passed to **sub_10086c20** to get the address 
of a function named `_runfunc@20`. By default as said earlier the modules are reflectively loaded so this isn't the regular control flow of 
**steamservice.dll**, this can be confirmed if you scroll up a bit in **sub_10059040** you'll see a flag being checked.

> ![VAC-7](/VAC-7.png)

**steamservice.dll** will most likely take this path unless we can do something about it

> ![VAC-8](/VAC-8.png)

Let's look at it in assembly

> ![VAC-9](/VAC-9.png)

Take a look at `je 0x10059127` ( `0x74 0x47` )

`0x74` is the jump if equal instruction and `0x47` is how many bytes forward to jump (71) in hex

What we wan't to do is change the first instruction at **steamservice.dll** + 0x590DE (0x100590de)

- to `jne 0x10059127` ( `0x75 0x47` )

we're changing the first byte of this instruction to be `0x75` which is jump if **NOT**
zero/equal. (Inverting)

> ![VAC-10](/VAC-10.png)

Now that we have a potential way of dumping the **VAC** modules let's test it! first we start steam and launch **x32dbg** as
admin we should remember the offset to our instructions **steamservice.dll** + 0x590DE.

> ![VAC-11](/VAC-11.png)

Once **x32dbg** is loaded attach to **steamservice.dll**

> ![VAC-12](/VAC-12.png)

Press `CTRL+G` and enter `steamservice.dll + 0x590DE`

> ![VAC-13](/VAC-13.png)

Now we're where we need to patch

> ![VAC-14](/VAC-14.png)

Right click on that instruction and click "Assemble" then enter `jnz 0x10059127` and hit ok

> ![VAC-15](/VAC-15.png)

It should be changed 

> ![VAC-16](/VAC-16.png)

The next step is to open **Procmon** play a game that uses **VAC** (I chose CSGO) and wait for
**steamservice.exe** to access some `.TMP` files.

Here are the **Procmon** filters

> ![VAC-19](/VAC-19.png)

While loading the game we see our first TMP file `C:\Windows\Temp\D54A.tmp`

> ![VAC-20](/VAC-20.png)

Let's join a public match and see if there are others

> ![VAC-21](/VAC-21.png)

And some more..

> ![VAC-22](/VAC-22.png)

We can also look at these files in the temp directory..

> ![VAC-23](/VAC-23.png)

I copied all of these files to a new directory and loaded `D54A.tmp` into **PE-bear**

> ![VAC-24](/VAC-24.png)

We see something familiar `_runfunc@20` this is the function that was found using **sub_10086c20**.

---

> ## To be continued

In the next post we will be doing analysis on these Anti-Cheat Modules to get a better understanding of what's going on.
I hope you enjoyed this post and most importantly learned a thing or two. Stay tuned!

---

> ## References

[^1]: [User_Mode_vs_Kernel_Mode](https://en.wikibooks.org/wiki/Windows_Programming/User_Mode_vs_Kernel_Mode)
[^2]: [List of games that use VAC - 1](https://en.wikipedia.org/wiki/Valve_Anti-Cheat#Additional_restrictions)
[^3]: [List of games that use VAC - 2](https://areweanticheatyet.com/?search=VAC&sortOrder=&sortBy=)
[^4]: [valve-apologizes-for-banning-over-12-000-legit-modern-warfare-2](https://www.engadget.com/2010-07-27-valve-apologizes-for-banning-over-12-000-legit-modern-warfare-2.html)
[^5]: [amd-pulls-drivers-that-cause-counter-strike-2-bans](https://www.tomshardware.com/news/amd-pulls-drivers-that-cause-counter-strike-2-bans-after-valve-roasted-them)
[^6]: [danielkrupinski - VAC-Bypass](https://github.com/danielkrupinski/VAC-Bypass)
[^7]: [nevioo1337 - VAC-ModuleDumper](https://github.com/nevioo1337/VAC-ModuleDumper/)
[^8]: [whereisr0da - Valve Anti Cheat - Part 1 : Module loading](https://whereisr0da.github.io/blog/posts/2021-03-10-quick-vac/)
[^9]: [Cra0 - Dumping VAC2 and VAC3 the easier way](https://cra0.net/blog/posts/archived/2015/rel-dumping-vac2-and-vac3-the-easier-way/)
[^10]: [twokilohertz -  VacDumperInternal](https://github.com/twokilohertz/VacDumperInternal)
[^11]: [absceptual.me - Reversing VAC: Initalization](https://web.archive.org/web/20240909100849/https://absceptual.me/posts/vac/)
[^12]: [The actual patch we do in this blog](https://github.com/danielkrupinski/vac-hooks/blob/master/vac-hooks/dllmain.c#L7)
[^13]: [noobesgt - PreventVAC + Information](https://www.unknowncheats.me/forum/anti-cheat-bypass/578728-preventvac-information.html)