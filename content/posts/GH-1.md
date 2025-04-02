+++
title = "3. Game Hacking - BakkesMod"
date = 2025-03-27T23:48:40-04:00
draft = false
author = "codeneverdies"
+++

> ## Intro

So i've been playing rocket league for as long as I can remember, and I have this mod called
**BakkesMod**. I have **BakkesMod** to use skins I don't have unlocked, you can basically call it a 
"skin changer" with one caveat, you can only see the skins client side. On the other hand it has 
loads of functionality.

> ![BM-1](/BM-1.png)

It was only a matter of time before I thought to myself "How does this even work?" so I did what anyone else
in the world would do, and that was go to their [github repo](https://github.com/bakkesmodorg) :).

> ## The Injectahhhhh

Upon visiting their profile I see many interesting repos but one catches my eye.

https://github.com/bakkesmodorg/BakkesModInjectorCpp

This is the code for their DLL Injector, i.e place an arbitrary DLL inside the address space of another (remote) process. 
Once that DLL is inside of the remote process it creates a remote thread to call DllMain of the DLL that was injected, 
once DllMain is called execution starts and BakkesMod can do it's thing.

**DLL Injection** is not a new technique, it's a widely known technique to get code to run inside of another
process. Sometimes malware and cheats use **DLL Injection** to setup for things like hooking because once their DLL is loaded
into the target process it has access to the memory of that target process as well, meaning it can manipulate
the functionality of the process while it's running which is a big win for someone who wants to do so.

Sidenote: (**BakkesMod** is considered a "Mod" not a "Cheat" hence the name, it does not give an unfair advantage)

Here's a code snippet from [ired-team](https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection#references) demonstrating **DLL Injection**

```c
int main(int argc, char *argv[]) {
	HANDLE processHandle;
	PVOID remoteBuffer;
	wchar_t dllPath[] = TEXT("C:\\experiments\\evilm64.dll");
	
	printf("Injecting DLL to PID: %i\n", atoi(argv[1]));
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);	
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
	CloseHandle(processHandle); 
	
	return 0;
}
```
---

Now that we know BakkesMod does **DLL Injection** we should be looking for these function calls inside the code

+ `OpenProcess`
+ `WriteProcessMemory`
+ `VirtualAllocEx`
+ `VirtualProtect` (maybe)
+ `CreateRemoteThread`

Looking around you'll see a couple files but one should stick out like a sore thumb, [`DllInjector.cpp`](https://github.com/bakkesmodorg/BakkesModInjectorCpp/blob/master/BakkesModInjectorC%2B%2B/DllInjector.cpp) In this file you'll find a function called [`InjectDLL`](https://github.com/bakkesmodorg/BakkesModInjectorCpp/blob/master/BakkesModInjectorC%2B%2B/DllInjector.cpp#L51)

> ![BM-2](/BM-2.png)

This function takes in a `std::wstring` `processName` which would most likely be `RocketLeague.exe` and a `std::filesystem::path` `path` which would most likely be the path to the DLL to be injected. Inside the function we can see it's doing the same exact thing we saw from `ired-team`'s demonstration, 
the order of the functions are a little different but they both serve the same purpose and that's Injecting a DLL into a remote process.

---

On lines [`57-60`](https://github.com/bakkesmodorg/BakkesModInjectorCpp/blob/master/BakkesModInjectorC%2B%2B/DllInjector.cpp#L57)
after it has a valid handle to the process it locates the address of `LoadLibraryW` using `GetProcAddress`

> ![BM-3](/BM-3.png)

This is also done in `ired-team`'s demonstration here

```c
PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
```

Lines [`61-64`](https://github.com/bakkesmodorg/BakkesModInjectorCpp/blob/master/BakkesModInjectorC%2B%2B/DllInjector.cpp#L61) 
handle allocating memory for the library name string and writing that to the allocation. 

> ![BM-4](/BM-4.png)

[`65-77`](https://github.com/bakkesmodorg/BakkesModInjectorCpp/blob/master/BakkesModInjectorC%2B%2B/DllInjector.cpp#L65) is where `CreateRemoteThread` is called to start execution, after execution has started **BakkesMod** waits and then does some cleanup.

> ![BM-5](/BM-5.png)

looking at the [`CreateRemoteThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) 
and [`LoadLibraryW`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) 
documentation on msdn helps understand what's going on.

```c
HMODULE LoadLibraryW(
  [in] LPCWSTR lpLibFileName
);
```

`LoadLibraryW` takes in one parameter, a pointer to a widechar string
that is the name of a DLL to be loaded.

```c
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```

In our case `lpStartAddress` is the address of `LoadLibraryW` and `lpParameter` is `dereercomp` which 
is a pointer to the name of the DLL to be loaded. So a thread will be created and once it starts `LoadLibraryW`
will execute with whatever string is held at the memory of `dereercomp`.

---

> ## Gettin' dirty

With all this information idk about you but this makes me wan't to write my own DLL Injector, let's get to it.
First we'll start with finding the process ID of rocket league, this is a special number the OS uses to identify a process.
We need it to tell `OpenProcess` what process we wan't a handle to. 

Here's my code to find the process ID of rocket league.

```c
DWORD get_pid() {

    DWORD pid = 0;
    PROCESSENTRY32 proc_entry = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if ( Process32First(snapshot, &proc_entry) ) {
        do {
            if ( strcmp(proc_entry.szExeFile, "RocketLeague.exe") == 0 ) {
                pid = proc_entry.th32ProcessID;
                break;
            }
        } while ( Process32Next(snapshot, &proc_entry) );
    }

    return pid;
}
```

Once our process ID is found we can use `OpenProcess` to get a handle

```c
HANDLE rocket_league = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
```

Now that we have a handle to the process we can allocate some memory for our widechar string

```c
LPVOID allocated = VirtualAllocEx(rocket_league, NULL, path_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Next step is to write our DLL string to the allocated memory

```c
WriteProcessMemory(rocket_league, allocated, path, path_sz, NULL);
```

Last but not least get the address of `LoadLibraryW` using `GetProcAddress`

```c

LPVOID loadlib = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

```

and create a new thread inside rocket league pointing to `LoadLibraryW` with one parameter `allocated`

```c
HANDLE thread = CreateRemoteThread(rocket_league, NULL, NULL, (LPTHREAD_START_ROUTINE)loadlib, allocated, 0, NULL);
```

I almost forgot to mention the dll we will be loading here it is.. Just a simple MessageBoxA payload

```C
// loadme.c -> loadme.dll

#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {

        switch (reason) {

                case DLL_PROCESS_ATTACH:
                        MessageBoxA(NULL, "I was loaded", "I was loaded", MB_OK);
                        break;

                case DLL_THREAD_ATTACH:
                        break;

                case DLL_THREAD_DETACH:
                        break;

                case DLL_PROCESS_DETACH:
                        break;

        }

        return TRUE;
}
```

With all of this let's see how it looks under the hood.

---

> ## Debug time ( ͡° ͜ °)

When our injector is open inside of x64dbg we set a breakpoint on "OpenProcess"

> ![GH-6](/BM-6.png)

Once we hit that break point and return, set a break point on VirtualAllocEx

> ![BM-7](/BM-7.png)

Before we return out of VirtualAllocEx look at the RAX register that will be
the return value, This is the address of our allocation inside of Rocket league.

> ![BM-8](/BM-8.png)

> ![BM-9](/BM-9.png)

Now set a breakpoint on "WriteProcessMemory" execute that
and reread our memory region to see our payload

> ![BM-10](/BM-10.png)

> ![BM-11](/BM-11.png)

Same as before set a breakpoint on "CreateRemoteThread" but look at the arguments passed
and remember the function prototype.

> ![BM-12](/BM-12.png)

  1. Is the process handle to the rocket league
  2. the security attributes (NULL)
  3. stack size (NULL)
  4. lpStartAddress (address of LoadLibraryW)
  5. lpParameter (first parameter to ^)
  6. CreationFlags (0)
  7. ThreadId output (NULL)

Once this remote thread is created we see something nice

![BM-FINAL](/BM-FINAL.png)

---

> ## Remarks

This post was aimed towards beginners/people who know little about game hacking/game security and want to learn more.
I am so fascinated by the idea that malware and cheats share the same techniques and I will continue to try
and document the things I find to support that idea. Thank you for reading.

---

> ## References

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

https://pentestlab.blog/2017/04/04/dll-injection/

https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection#references

[BakkesMod - Github repo](https://github.com/bakkesmodorg)

[Their injector repo](https://github.com/bakkesmodorg/BakkesModInjectorCpp)