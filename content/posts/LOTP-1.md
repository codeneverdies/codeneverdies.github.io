+++
title = "1. Land Of The PEB - Modules and DLLs"
date = 2025-03-26T00:09:18-04:00
draft = false
author = "codeneverdies"
+++

Welcome to my first series called "Land Of The PEB" where I will be discussing various topics
related to the [Process Environment Block](https://en.wikipedia.org/wiki/Process_Environment_Block) (PEB).

### What is this thing?

The Process Environment Block (we will refer to as PEB) is a data structure in the [Windows NT](https://en.wikipedia.org/wiki/Windows_NT) 
operating system that holds lots of useful information about the current process like..

+ Debug Flags
+ Process start command line arguments
+ Pointer to the process's heap
+ The base address of the current process.
+ List of loaded modules (DLLs)

### How can I use it?

In this post we will be focusing on the member that relates to loaded modules i.e, **PEB_LDR_DATA**
and we will be using this structure to write our own version of **GetModuleHandle**. To accomplish this
we must do the following..

+ Get a pointer to the PEB
+ Get a pointer to **PEB_LDR_DATA**
+ Get a pointer to the **InMemoryOrderModuleList**

Once we get to this list in memory we can loop through this list and compare each module name with
the one we want for example we will do "ntdll.dll" this could be useful if you don't want **GetModuleHandle**
in your Import Address Table.

### To the land of the PEB!

It must be known that the PEB is actually located inside of the Thread Environment Block (TEB) at offset `0x60` on 64-bit systems
and `0x30` on 32-bit systems. There are two ways I know of getting a pointer to the PEB they both access the TEB located in the `gs` 
segment register. The first is very useful if you don't wan't to write assembly.

```c
//64-bit systems
PPEB peb = (PPEB)__readgsqword(0x60);
```

These are intrinsic functions that do something close to this.. [^3]

```asm
    push rdi
    mov rdi, rsp
    sub rsp, 0x20
        
    xor rax, rax
    mov rax, gs:[0x60]

    mov rsp, rdi
    pop rdi
    ret
```

Now that we have a pointer to the PEB lets look for our module, we can start with
getting a pointer to **PPEB_LDR_DATA** [^1]

```c
PPEB_LDR_DATA ldr = peb->Ldr;
```

Once we have both of those pointers we can get our last needed pointer which is to the
InMemoryOrderModuleList. This points to the first entry in the list, each entry is of type LIST_ENTRY
which means each entry has a forward link pointing to the next module in the list. For each entry
we will compare it's name with "ntdll.dll" if the names match we have found ntdll.dll and we grab the base
address. [^2]

```c

entry = &ldr->InMemoryOrderModuleList;
next_entry = entry->Flink;

for ( LIST_ENTRY *e = next_entry; e != entry; e = e->Flink ) {

    data_tbl = (LDR_DATA_TABLE_ENTRY *)((BYTE *)e - sizeof(LIST_ENTRY));

    if ( wcscmp(data_tbl->BaseDllName.pBuffer, "ntdll.dll") == 0 ) {
        mod = (HMODULE)(data_tbl->DllBase);
        break;
    }
}
```

[^1]: https://github.com/codeneverdies/ws-loader/blob/main/src/util.c#L48
[^2]: https://github.com/codeneverdies/ws-loader/blob/main/src/util.c#L50
[^3]: https://github.com/codeneverdies/ws-loader/blob/main/asm/init.asm#L23