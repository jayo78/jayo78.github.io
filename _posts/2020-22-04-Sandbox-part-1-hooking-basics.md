---
layout: single
title: Sandbox part 1: hooking basics
date: 2020-22-04
classes: wide
---

In this 3 part series we will be building a simple userland sandbox by hooking Windows API functions. The sandbox will be able to inject itself into a process and then intercept and interpret calls to the Windows OS. This type of software is widely used to examine malicious programs dynamically and is designed to be run in a virtual machine. By building a sandbox we are able to learn and walk through some really cool windows memory hacking techniques seen in game cheats and malware. In this first part the goal is to understand what a sandbox is and how hooking works with examples.

#### Prerequisites and Resources

You will need to understand:

- [DLLs](https://support.microsoft.com/en-us/help/815065/what-is-a-dll), [Windows processes and threads](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads), [PE file format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- C/C++, basic x86, debugging

Resources I used:

- [dissecting inline hooks](http://www.binaryguard.com/bgc/malware/sandbox/2015/11/09/dissecting_inline_hooks.html)
- [x86 api hooking demystified](http://jbremer.org/x86-api-hooking-demystified/)
- [inline hooking for programmers](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html)

#### So what is a sandbox?

A sandbox is designed to examine the behavior of an executable and is largely used in Cybersecurity solutions for analyzing malware. There are a few open source projects like [Cuckoo](https://cuckoosandbox.org/). 

The idea is to run a program in a controlled environment to see what it attempts to do. A native executable will need to reach out to the host operating system in order to have any functionality. For example, it might need to manipulate a file using the I/O functions or use sockets to connect to remote servers. In order to intercept these calls to the operating system, a userland sandbox will need to sit in the middle of this communication.

We will be building a sandbox for Windows executables, which have the PE file [format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format). The Windows API (win32 API) allows for userland programs to interact with the Windows OS by providing functions in shared libraries called *Dynamically Linked Libraries*. The sandbox will need to monitor these functions.

![Sandbox](/assets/images/Sandbox.PNG)

Since every process essentially has their very own copy of Windows DLLs needed to execute, our sandbox will need to be injected into the executable's process that we want to examine. Once injected the sandbox can insert changes known as *hooks* into the imported DLL functions that will now be used by the executable. 

**How it works:**

1. Attach to a process, and inject our own DLL (Part 2)
2. Hook Windows API functions from within the injected process (Part 1, *you are here*)
3. Intercept and monitor API calls
4. profit???

I will cover injection in part 2 so stay tuned. First lets understand hooks.

#### The classic 5 byte hook

We will be hooking the [MessageBoxA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa) function by replacing its first 5 bytes with a `jmp` instruction to our own function. The MessageBoxA function simply displays a pop up text box with a title and dialog. By hooking it we will be able to intercept calls and alter the arguments.

 ![mbox_prolog]/assets/images/mbox_prolog.PNG)

Here I have disassembled `user32.dll` and found the function we would like to hook. The highlighted 5 bytes correspond to the assembly instructions directly to the right. This set of instructions is a fairly typical prologue found in many API functions.

By overwriting these first 5 bytes with a `jmp` instruction, we are redirecting execution to our own defined function. We will save the original bytes so that they can be referenced later when we want to pass execution back to the hooked function.

The `jmp` instruction is a relative jump to an offset starting from the next instruction's address. The corresponding `jmp` opcode is `E9` and it takes a 4 byte offset that we will need to calculate. 

 ![mbox_prolog](/assets/images/5bytehook.PNG)

Lets first get the address of MessageBoxA in memory.

```C++
// 1. get memory address of the MessageBoxA function from user32.dll 
hinstLib= LoadLibraryA(TEXT("user32.dll"));
function_address= GetProcAddress(hinstLib, "MessageBoxA");
```

We are using a technique called dynamic linking where we load the DLL that contains the function we want, using [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya). Then [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) will give us the address of the function in memory. We can now save the first 5 bytes at the address we found into a buffer using [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).

```c++
// 2. save the first 5 bytes into saved_buffer
ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);
```

Before we write our patch in, we need to calculate the offset (distance) from MessageBoxA to a proxy function that we will write in a sec. The `jmp <offset>` instruction will essentially move the instruction pointer (EIP) past the current instruction (5 bytes) and then add the offset: `eip = eip + 5 + offset`

Find the offset: `offset = <destination address> - (<source address> + 5)`

```c++
proxy_address= &proxy_function;
src= (DWORD)function_address + 5; 
dst= (DWORD)proxy_address;
relative_offset= (DWORD *)(dst-src);
```

Here is the complete implementation which then writes the patch to MessageBoxA in memory

```c++
void install_hook()
{
    HINSTANCE hinstLib;
    VOID *proxy_address;
    DWORD *relative_offset;
    DWORD src; 
    DWORD dst;
    CHAR patch[5]= {0};

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib= LoadLibraryA(TEXT("user32.dll"));
    function_address= GetProcAddress(hinstLib, "MessageBoxA");

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a call to proxy_function
    proxy_address= &proxy_function;
    src= (DWORD)function_address + 5; 
    dst= (DWORD)proxy_address;
    relative_offset= (DWORD *)(dst-src); 

    memcpy(patch, 1, "\xE9", 1);
	memcpy(patch + 1, 4, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)function_address, patch, 5, NULL);
}
```

**Quick note: WriteProcessMemory and ReadProcessMemory query the protections on the memory they are accessing and alter them accordingly. They really want you to succeed :)* 

The proxy function that we redirect execution to will need to accept the same parameters, have the same calling convention, and return the same type that MessageBoxA does.

```c++
// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
```

Now we can print out the parameters meant for MessageBoxA, alter them, and then continue to the real MessageBoxA. If we just call MessageBoxA we will run into the hook again causing infinite recursion and a stack overflow. To prevent this we will first replace the bytes we overwrote with the original ones that were previously saved into a buffer. 

```c++
// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Hello from MessageBox!\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << "\n";

    // unhook the function (re-write the saved buffer) to prevent infinite recursion
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hooked_address, saved_buffer, 5, NULL);

    // return to the original function and modify the intended parameters
    return MessageBoxA(NULL, "yeet", "yeet", uType);
}
```

This hook will only effect a call to MessageBoxA from within the same program. To tamper with another processes functions from imported DLLs would require injection, which will be covered in the next part. View this example on [github](https://github.com/jayo78/basic-hooking/blob/master/hook_v1.cpp).

Since the proxy function re-writes the original bytes, which unhooks the function, we would need to continually hook MessageBoxA to intercept subsequent calls. Lets talk trampolines. 

#### Trampolines

We can use a trampoline function to keep our hook intact while not causing infinite recursion. The trampoline's job is to execute the original bytes from function that we hooked and then jump past the installed hook. We can call it from the proxy function.

 ![mbox_prolog](/assets/images/trampoline.PNG)

By jumping 5 bytes past the original function's address we are not executing the relative `jmp` to the proxy function, by passing the installed hook. 

We are pushing the address of the hooked function + 5 and then using `ret` to jump to that address. These two instructions, which use a 4 byte address, total to 6 bytes. Our trampoline then will be 11 bytes. Lets build the trampoline by adding to the `install_hook()` function we already wrote.

```c++
void install_hook()
{
    HINSTANCE hinstLib;
    VOID *proxy_address;
    DWORD *relative_offset;
    DWORD *hook_address;
    DWORD src; 
    DWORD dst;
    CHAR patch[5]= {0};
    char saved_buffer[5]; // buffer to save the original bytes
    FARPROC function_address= NULL;

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib= LoadLibraryA(TEXT("user32.dll"));
    function_address= GetProcAddress(hinstLib, "MessageBoxA");

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    proxy_address= &proxy_function;
    src= (DWORD)function_address + 5; 
    dst= (DWORD)proxy_address;
    relative_offset= (DWORD *)(dst-src); 

    memcpy(patch, "\xE9", 1);
	memcpy(patch + 1, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)function_address, patch, 5, NULL);

    // 4. Build the trampoline
    trampoline_address= VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    hook_address= (DWORD *)((DWORD)function_address + 5);
    memcpy((BYTE *)trampoline_address, &saved_buffer, 5);
    memcpy((BYTE *)trampoline_address + 5, "\x68", 1);
    memcpy((BYTE *)trampoline_address + 6, &hook_address, 4);
    memcpy((BYTE *)trampoline_address + 10, "\xC3", 1);
}
```

We first call [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) to allocate 11 bytes of memory. We need to specify the protection of this memory location as executable, readable, and writable. This will allow us to edit the allocated bytes and then later execute them. After writing the trampoline to memory we can call it from the proxy function. Here is a function definition that we can call after assigning it to a memory location. It has the same parameters as MessageBoxA.

```c++
typedef 
int (WINAPI *defTrampolineFunc)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

```

Using the above definition, the proxy function can now call the previously allocated trampoline code.

```c++
// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "----------intercepted call to MessageBoxA----------\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << "\n";

    // pass to the trampoline with altered arguments which will then return to MessageBoxA
    defTrampolineFunc trampoline= (defTrampolineFunc)trampoline_address;
    return trampoline(hWnd, "yeet", "yeet", uType);
}
```

View the full example on [github](https://github.com/jayo78/basic-hooking/blob/master/hook_v2.cpp).

#### Conclusion

We covered a simple 5 byte - relative jump hook that should have given you a taste of what hooks are and how they can be useful. There are many ways to implement hooks, some more complicated than others. Please see [here](http://jbremer.org/x86-api-hooking-demystified/) for more hooking examples. 

The sandbox that were building will need to hook many functions. Since this can quickly get quite tedious due to the fact that each target function is different, we will need a hooking engine. A hooking engine will be able to hook any function given to it utilizing an internal disassembler - see [here](https://www.malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html). Its important to understand the fundamentals of implementing your own hooks, but for our sandbox we will be using a hooking library.

In the next part we will be going over process injection, where we will be hooking some simple malware to analyze what its doing. The code referenced in this post can be found [here](https://github.com/jayo78/basic-hooking). Thanks for reading! part 2 coming.