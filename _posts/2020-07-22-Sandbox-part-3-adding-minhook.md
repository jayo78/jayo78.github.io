---
layout: single
title: Sandbox part 3 - adding minhook 
date: 2020-07-22
classes: wide
---

Part 3 is the final chapter in our journey into sandbox development. In this part we will first deal with implementing the open-source hooking library, [minhook](https://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra), as our hooking engine to ensure more reliable and efficient hooks. Then we will add a mini logger class to conveniently log all the information we receive to a file. Our development in this part will be focused on the DLL that will be injected, which will now be called the monitor. The monitor will contain both our hooking engine and logger to handle API interception and reporting respectively.

#### How does minhook work?

*The source code is publicly available and very easy to read so check that out if this explanation doesn't suffice.*

[minhook](https://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra) is a light weight hooking engine which employs the same relative jump, inline hooking technique we covered in part 1 and 2. It is capable of hooking a wide variety of functions. Creating our own hooking engine would be a whole project itself due to the fact that Windows API function prologues can differ, making hooking certain functions difficult. We are using minhook to avoid the annoyances of detecting the different prologues and then adjusting our hooking technique or placement accordingly. Much like how we disassembled MessageBoxA in order to overwrite its first couple of bytes in part 1, minhook uses an internal disassembler to analyze each function and decide where to hook it. This is whats meant by "hooking engine."

The only 3 functions we will be using from the library are `MH_Initialize`, `MH_CreateHookAPI`, and `MH_EnableHook`. These are powerful functions which abstract away the hooking process. `MH_Initialize` is simply called before hooking anything in order to initialize heap space for storing [trampoline functions](http://jbremer.org/x86-api-hooking-demystified/#ah-trampoline). `MH_CreateHookAPI` does all the heavy lifting to install a hook that we specify, lets look at its definition:

```c
MH_STATUS WINAPI MH_CreateHookApi(
        LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal);
```

It takes the module name (DLL) that exports the function we want to hook, the actual function/procedure name, the proxy function (detour) address, and a function pointer which will eventually contain the address of the trampoline. This is information we used in part 1 and 2 when installing our own hooks. `MH_CreateHookAPI` first analyzes the function given to it in order to see where the hook should be placed. It then sets up a trampoline function internally within heap space that was previously allocated. The function pointer (ppOriginal) will now be populated with the trampoline address. `MH_EnableHook` patches the location found for the hook with a familiar relative jump to the proxy function.

#### Implementing minhook

Since we are using `MH_CreateHookAPI` as previously explained and want to hook a bunch of functions it makes sense to define a general structure to hold all the information we need to pass to this function. 

```c
struct HOOK_INFO {
    LPCWSTR lib;
    LPCSTR target;
    LPVOID proxy;
    LPVOID fp;
};
```

Lets look at hooking `GetProcAddress` as an example of the values that would go into this struct. 

```c
{
	L"kernel32", 
	"GetProcAddress",
	&ProxyGetProcAddress,
	&fpGetProcAddress
}
```

The first two parameters are just the library containing the function and then the actual function. `MH_CreateHookAPI` handles loading and finding the function from these strings. The next two parameters are pointers to our proxy function and a function that will get populated by minhook with a trampoline to the original API function (past our hook). Lets look at what these look like:

```c
FARPROC WINAPI ProxyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    wchar_t wProcName[128];
    MultiByteToWideChar(CP_THREAD_ACP, (DWORD)0, lpProcName, -1, wProcName, 128);
    logger << L"[HOOK] Intercepted call to GetProcAddress:\n" << L"- Function Name: " << 		wProcName << std::endl;
    return fpGetProcAddress(hModule, lpProcName);
}

typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
GETPROCADDRESS fpGetProcAddress= NULL;
```

*we will go over the logger class, but this proxy is just converting the lpProcName argument to Unicode and then reporting it to the logger object through a stream*

Okay now that we have a general structure we can create an array of HOOK_INFO structs and loop through them to hook as many functions as we would like.

```c
HOOK_INFO hooks[]= {
    {
        L"kernel32", 
        "GetProcAddress",
        &ProxyGetProcAddress,
        &fpGetProcAddress
    },
    
    ... more hooks ...
};

__forceinline BOOL install_hook(HOOK_INFO *pHookInfo)
{
    if (MH_CreateHookApi(pHookInfo->lib, pHookInfo->target, pHookInfo->proxy, (LPVOID *)			(pHookInfo->fp)) != MH_OK)
        return FALSE;

    return TRUE;
}

VOID install_all()
{
    int numElts= sizeof(hooks)/sizeof(hooks[0]);

    for (int i= 0; i < numElts; i++)
    {
        if (install_hook(&hooks[i]))
            logger << L"[+] Installed hook in: " << hooks[i].target << "\n";
    }
}
```

All of the above code is contained in the monitor DLL and ready to be injected. Here is the DLL entry, which first initializes minhook, installs the hooks, and then enables the hooks.

```c
BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)  
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            logger << L"[+] Installing hooks...\n";

            MH_Initialize();
            install_all();
            MH_EnableHook(MH_ALL_HOOKS);

            logger << L"[+] Hooks installed, Resuming main thread..." << std::endl;
            break;
    }

    return TRUE;  
}
```

In the injector we wait for the remote thread to load and execute the monitor. At that point we can resume the process with our hooks intact.

#### Logger

The logger I wrote simply overrides the `<<` operator when applied to a logger object. The override sends strings to an internal stream that gets flushed to a log file whenever it sees `std::endl`. 

```c
// override the << operator to redirect values to our internal stream
    template <typename T> 
    Logger& operator <<(T const& value) 
    {   
        stream << value;
        return *this;
    }

// override the << operator to detect the std::endl stream manipulation
    Logger& operator<<(ManipFn manip)
    { 
        if (manip == static_cast<ManipFn>(std::endl))
            this->write_log();

        return *this;
    }
```

We must override the `<<` operator twice, once for string values an another for stream manipulations. Have a look at [this](https://stackoverflow.com/questions/511768/how-to-use-my-logging-class-like-a-std-c-stream) stack overflow thread, I used modified versions of the code suggested here. When a manipulation is passed we check to see if its `std::endl`. If it is we write the current contents of the stream to a file that was previously opened in the class constructor. The full code can be found on [github](https://github.com/jayo78/win-api-monitor/blob/master/Monitor/logger.h).

#### Conclusion

This 3rd part in the mini series concludes our simple API monitor/sandbox build. Cool right?! It can certainly be expanded to include many more hooks, the version on my github only contains a few I consider useful. 

This is a very basic sandbox implemented in userland, so it does have its limitations. It would be trivial for a developer to subvert our hooks by either detecting them or using native api calls that bypass higher level functions (we could hook these). Even professional sandboxes out there like croudstrike's falcon sandbox or cuckoo's open source sandbox don't fully prevent evasion by malicious programs and they run in kernel mode. Sandbox evasion, empolyed by malicious actors, and then subsequent, evasion detection, implemented by sandbox vendors are really interesting topics that highlight the constant arms race experienced in all facets of cybersecurity.

Thanks for reading, I like to write about these ventures so I gain a better grasp on the subjects I'm learning. Hopefully it helped you too, or maybe even inspired you to do something dope.

 