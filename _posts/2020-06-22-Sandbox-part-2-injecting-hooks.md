---
layout: single
title: Sandbox part 2 - injecting hooking
date: 2020-06-22
classes: wide
---

In part 2 of building a userland sandbox I will be walking through injecting hooks into a remote process in order to intercept a target executable's calls to the Windows API. Refer to [part 1](https://jayo78.github.io/Sandbox-part-1-hooking-basics/) for a more in-depth explanation of a sandbox. In this part we will see a more complete example of sandbox functionality using process injection. We will first be implementing a simple injector using the CreateRemoteThread + LoadLibrary DLL injection technique which has been thoroughly covered online and used for years. The hooks we created in part 1 will now be used to hook a remote processes calls. Then in Part 3 we finish up by setting up inter-process communication in order to extract the information that our injected hooks intercept from the target program's running process. 

I will focus my attention on the actual implementation of injecting and installing hooks. There are extensive recourses out there that do a better job than I would at explaining topics like processes, threads, OS internals, etc. I used many resources that I'll share and I encourage the reader to extend your own research beyond this article where you find gaps in knowledge. Lets get into it!

#### Process injection

Processes are more than simply executing a program. There is a lot of behind the scenes work done by the Windows OS in terms of the security of a program, communication with other processes, and access to shared recourses. The birth of a process involves the mapping of a program's memory on disk to virtual memory where it can begin executing. Windows separates address spaces using virtualization so they don't bump into each other's memory and so it can easily interface with each one individually - read [here](https://answers.microsoft.com/en-us/windows/forum/windows_10-performance/physical-and-virtual-memory-in-windows-10/e36fb5bc-9ac8-49af-951c-e7d39b979938?auth=1). 

Knowing this OS functionality we can now begin looking at ways a process can access another processes memory using functions provided by the Windows API. I highly recommend checking out this [post](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process) on common process injection techniques. There are more in depth articles out there outlining many injection methods - see [here](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf) - but for our sandbox we will be using [DLL injection](http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html). 

There are a few flavors of DLL injection. We first need to open the executable we would like to examine, using [CreateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa). This function lets us create a process as suspended, which will now let us inject and install hooks before resuming the main thread. We can utilize [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) and [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) to load our hooking DLL into the process. 

