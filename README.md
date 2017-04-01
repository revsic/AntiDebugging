# Anti Debugging

Anti debugging technique written in C++ language.

- Anti Attach, Anti Anti Attach : [AntiAttach.cpp](https://github.com/revsic/AntiDebugging/blob/master/AntiAttach.cpp), [AntiAntiAttaching.cpp](https://github.com/revsic/AntiDebugging/blob/master/AntiAntiAttach.cpp)
- Text Section Hashing : [TextSectionHasher.cpp](https://github.com/revsic/AntiDebugging/blob/master/TextSectionHasher.cpp)
- VEH Checker, DR Register Resetter : [VEH_Checker.cpp](https://github.com/revsic/AntiDebugging/blob/master/VEH_Checker.cpp), [DR_Register_Resetter.cpp](https://github.com/revsic/AntiDebugging/blob/master/DR_Register_Resetter.cpp)

## Anti Attach, Anti Anti Attach

Debugger attach process with DebugActiveProcess win32api.

```cpp
DebugActiveProcess(pid);

DEBUG_EVENT dbgEvent;
BOOL dbgContinue = True;

while (dbgContinue) {
    if (FALSE == WaitForDebugEvent(&dbgEvent, 100)) {
        continue;
    }

    ...
}
```

DebugActiveProcess create Thread in debuggee process and call `DbgUiRemoteBreakin()`.

```cpp
//AntiAttach
__declspec(naked) void AntiAttach() {
    __asm {
		jmp ExitProcess
	}
}

//main
HANDLE hProcess = GetCurrentProcess();

HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
FARPROC func_DbgUiRemoteBreakin = GetProcAddress(hMod, "DbgUiRemoteBreakin");

WriteProcessMemory(hProcess, func_DbgUiRemoteBreakin, AntiAttach, 6, NULL);
```

Anti Attacher hooks `DbgUiRemoteBreakin` and redirects `DbgUiRemoteBreakin` to `ExitProcess` when the function is called. Anti Anti Attacher releases the hooked `DbgUiRemoteBreakin` function.

More details on [blog](http://revsic.tistory.com/31)

## Text Section Hashing

Debugger sets software break point by overwriting the `int 3` instruction `\xCC` in the text section.

Hashing Text section and periodically check that the text section has changed.

```cpp
while (1) {
	Sleep(1000);

	DWORD64 dwCurrentHash = HashSection(lpVirtualAddress, dwSizeOfRawData);
	if (dwRealHash != dwCurrentHash) {
		MessageBoxW(NULL, L"DebugAttached", L"WARN", MB_OK);
		exit(1);
	}

	if (bTerminateThread) {
		return;
	}
}
```

## VEH Checker, DR Register Resetter

VEH Debugger use Vectored Exception Handler. Verify that VEH is set. Check the `fourth bit (ProcessUsingVEH)` of the `PEB`'s `CrossProcessFlags(+0x50)`. If ProcessUsingVEH bit is set, then VEH is being used.

```cpp
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);
PPEB pPEB = (PPEB)pbi.PebBaseAddress;

SIZE_T Written;
DWORD64 CrossProcessFlags = -1;
ReadProcessMemory(hProcess, (PBYTE)pPEB + 0x50, (LPVOID)&CrossProcessFlags, sizeof(DWORD64), &Written);

printf("[*] CrossProcessFlags : %p\n", CrossProcessFlags);
if (CrossProcessFlags & 0x4) {
	printf("[*] veh set\n");
}
else {
	printf("[*] veh unset\n");
}
```

VEH Debugger usually uses Hardware Break Point. Verify that Hardware BP is set

```cpp
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

CONTEXT ctx;
memset(&ctx, 0, sizeof(CONTEXT));
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

ctx.Dr0 = 0;
ctx.Dr1 = 0;
ctx.Dr2 = 0;
ctx.Dr3 = 0;
ctx.Dr7 &= (0xffffffffffffffff ^ (0x1 | 0x4 | 0x10 | 0x40));

SetThreadContext(hThread, &ctx);
CloseHandle(hThread);
```
