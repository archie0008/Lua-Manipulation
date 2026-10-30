#include "stdafx.h"
extern void _start(HMODULE module);
DWORD WINAPI start_thread(LPVOID module)
{
    _start(static_cast<HMODULE>(module));
    return 0;
}
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        HANDLE thread = CreateThread(nullptr, 0, start_thread, module, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
