#include <Windows.h>
#include <stdio.h>

// ======================================================================================================================================================

#define DEBUG_FILE				    L"C:\\DummyDebug.log"

// ======================================================================================================================================================

/*
@ dpapisrv.dll's exports
*/

#pragma comment(linker, "/export:InitializeLsaExtension=dpapisrv.dll.InitializeLsaExtension,@1")
#pragma comment(linker, "/export:QueryLsaInterface=dpapisrv.dll.QueryLsaInterface,@2")

// ======================================================================================================================================================

/*
@ Writes the debug log to a file.
*/

VOID LogToFileW(IN LPCWSTR szFmt, ...) {

    WCHAR       szInputBuffer[0xFF] = { 0 };
    PSTR        pArgs = NULL;
    HANDLE      hFile = INVALID_HANDLE_VALUE;
    DWORD       dwWrittenBytes = 0x00;

    va_start(pArgs, szFmt);
    vswprintf_s(szInputBuffer, _countof(szInputBuffer), szFmt, pArgs);
    va_end(pArgs);

    if ((hFile = CreateFileW(DEBUG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, szInputBuffer, (DWORD)(wcslen(szInputBuffer) * sizeof(WCHAR)), &dwWrittenBytes, NULL);
        CloseHandle(hFile);
    }
    else
    {
        OutputDebugStringW(szInputBuffer);
    }
}

// ======================================================================================================================================================

#define DBGPRINTF(fmt, ...) \
    LogToFileW((fmt), __VA_ARGS__)

// ======================================================================================================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved) {

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DBGPRINTF(L"\n\n--------------------------------------------------------------------------------------\n");
        DBGPRINTF(L"[*] Hello From Lsass.exe: %d\n", GetCurrentProcessId());
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

