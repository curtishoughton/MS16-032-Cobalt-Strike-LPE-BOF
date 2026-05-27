# MS16-032 Beacon Object File (BOF)

A Cobalt Strike Beacon Object File (BOF) implementation of the MS16-032 local privilege escalation exploit (CVE-2016-0099) with direct beacon injection.

## Overview

MS16-032 exploits a race condition in the Windows Secondary Logon Service (`seclogon`) to obtain a SYSTEM token and inject a new beacon.

## Vulnerable Systems

- Windows 7 (all versions)
- Windows 8 / 8.1 (all versions)
- Windows 10 (pre-patch)
- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2

**Note:** Systems must be unpatched (before KB3139914, March 2016). Requires 2+ logical processors.

## Features

- Pure BOF implementation (no CRT dependencies)
- Correct MS16-032 race condition exploitation
- Direct beacon injection via Early Bird APC (no `CreateRemoteThread`)
- RW->RX memory protection (no RWX allocations)
- Clean thread shutdown via interlocked flags (no `TerminateThread`)
- Full token validation (type, SID, integrity level)
- Dual process creation fallback (`CreateProcessWithTokenW` / impersonation)
- CPU count pre-flight check
- Retry loop with configurable attempts

## Installation

### Prerequisites

- Cobalt Strike 4.0+
- MinGW-w64 cross-compiler

### Compilation

```bash
# Build both architectures
make

# Or build individually
make x64
make x86
```

Or compile manually (the `-o` flag sets the correct output filename):

```bash
x86_64-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x64.o -masm=intel
i686-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x86.o -masm=intel
```

**Important:** The output files must be named `ms16032_inject.x64.o` / `ms16032_inject.x86.o` and placed in the same directory as `ms16032_inject.cna`.

### Loading into Cobalt Strike

1. Place compiled `.o` files alongside `ms16032_inject.cna` and `beacon.h`
2. In Cobalt Strike: `Script Manager` -> `Load` -> select `ms16032_inject.cna`

## Usage

```
beacon> ms16032_inject <listener>
```

Automatically escalates to SYSTEM and injects a new beacon for the specified listener.

## How It Works

### The Vulnerability (CVE-2016-0099)

The Windows Secondary Logon Service (`seclogon`) runs as SYSTEM and processes `CreateProcessWithLogonW` requests from client processes. When it handles a request, it opens the client process's token to create the new process. A race condition exists: when multiple threads call `CreateProcessWithLogonW` simultaneously, the service can confuse which client it's servicing and assign its own **SYSTEM token** as the primary token of the child process.

### Exploitation Process

1. **Pre-flight checks**: Verifies 2+ logical CPUs are present (required for the race)
2. **Race condition**: 10 threads simultaneously spam `CreateProcessWithLogonW` with dummy credentials and `CREATE_SUSPENDED`
3. **Token inspection**: Each thread opens the suspended child process's token via `OpenProcessToken` and checks if it's SYSTEM (SID `S-1-5-18`)
4. **Token validation**: Validates the token is a primary token with system-level integrity
5. **Token capture**: On success, duplicates the SYSTEM token for use

### Injection Process

1. **Process creation**: Spawns `dllhost.exe` as SYSTEM using the captured token (via `CreateProcessWithTokenW` or impersonation fallback)
2. **Memory allocation**: Allocates RW memory in the target process
3. **Shellcode write**: Writes beacon shellcode to the allocated memory
4. **Memory protection**: Flips memory from RW to RX (no RWX)
5. **APC injection**: Queues a user APC on the suspended thread — executes before the entry point
6. **Execution**: Resumes the thread, APC fires, beacon starts

## OPSEC Considerations

### Pros
- No files written to disk
- No RWX memory allocations (RW->RX)
- No `CreateRemoteThread` (uses APC injection)
- `CREATE_NO_WINDOW` flag on all spawned processes
- BOF runs in-process (no fork & run)
- Clean thread shutdown via interlocked flags

### Cons
- Creates suspended `cmd.exe` processes during the race (process creation events)
- `OpenProcessToken` calls on child processes
- Process injection into `dllhost.exe`
- Multiple rapid `CreateProcessWithLogonW` calls (seclogon activity)

### Detection Vectors

- Sysmon Event ID 1: Multiple suspended `cmd.exe` processes in rapid succession
- Sysmon Event ID 10: `OpenProcessToken` on child processes
- Sysmon Event ID 1: `dllhost.exe` spawned by an unusual parent
- ETW: Rapid `CreateProcessWithLogonW` calls to seclogon

### Evasion Improvements

You can modify the injection target in `ms16032_inject.c`:

```c
// Default
wchar_t target[] = L"C:\\Windows\\System32\\dllhost.exe";

// Alternatives:
// wchar_t target[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
// wchar_t target[] = L"C:\\Windows\\System32\\svchost.exe";
```

## Troubleshooting

### "Requires 2+ logical CPUs"

The race condition only works on multi-processor systems. Single-CPU VMs will always fail.

### No SYSTEM token after all attempts

- **System is patched**: Check with `systeminfo` for KB3139914
- **Race didn't trigger**: Run again — race conditions are probabilistic
- **seclogon not running**: The Secondary Logon service must be running (`sc query seclogon`)

### Beacon doesn't call back

- Verify listener is configured correctly
- Check firewall rules from SYSTEM context
- Try SMB or TCP listener
- Ensure architecture matches (x64 vs x86)

### "Cannot spawn SYSTEM process"

- Need `SeImpersonatePrivilege` — standard for administrator/service contexts
- If both creation methods fail, try from a different user context

## Credits

- **Original Research**: James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) — Project Zero
- **Original PoC**: FuzzySecurity — [Invoke-MS16-032.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)
- **CVE**: CVE-2016-0099

## References

- [Microsoft Security Bulletin MS16-032](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)
- [CVE-2016-0099](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0099)

## Legal Disclaimer

This tool is provided for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
