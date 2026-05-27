# MS16-032 Beacon Object File (BOF)

A Cobalt Strike BOF implementing the MS16-032 local privilege escalation exploit (CVE-2016-0099) with direct beacon injection via Early Bird APC.

## Overview

MS16-032 exploits a race condition in the Windows Secondary Logon Service (`seclogon`) to leak a SYSTEM token handle into the calling process. The BOF then uses that token to spawn a sacrificial process as SYSTEM and injects beacon shellcode via APC — no files touch disk.

## Vulnerable Systems

- Windows 7 (all editions)
- Windows 8 / 8.1 (all editions)
- Windows 10 (pre-patch)
- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2

Systems must be **unpatched** (before KB3139914, March 2016).

## Features

- Pure BOF implementation (no CRT dependencies)
- Correct exploit chain: baseline/diff handle snapshots to detect leaked SYSTEM tokens
- Dynamic token object type index resolution (works across all Windows builds)
- Event-based clean thread shutdown (no `TerminateThread`)
- Full token validation: type, SID, integrity level
- RW -> RX memory protection (no RWX allocations)
- Early Bird APC injection (no `CreateRemoteThread`)
- CPU count pre-flight check (requires 2+ logical processors)
- Retry loop with configurable attempts
- Dual process creation fallback (`CreateProcessWithTokenW` / `CreateProcessAsUserW`)
- Supports both x86 and x64 architectures (WOW64-safe)

## Requirements

- Cobalt Strike 4.0+
- MinGW-w64 cross-compiler (or Visual Studio with appropriate flags)
- `SeImpersonatePrivilege` on the beacon process (service accounts, administrators)

## Compilation

```bash
# x64
x86_64-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x64.o -Wall

# x86
i686-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x86.o -Wall
```

## Installation

1. Place compiled `.o` files, the `.cna` script, and `beacon.h` in the same directory.
2. In Cobalt Strike: **Script Manager** > **Load** > select `ms16032_inject.cna`.

## Usage

```
beacon> ms16032_inject <listener>
```

Example:

```
beacon> ms16032_inject smb_listener
[*] MS16-032 LPE | CPUs: 4 | Shellcode: 265813 bytes
[*] Token type index: 5
[*] Attempt 1/10
[*] Baseline: 12 token handles — racing...
[+] SYSTEM token acquired!
[*] Injecting beacon...
[+] Sacrificial process PID 4812
[+] Beacon injected via APC
[+] Exploit complete — beacon should check in shortly
```

## How It Works

### Exploitation

1. **Pre-flight check**: Verifies 2+ logical processors are available (required for the race).
2. **Type index resolution**: Opens our own process token and queries the system handle table to learn the kernel's `ObjectTypeIndex` for Token objects on this specific build — avoids hardcoded values that vary across Windows versions.
3. **Baseline snapshot**: Records all token handles currently in the Beacon process.
4. **Race condition**: Spawns 10 threads that spam `CreateProcessWithLogonW` with dummy credentials. The race condition in `seclogon.dll` can cause it to leak a SYSTEM token handle back into the calling process.
5. **Diff snapshot**: Queries token handles again and identifies any **new** handles that appeared during the race.
6. **Token validation**: Each new token handle is checked for: primary type, S-1-5-18 (SYSTEM) SID, and system-level integrity. Unusable tokens are discarded.
7. **Clean shutdown**: Race threads are stopped via a manual-reset event and joined with `WaitForMultipleObjects` — no `TerminateThread`.
8. **Retry**: If no SYSTEM token is found, the cycle repeats (up to 10 attempts). Race conditions are probabilistic.

### Injection (Early Bird APC)

1. **Privilege enable**: Best-effort enable of `SeImpersonatePrivilege` on the Beacon's own token (useful for service accounts where the privilege exists but is disabled).
2. **Process creation**: Spawns `dllhost.exe` as SYSTEM in a suspended state. Tries `CreateProcessWithTokenW` first, falls back to impersonation + `CreateProcessAsUserW`.
3. **Memory allocation**: Allocates `PAGE_READWRITE` memory in the target process.
4. **Shellcode write**: Writes beacon shellcode to the allocated region.
5. **Protection flip**: Changes memory to `PAGE_EXECUTE_READ` via `VirtualProtectEx`.
6. **APC queue**: Queues a user APC pointing to the shellcode on the suspended main thread.
7. **Resume**: Resumes the thread. The APC fires during `NtTestAlert` in `LdrInitializeThunk`, before the process entry point — the beacon starts executing as SYSTEM.

## OPSEC Considerations

### Strengths

- No files written to disk
- No `CreateRemoteThread` (uses APC injection instead)
- No RWX memory allocations (RW -> RX)
- `CREATE_NO_WINDOW` flag on all spawned processes
- Uses legitimate Windows process (`dllhost.exe`) as injection target
- BOF format — runs inline in Beacon, minimal footprint
- Clean thread lifecycle — no `TerminateThread`, no leaked state

### Weaknesses

- Multiple suspended `cmd.exe` processes created/terminated during the race (Sysmon Event ID 1)
- Token handle enumeration via `NtQuerySystemInformation` (Sysmon Event ID 10)
- APC injection into `dllhost.exe` (behavioral detection)
- Rapid process creation/termination pattern is anomalous

### Detection Vectors

| Source | Event | What It Catches |
|--------|-------|-----------------|
| Sysmon | Event ID 1 | Burst of suspended `cmd.exe` creation/termination |
| Sysmon | Event ID 10 | `NtQuerySystemInformation` handle enumeration |
| EDR | Behavioral | Rapid process creation + token manipulation |
| EDR | Memory | RW->RX transition in remote process |

### Tuning the Injection Target

You can change the sacrificial process in `ms16032_inject.c` (the `target` variable in `InjectBeacon`):

```c
// Default
wchar_t target[] = L"C:\\Windows\\System32\\dllhost.exe";

// Alternatives:
// wchar_t target[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
// wchar_t target[] = L"C:\\Windows\\System32\\svchost.exe";
```

## Troubleshooting

### "Exploit requires 2+ logical CPUs"

The race condition cannot be won on a single-CPU system. Verify with `systeminfo` or check `NUMBER_OF_PROCESSORS`.

### "No SYSTEM token after 10 attempts"

- **System is patched** — check for KB3139914 with `wmic qfe`.
- **Race didn't trigger** — probabilistic; try running again.
- **Secondary Logon service not running** — verify with `sc query seclogon`.

### "Cannot spawn SYSTEM process (need SeImpersonatePrivilege)"

The Beacon process lacks `SeImpersonatePrivilege`. This exploit works best from:
- IIS application pool identities
- SQL Server service accounts
- Other service accounts with `SeImpersonatePrivilege`
- Administrator contexts (elevated)

Run `whoami /priv` to check available privileges.

### Beacon doesn't call back

- Verify listener configuration matches the architecture (x86 vs x64).
- Check firewall rules — SYSTEM context may have different network access.
- Try SMB or TCP listeners if HTTP/HTTPS fails from SYSTEM.

## Credits

- **Original Research**: James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) — Project Zero
- **PowerShell PoC**: FuzzySecurity
- **CVE**: CVE-2016-0099

## References

- [Microsoft Security Bulletin MS16-032](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)
- [CVE-2016-0099](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0099)
- [FuzzySecurity Invoke-MS16-032](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)

## Legal Disclaimer

This tool is provided for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
