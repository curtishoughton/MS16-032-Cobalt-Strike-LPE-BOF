# MS16-032 Beacon Object File (BOF)

A Cobalt Strike Beacon Object File (BOF) implementation of the MS16-032 local privilege escalation exploit with direct beacon injection capabilities.

## Overview

MS16-032 exploits a race condition in the Windows Secondary Logon Service to obtain a SYSTEM token:

 **ms16032_inject** - Automatically inject a new Cobalt Strike beacon running as SYSTEM (recommended)

## Vulnerable Systems

- Windows 7 (all versions)
- Windows 8 / 8.1 (all versions)
- Windows 10 (pre-patch)
- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2

**Note:** Systems must be unpatched (before MS16-032 patch from March 2016).

## Features

- ✅ Pure BOF implementation (no CRT dependencies)
- ✅ Direct beacon injection (no files touch disk)
- ✅ Minimal OPSEC footprint
- ✅ Supports both x86 and x64 architectures
- ✅ Uses legitimate Windows processes for injection
- ✅ Automatic shellcode generation

## Installation

### Prerequisites

- Cobalt Strike 4.0+
- MinGW-w64 cross-compiler

### Compilation

```bash
# Compile x64 version
x86_64-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x64.o -masm=intel

# Compile x86 version
i686-w64-mingw32-gcc -c ms16032_inject.c -o ms16032_inject.x86.o -masm=intel
```

### Loading into Cobalt Strike

1. Place all files in the same directory:
   - `ms16032_inject.x64.o` / `ms16032_inject.x86.o`
   - `ms16032_inject.cna` (or combined script)
   - `beacon.h`

2. Load the Aggressor script:
   - Open Cobalt Strike
   - Go to `Script Manager`
   - Click `Load`
   - Select `ms16032_inject.cna` (or both scripts)

## Usage

### Method 1: Direct Beacon Injection (Recommended)

Automatically spawns a new SYSTEM beacon without touching disk:


## How It Works

### Exploitation Process

1. **Race Condition Setup**: Creates multiple threads that spam `CreateProcessWithLogonW()` with dummy credentials
2. **Token Leak**: Exploits the race condition to leak a SYSTEM token handle
3. **Token Discovery**: Enumerates process handles to find the leaked SYSTEM token
4. **Privilege Escalation**: Uses the SYSTEM token to spawn a new process with elevated privileges

### Injection Process (ms16032_inject)

1. **Shellcode Generation**: Automatically generates beacon shellcode for the specified listener
2. **Process Creation**: Spawns dllhost.exe` as SYSTEM in suspended state
3. **Memory Allocation**: Allocates RWX memory in the target process
4. **Shellcode Injection**: Writes beacon shellcode to allocated memory
5. **Execution**: Creates remote thread to execute the shellcode

## OPSEC Considerations

### Pros
- ✅ No files written to disk (inject variant)
- ✅ Uses `CREATE_NO_WINDOW` flag (minimal visibility)
- ✅ Spawns legitimate Windows processes
- ✅ BOF format minimizes suspicious API calls
- ✅ All output through Cobalt Strike channels

### Cons
- ⚠️ Creates multiple suspended processes during race condition (process creation logs)
- ⚠️ Token handle enumeration may trigger security tools
- ⚠️ Remote thread creation in notepad.exe (inject variant)
- ⚠️ RWX memory allocation (consider using RW->RX if needed)

### Detection Vectors

- Sysmon Event ID 1 (Process Creation) - Multiple suspended cmd.exe processes
- Sysmon Event ID 8 (CreateRemoteThread) - Injection into notepad.exe
- Sysmon Event ID 10 (ProcessAccess) - Token handle enumeration
- EDR behavioral detection - Rapid process creation/termination patterns

### Evasion Improvements

You can modify the injection target in `ms16032_inject.c` (line 233):

```c
// Current default
wchar_t target[] = L"C:\\Windows\\System32\\dllhost.exe";

// Alternative options:
// wchar_t target[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
// wchar_t target[] = L"C:\\Windows\\System32\\svchost.exe";
```
## How It Works

### Exploitation Process

1. **Race Condition Setup**: Creates multiple threads that spam `CreateProcessWithLogonW()` with dummy credentials
2. **Token Leak**: Exploits the race condition to leak a SYSTEM token handle
3. **Token Discovery**: Enumerates process handles to find the leaked SYSTEM token
4. **Privilege Escalation**: Uses the SYSTEM token to spawn a new process with elevated privileges

### Injection Process (ms16032_inject)

1. **Shellcode Generation**: Automatically generates beacon shellcode for the specified listener
2. **Process Creation**: Spawns `notepad.exe` as SYSTEM in suspended state
3. **Memory Allocation**: Allocates RWX memory in the target process
4. **Shellcode Injection**: Writes beacon shellcode to allocated memory
5. **Execution**: Creates remote thread to execute the shellcode

## OPSEC Considerations

### Pros
- ✅ No files written to disk (inject variant)
- ✅ Uses `CREATE_NO_WINDOW` flag (minimal visibility)
- ✅ Spawns legitimate Windows processes
- ✅ BOF format minimizes suspicious API calls
- ✅ All output through Cobalt Strike channels

### Cons
- ⚠️ Creates multiple suspended processes during race condition (process creation logs)
- ⚠️ Token handle enumeration may trigger security tools
- ⚠️ Remote thread creation in notepad.exe (inject variant)
- ⚠️ RWX memory allocation (consider using RW->RX if needed)

### Detection Vectors

- Sysmon Event ID 1 (Process Creation) - Multiple suspended cmd.exe processes
- Sysmon Event ID 8 (CreateRemoteThread) - Injection into notepad.exe
- Sysmon Event ID 10 (ProcessAccess) - Token handle enumeration
- EDR behavioral detection - Rapid process creation/termination patterns

### Evasion Improvements

You can modify the injection target in `ms16032_inject.c` (line 233):

```c
// Current default
wchar_t target[] = L"C:\\Windows\\System32\\notepad.exe";

// Alternative options:
// wchar_t target[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
// wchar_t target[] = L"C:\\Windows\\System32\\dllhost.exe";
// wchar_t target[] = L"C:\\Windows\\System32\\svchost.exe";
```

## Troubleshooting

### "Failed to find SYSTEM token"

**Possible causes:**
- System is patched against MS16-032
- Race condition failed to trigger
- Insufficient privileges to enumerate handles

**Solutions:**
- Verify system is vulnerable: Check patch level with `systeminfo`
- Run the exploit multiple times (race conditions are probabilistic)
- Try from a different user context

### "CreateProcessAsUser failed"

**Possible causes:**
- Token doesn't have required privileges
- Target executable path is incorrect
- AppLocker or other application whitelisting is blocking execution

**Solutions:**
- Verify the target path exists
- Try a different injection target (RuntimeBroker.exe, dllhost.exe)
- Check for application whitelisting policies

### Beacon doesn't call back

**Possible causes:**
- Network connectivity issues from SYSTEM context
- Firewall blocking outbound connection
- Listener configuration mismatch

**Solutions:**
- Verify the listener is configured correctly
- Check firewall rules
- Try a different listener type (SMB, TCP)
- Ensure the architecture matches (x64 vs x86)

## Credits

- **Original Research**: James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) - Project Zero
- **BOF Implementation**: Created for red team operations
- **MS16-032 Vulnerability**: CVE-2016-0099

## References

- [Microsoft Security Bulletin MS16-032](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)
- [CVE-2016-0099](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0099)
- [Original PoC by FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool. Always obtain proper authorization before testing.

## License

This project is provided as-is for security research and authorized penetration testing. Use responsibly and legally.

---

**For questions, issues, or contributions, please open an issue on GitHub.**
