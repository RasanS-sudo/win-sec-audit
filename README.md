[README.md](https://github.com/user-attachments/files/26948025/README.md)
# WinSecAudit

**Host-based Windows security posture assessment tool written in C#.**

Queries the Windows API directly to audit local security configuration — password policy, account lockout, privileged group membership, network exposure, running services, scheduled tasks, patch status, and Windows Defender state. Outputs a color-coded console report and a dark-mode HTML report with expandable findings and remediation guidance.

Built for security analysts and GovCon environments where you need to assess a Windows host quickly, without installing third-party tools.

---

## What It Checks

| Category | Checks |
|---|---|
| **Password Policy** | Minimum length, history depth, max age, never-expire detection |
| **Account Lockout** | Lockout threshold (brute force exposure), lockout duration |
| **Privileged Groups** | Administrators, Remote Desktop Users, Backup Operators, Power Users, Remote Management Users |
| **Network Exposure** | Listening TCP ports flagged against a high-risk port database (Telnet, RDP, SMB, FTP, WinRM, MSSQL, etc.) |
| **SMBv1** | Registry-level detection — flags EternalBlue/WannaCry exposure |
| **Windows Firewall** | All three profiles (Domain, Private, Public) via `netsh` |
| **High-Risk Services** | RemoteRegistry, Telnet Server, SNMP, IIS FTP, and others |
| **Scheduled Tasks** | Non-Microsoft SYSTEM tasks executing from Temp/AppData/Public paths |
| **Autorun Registry** | HKLM Run keys — detects encoded PowerShell, mshta, wscript persistence |
| **Windows Update** | AUOptions policy, last successful install date |
| **Windows Defender** | Real-time protection state, signature age |

---

## Requirements

- Windows 10 / Windows Server 2016 or later
- .NET 6.0 Runtime (or use the self-contained single-file build)
- **Administrator privileges recommended** — standard user mode runs partial checks

---

## Usage

```
WinSecAudit.exe [options]

Options:
  --verbose / -v        Show remediation steps in console output
  --html-only           Skip console findings, only write HTML report
  --console-only        Skip HTML report generation
  --output <path>       Specify HTML report output path
```

**Basic run (generates HTML report in current directory):**
```
WinSecAudit.exe
```

**Elevated run with verbose console output:**
```
# Right-click → Run as Administrator
WinSecAudit.exe --verbose
```

**Specify report output path:**
```
WinSecAudit.exe --output C:\Reports\workstation-audit.html
```

**Console only, no HTML:**
```
WinSecAudit.exe --console-only --verbose
```

**Exit codes:** `0` = Low/Pass, `1` = Medium issues, `2` = High or Critical findings — usable in scripts.

---

## Sample Output

```
  ██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗
  ██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝
  ██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║
  ██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║
  ╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝

  Host:      WORKSTATION-01
  OS:        Microsoft Windows NT 10.0.19045.0
  User:      CORP\analyst
  Elevated:  Yes
  Time:      2025-01-15 14:32:07 UTC

  [...] Password & Account Policy          [WARN] 3 issues found
  [...] Privileged Group Membership        [PASS] 5 checks
  [...] Network Exposure & Firewall        [WARN] 2 issues found
  [...] Services & Persistence             [PASS] 3 checks
  [...] Patch Management & Defender        [WARN] 1 issues found

  RISK TIER:   HIGH

  Critical: 0   High: 2   Medium: 3   Low: 1   Pass: 12

  HTML report saved: C:\...\WinSecAudit_WORKSTATION-01_20250115_143207.html
```

---

## Build

**Prerequisites:** [.NET 6 SDK](https://dotnet.microsoft.com/download)

```bash
# Clone
git clone https://github.com/RasanS-sudo/win-sec-audit.git
cd win-sec-audit/WinSecAudit

# Run directly
dotnet run

# Build standard binary
dotnet build -c Release

# Build self-contained single .exe (no .NET install required on target)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
# Output: bin/Release/net6.0-windows/win-x64/publish/WinSecAudit.exe
```

---

## Architecture

```
WinSecAudit/
├── Program.cs                      # Entry point, orchestration, console output
├── Models.cs                       # Finding, AuditResult, Severity enum
├── HtmlReportGenerator.cs          # Dark-mode HTML report renderer
└── Auditors/
    ├── PasswordPolicyAuditor.cs    # NetUserModalsGet P/Invoke (levels 0 & 3)
    ├── PrivilegedGroupAuditor.cs   # NetLocalGroupGetMembers P/Invoke
    ├── NetworkAuditor.cs           # IPGlobalProperties, netsh, registry (SMBv1)
    ├── ServicesAuditor.cs          # EnumServicesStatusEx, schtasks, registry Run keys
    └── PatchAuditor.cs             # Windows Update registry, Defender registry
```

**No third-party dependencies.** All auditors use:
- Windows API P/Invoke (`netapi32.dll`, `advapi32.dll`, `kernel32.dll`)
- .NET `System.Net.NetworkInformation` for port enumeration
- `Microsoft.Win32.Registry` for registry reads
- Process execution for `netsh` and `schtasks` (both inbox Windows tools)

---

## Framework Mapping

Findings map to common compliance controls:

| Finding | Framework Control |
|---|---|
| Password length < 14 | NIST SP 800-63B, CMMC AC.1.001, CIS Benchmark L1 |
| No account lockout | CMMC AC.2.006, NIST 800-53 AC-7 |
| Telnet / FTP running | CMMC SC.3.177, NIST 800-53 SC-8 |
| RDP exposed (0.0.0.0) | CMMC AC.2.006, NIST 800-53 AC-17 |
| SMBv1 enabled | NIST 800-53 SI-2, CISA Advisory |
| Firewall disabled | CMMC SC.1.002, NIST 800-53 SC-7 |
| Defender RTP off | CMMC SI.1.210, NIST 800-53 SI-3 |
| Autorun registry abuse | NIST 800-53 CM-7, CMMC CM.2.061 |

---

## Limitations

- **Windows only** — uses Windows-specific APIs throughout
- **No domain-level checks** — audits local policy only; GPO-applied settings are read where they land in registry
- **No network scanning** — checks what's listening on *this* host; does not probe remote hosts
- **Defender checks** — reads registry state only; does not call Windows Security Center COM APIs
- **Scheduled task heuristics** — suspicious path detection is heuristic-based; investigate flagged tasks, don't auto-delete

---

## License

MIT

---

*Built as part of a security engineering portfolio targeting federal/GovCon analyst roles.*
*Frameworks referenced: NIST 800-53 Rev 5, CMMC Level 1/2, CIS Benchmarks for Windows.*
