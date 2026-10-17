# Windows agent notes

State of the Windows side of `rex-boing-agent`: what it reads and how,
which struct layouts it depends on and where they were checked, what has
not run on real Windows yet, and what to look at the first time it does.

Everything was written and cross-compiled on macOS. No line of the
Windows-only code has executed yet. The OS-independent helpers (`win*.go`)
are unit-tested on every OS.

## Files

| File | Build | Contents |
|---|---|---|
| `internal/collect/collect_windows.go` | windows | The collector: wiring, sampling per section, doctor, notices, volume cache |
| `internal/collect/collect_windows_sys.go` | windows | Raw kernel32/ntdll/psapi/dxgi calls and their structs |
| `internal/collect/collect_windows_pdh.go` | windows | PDH query wrapper |
| `internal/collect/collect_windows_host.go` | windows | Registry, host description, reboot pending, service state, volumes, adapters |
| `internal/collect/collect_windows_proc.go` | windows | Process table |
| `internal/collect/collect_windows_lhm.go` | windows | Optional LibreHardwareMonitor reader |
| `internal/collect/winparse.go` (+ `_test`) | all | Pure helpers: CPU math, core kinds, clocks, memory, PDH item parsing, GPU engine aggregation, DXGI/NVIDIA merging, thermal zones, LHM JSON, network naming, host naming, virtualization |
| `internal/manage/manage_windows.go` | windows | install, uninstall, upgrade, pair-code, `CleanupOld` |
| `internal/manage/winkeys.go` (+ `_test`) | all | Key parsing, line building, shell quoting, authorized_keys rewrite, encodings, version check |
| `internal/manage/cleanup_other.go` | !windows | No-op `CleanupOld` |

`main.go` should call `manage.CleanupOld()` at the start of every run (it
deletes `*.old.exe` left by upgrades and uninstalls).

## What each section reads

### cpu
* Per-logical-processor times: `NtQuerySystemInformation(SystemProcessorPerformanceInformation = 8)`.
  With more than one processor group (more than 64 logical processors) each
  group is read with `NtQuerySystemInformationEx`, passing the group number
  (a USHORT) as the input buffer, as gopsutil does. If that export is
  missing, only the current group is measured and doctor says so.
* total/user/system/idle from deltas: system = kernel − idle (kernel time
  includes idle), nice = 0, no iowait/steal/load.
* Processor count: `GetActiveProcessorGroupCount` + `GetActiveProcessorCount(group)`
  per group (their sum equals `GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)`).
* Core kinds: `GetLogicalProcessorInformationEx(RelationProcessorCore)`,
  `PROCESSOR_RELATIONSHIP.EfficiencyClass` (higher = performance). This is
  the same field `GetSystemCpuSetInformation` reports, but this call also
  gives the physical core count and each core's logical-processor mask, so
  one API covers both. On homogeneous CPUs Windows reports class 0 for
  every core; then `kinds`, `performanceCores` and `efficiencyCores` are
  left out rather than claiming "all P".
* Clocks: PDH `\Processor Information(*)\% Processor Performance` ×
  `\Processor Information(*)\Processor Frequency` (nominal MHz per
  instance, as Task Manager does); falls back to the registry `~MHz` of
  `CentralProcessor\0`. `_Total` gives `clockMHz`; per-instance values
  averaged by kind give `performanceClockMHz` / `efficiencyClockMHz`.
* processes/threads: `GetPerformanceInfo` in vitals, the Toolhelp snapshot in full.

### memory
`GlobalMemoryStatusEx` (total, available → used, `pressure` = used/total,
`pressureLevel` from dwMemoryLoad ≥ 90 warning, ≥ 97 critical) and
`GetPerformanceInfo` (`cached` = SystemCache, `wired` = non-paged pool).
Swap is the page file: total = (CommitLimit − PhysicalTotal) pages, used =
`\Paging File(_Total)\% Usage` × total. If that counter is missing, swap is
left out instead of guessed. No page file reports a zero swap.

### gpus
* Adapters: DXGI `CreateDXGIFactory1` → `IDXGIFactory1::EnumAdapters1`
  (vtable slot 12) → `IDXGIAdapter1::GetDesc1` (slot 10) → `Release` (2).
  Gives name, PCI vendor, dedicated/shared memory and the LUID. Software
  adapters (Basic Render Driver) are skipped, Microsoft display-only
  adapters (Hyper-V video, Remote Display) are shown only when in use.
* Utilization: `\GPU Engine(*)\Utilization Percentage`, instances like
  `pid_1234_luid_0x00000000_0x0000D1B6_phys_0_eng_3_engtype_VideoDecode`.
  Summed over processes per physical engine; each engine type
  (`3d`, `copy`, `videodecode`, `videoencode`, `compute`, …) reports its
  busiest engine and the adapter its busiest engine, which is what Task
  Manager shows (the brief said "sum per engtype"; summing several copy
  engines can exceed 100 %). Per-process GPU % is a process's busiest
  engine; `processes.gpuAttribution` is true when the counter works.
* Memory: `\GPU Adapter Memory(*)\Dedicated Usage` and `Shared Usage`.
  Discrete GPUs (≥ 512 MiB VRAM) report dedicated use/VRAM; integrated ones
  dedicated + shared, as Task Manager does.
* The LUID in instance names is written as two hex halves. Which half comes
  first is not documented (high first, by every example), so both orders
  are matched; one half is practically always 0.
* NVIDIA: `internal/nvidia` (nvidia-smi) adds temperature, power, fan,
  clocks and exact VRAM, merged by name, else by elimination when there is
  one NVIDIA GPU on each side, else appended. Order: largest dedicated
  memory first.
* The GPU counters are a separate PDH query collected at most every
  max(1 s, 20 × the last collection's duration, ≤ 10 s), because GPU Engine
  can have thousands of instances.

### network
PDH `\Network Interface(*)\Bytes Received/sec` / `Bytes Sent/sec`. Instance
names are adapter descriptions with `( ) # / \` replaced by `[ ] _ _ _`,
which is how they are matched to `GetAdaptersAddresses` (friendly name,
up/down, link speed, type). Skipped: isatap, Teredo, loopback, Hyper-V
virtual adapters, vEthernet, WAN Miniport, pseudo-interfaces, 6to4,
IP-HTTPS, kernel debug, and adapters of type loopback/tunnel. Totals are
integrated rate × interval. `primaryInterface`/`localAddress`: the up
adapter with a default gateway and the lowest IPv4 metric, else the first
up adapter with IPv4. Adapters are re-read every 30 s.

### disk
PDH `\PhysicalDisk(_Total)\Disk Read Bytes/sec` and `Disk Write Bytes/sec`.
Volumes (full only): `GetLogicalDriveStringsW`, `GetDriveTypeW` (fixed and
remote only), `GetDiskFreeSpaceExW` (available = free to this user),
`GetVolumeInformationW` (fs; network drives get "(network)"), system drive
first, name `C:`. Refreshed in the background at most every 15 s because a
dead network drive can block for many seconds; the first full sample
waits at most 250 ms for it.

### battery
`GetSystemPowerStatus`: present unless BatteryFlag has bit 128 (no
battery; 255 = unknown also has it), percentage, charging (flag 8),
pluggedIn (ACLineStatus 1), timeRemainingMinutes when not on AC and known.
No battery: section omitted.

### thermal, power
* `\Thermal Zone Information(*)\Temperature` (Kelvin → °C, keys `tz0`…,
  category Other). Own PDH query, collected at most every 5–30 s since it
  evaluates ACPI methods. Many desktops have no zones; ACPI zones are often
  static or meaningless.
* LibreHardwareMonitor, only if the user runs it with Options → Remote Web
  Server: `GET http://127.0.0.1:8085/data.json`, no proxy, 300 ms timeout,
  8 MiB cap, at most every 5 s (30 s while unreachable), in the background;
  readings older than 20 s are dropped. Reads CPU temperatures (headline:
  "CPU Package", "Core (Tctl/Tdie)", Tctl/Tdie, …, else the hottest),
  skipping "Distance to TjMax"; all temperature sensors by hardware
  category; fans; CPU package power (`power.cpuWatts` and `packageWatts`,
  "CPU Cores" as fallback); AMD/Intel GPU temperatures merged into GPUs.
  Handles both the current JSON (SensorId, Type, RawValue, HardwareId) and
  older versions (formatted values with `,` decimals and °F). No driver is
  shipped or loaded.
* `state` is always `nominal`: Windows has no thermal pressure API.
* `power.gpuWatts` = sum of nvidia-smi power draw.

### processes (full only, at most one scan per 0.9 s)
Toolhelp32 snapshot (pid, ppid, threads, exe name; pid 0 "System Idle
Process" is left out). Then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`:
`GetProcessTimes` (CPU % of one core from deltas; creation time → `start`
µs), `GetProcessMemoryInfo` (WorkingSetSize), `GetProcessIoCounters`
(Read/WriteTransferCount deltas → diskRead/diskWrite; note this counts all
I/O, network and device included), `QueryFullProcessImageNameW` (path,
cached per process). Denied handles keep name/pid/threads only. State is
keyed by (pid, creation time) and rebuilt every scan, so exited processes
and reused pids never leak. No user names, no cmd (reading the PEB is out
of scope for v1).

### system (full only)
uptime from `GetTickCount64`; `rebootRequired` from the presence of
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
or `…\Component Based Servicing\RebootPending` (re-read every 30 s). No
failed services, no containers.

### host (hello)
Hostname; `RtlGetVersion` for the build (not subject to manifest lies);
registry `ProductName` (build ≥ 22000 and "Windows 10" → "Windows 11"),
`DisplayVersion` (else `ReleaseId`) as osVersion, `UBR`; kernel =
`10.0.<build>.<ubr>`; chip from `ProcessorNameString` with (R)/(TM)/"CPU @
x GHz"/"N-Core Processor" removed; model/vendor from
`HARDWARE\DESCRIPTION\System\BIOS` (SystemProductName/SystemManufacturer,
then BaseBoard*, OEM placeholders skipped); virtualization from those
(hyperv, vmware, virtualbox, parallels, amazon, google, xen, kvm, bochs,
else none); bootTime = now − GetTickCount64.

### Robustness
* Every source runs under `recover`; a panic drops that section for the
  sample and is logged to stderr once per source.
* Every optional DLL export is looked up (`LazyProc.Find`) before the call.
  DLLs load from System32 only.
* Every `unsafe.Pointer → uintptr` conversion sits in the `LazyProc.Call`
  / `syscall.SyscallN` expression itself, so the GC keeps the buffer alive
  and in place (both are `uintptrescapes`/`uintptrkeepalive`). COM objects
  are held as typed pointers, never as uintptr.
* Struct sizes that matter have compile-time checks; the module vets for
  windows/amd64, arm64 and 386.
* Counters that do not exist are not added; doctor lists them.

## manage

* Install dir `%LOCALAPPDATA%\RexBoingRemote` (Known Folder fallback),
  executable `rex-boing-agent.exe`.
* install: copies itself there (temp file + rename; a running installed
  copy is renamed aside to `*.old.exe` first). Key file: members of
  BUILTIN\Administrators use `%ProgramData%\ssh\administrators_authorized_keys`,
  everyone else `%USERPROFILE%\.ssh\authorized_keys`. Membership is checked
  with `CheckTokenMembership` and, because a non-elevated UAC token carries
  Administrators as deny-only (which `CheckTokenMembership` reports as not a
  member), also by scanning the token's group list. If `sshd_config` no
  longer routes administrators to that file (no uncommented
  `administrators_authorized_keys`), the user's own file is used. A new
  admin file gets `icacls <file> /inheritance:r /grant *S-1-5-32-544:F
  /grant *S-1-5-18:F`. Not writable → `{"ok":false,"error":"admin-key-file"}`
  telling the user to run elevated. `%ProgramData%\ssh` missing →
  `sshd-missing`.
* Forced command by `HKLM\SOFTWARE\OpenSSH\DefaultShell`:
  powershell.exe/pwsh.exe → `& 'C:\…\rex-boing-agent.exe' ssh` (a `'` is
  doubled); anything else (cmd.exe) → `"C:\…\rex-boing-agent.exe" ssh`.
  Inside `command="…"` only `\"` is an escape for OpenSSH, so `"` becomes
  `\"` and backslashes stay. Line: `restrict,command="…" <type> <base64>
  rex-boing-remote:<label>`, the same key types and label rule as
  manage_unix.go.
* The file is rewritten in place (keeps its owner and ACL; a
  temp-and-rename would take the folder's inherited ACL), same key blob
  replaced, duplicates dropped, foreign lines byte for byte, CRLF or LF as
  the file has it. A UTF-8 BOM is dropped and a UTF-16 file (what
  PowerShell 5's `>` writes, which sshd cannot read) is converted to UTF-8.
* uninstall: removes our lines from both files where readable (the admin
  file is skipped silently for non-administrators, and reported for
  non-elevated administrators), moves the running exe to
  `%TEMP%\rex-boing-agent-<pid>.old.exe` (renaming a running exe is
  allowed; it is scheduled with `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`,
  which only works for administrators, and `CleanupOld` deletes it the next
  time any agent runs), then deletes the install dir. If %TEMP% is on
  another volume, it removes the rest and schedules the exe and folder for
  deletion at reboot, or says to delete them by hand.
* upgrade: exactly `size` bytes to `rex-boing-agent.new.exe`, SHA-256
  check, `<new> version` must say `rex-boing-agent`, protocol 1 and os
  windows; then the installed exe is renamed to `rex-boing-agent.old.exe`
  (or a unique `*.old.exe` if an older one is still running) and the new
  one renamed into place, with rollback. Sharing violations (antivirus
  scanning the new file) are retried for about 2 s. Result codes match the
  Unix side (`usage`, `short-read`, `hash-mismatch`, `verify-failed`,
  `upgrade-failed`).
* pair-code: hostname, `USERNAME` (or `DOMAIN\user` for domain accounts),
  port from `%ProgramData%\ssh\sshd_config` and host keys from
  `ssh_host_{ed25519,ecdsa,rsa}_key.pub` via the shared helpers in
  paircode.go, IPv4 addresses from `GetAdaptersAddresses` (up,
  non-loopback, not link-local; WSL/Default Switch/host-only adapters
  without a gateway skipped) ordered by `orderPairAddresses`, then
  `<hostname>.local`. Produced whether or not sshd is running.

## Background history (serve, install-service)

* Endpoint: named pipe `\\.\pipe\rex-boing-remote-<user SID>`
  (`internal/serve/ipc_windows.go`). Security descriptor
  `O:<SID>D:P(A;;GA;;;<SID>)`: owned by the user, protected DACL granting
  only the user. `PIPE_REJECT_REMOTE_CLIENTS`. The first instance uses
  `FILE_FLAG_FIRST_PIPE_INSTANCE` (a name someone else created first makes
  `serve` fail rather than join it); each next instance is created while the
  previous one still holds the name. All I/O is overlapped with an event, so
  reads and writes time out (`CancelIoEx` + `GetOverlappedResult`) and Close
  interrupts `ConnectNamedPipe` through a second event. Clients open with
  `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION` and refuse a pipe whose
  owner (`GetSecurityInfo`, `OWNER_SECURITY_INFORMATION`) is not their SID.
* Service: `schtasks /Create /TN "\Rex Boing Remote agent" /XML <file> /F`
  with a UTF-16LE task definition (`internal/service/service.go`, `taskXML`):
  `LogonTrigger` for `DOMAIN\user`, principal = the user's SID,
  `InteractiveToken`, `LeastPrivilege`, no execution time limit, restart on
  failure every minute. Then `schtasks /Run`, which only starts it if the user
  has a desktop session; otherwise the next sign-in does.
* Restart after `upgrade`: `{"want":"stop"}` on the pipe (serve saves and
  exits), then `schtasks /Run`. `uninstall-service`: stop, `/End`, `/Delete`,
  delete `history.json`.

Not verified on real Windows: that a standard (non-admin) user may create a
task with a per-user logon trigger this way; the SID as principal `UserId`;
the owner check when the serve runs elevated (it should not: the task is
`LeastPrivilege`). The pipe round trip itself runs in CI on windows-latest
(`internal/serve` tests).

## Layouts verified, and where

| Struct / API | Layout used | Source |
|---|---|---|
| SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION | 3 × LARGE_INTEGER, Reserved1[2] LARGE_INTEGER, ULONG; 48 bytes with tail padding (explicit pad for 386) | [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation); gopsutil [cpu_windows.go](https://github.com/shirou/gopsutil/blob/master/cpu/cpu_windows.go) (same fields, InterruptCount padded to 8) |
| NtQuerySystemInformationEx per group | (class, &USHORT group, 2, buf, len, &ret) | gopsutil cpu_windows.go `perfInfoAllGroups` |
| PDH_FMT_COUNTERVALUE_ITEM_W | szName ptr @0, CStatus DWORD @8, double @16, stride 24 on amd64/arm64/386 | [ITEM_W](https://learn.microsoft.com/en-us/windows/win32/api/pdh/ns-pdh-pdh_fmt_countervalue_item_w), [PDH_FMT_COUNTERVALUE](https://learn.microsoft.com/en-us/windows/win32/api/pdh/ns-pdh-pdh_fmt_countervalue); gopsutil [common_windows.go](https://github.com/shirou/gopsutil/blob/master/internal/common/common_windows.go) uses the same CStatus/double pair |
| PdhGetFormattedCounterArrayW | size in bytes, NULL buffer + 0 → PDH_MORE_DATA, names stored after the items | [docs](https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhgetformattedcounterarrayw) |
| PdhAddEnglishCounterW | (query, path, userdata, &counter); missing object/counter → error, missing instance → success | [docs](https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhaddenglishcounterw) |
| PDH status values | PDH_MORE_DATA 0x800007D2, CSTATUS_VALID 0, NEW 1, PDH_FMT_DOUBLE 0x200, NOCAP100 0x8000 | [PDH error codes](https://learn.microsoft.com/en-us/windows/win32/perfctrs/pdh-error-codes), formats from the ItemArray page |
| SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX / PROCESSOR_RELATIONSHIP | Relationship @0, Size @4, Flags @8, EfficiencyClass @9, GroupCount @30, GROUP_AFFINITY{Mask ptr, WORD Group, WORD[3]} @32 | [SLPI_EX](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex), [PROCESSOR_RELATIONSHIP](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-processor_relationship) (EfficiencyClass: Windows 10+, nonzero only on heterogeneous CPUs) |
| MEMORYSTATUSEX | 2 DWORD + 7 DWORDLONG, 64 bytes | [docs](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex) |
| PERFORMANCE_INFORMATION | DWORD cb, 10 SIZE_T (pages), 3 DWORD | [docs](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information) |
| PROCESS_MEMORY_COUNTERS / GetProcessMemoryInfo | DWORD cb, DWORD faults, 8 SIZE_T; LIMITED access suffices since Vista | [docs](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo) |
| IO_COUNTERS | 6 ULONGLONG | `windows.IO_COUNTERS` in x/sys v0.30.0 |
| SYSTEM_POWER_STATUS | 4 BYTE + 2 DWORD, 12 bytes; flag 128 = no battery, 255 = unknown, 8 = charging; −1 = unknown time | [docs](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-system_power_status) |
| DXGI_ADAPTER_DESC1 | WCHAR[128], 4 UINT, 3 SIZE_T, LUID{DWORD Low, LONG High}, UINT Flags; 312 bytes on 64-bit | [docs](https://learn.microsoft.com/en-us/windows/win32/api/dxgi/ns-dxgi-dxgi_adapter_desc1), [CreateDXGIFactory1](https://learn.microsoft.com/en-us/windows/win32/api/dxgi/nf-dxgi-createdxgifactory1) |
| IDXGIFactory1 / IDXGIAdapter1 vtables, IID 770aae78-f26f-4dba-a829-253c83d1b387 | EnumAdapters1 = 12, GetDesc1 = 10, Release = 2; DXGI_ADAPTER_FLAG_SOFTWARE = 2 | dxgi.h C vtable declarations ([apitrace/dxsdk](https://github.com/apitrace/dxsdk/blob/master/Include/dxgi.h)) |
| IP_ADAPTER_ADDRESSES, ProcessEntry32, Toolhelp, GetProcessTimes, QueryFullProcessImageName, drive APIs, MoveFileEx, tokens, services, registry | as declared by golang.org/x/sys/windows v0.30.0 | x/sys |
| OpenSSH for Windows key files, DefaultShell, icacls line | administrators → `%ProgramData%\ssh\administrators_authorized_keys`, ACL Administrators + SYSTEM only; `HKLM\SOFTWARE\OpenSSH\DefaultShell` | [server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration), [key management](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement), [Win32-OpenSSH DefaultShell](https://github.com/PowerShell/Win32-OpenSSH/wiki/DefaultShell) |
| LibreHardwareMonitor data.json | nodes {id, Text, Min, Value, Max, ImageURL, Children}; sensors add SensorId, Type, RawMin/RawValue/RawMax (NaN written as "NaN"); hardware adds HardwareId | [HttpServer.cs](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/blob/master/LibreHardwareMonitor.Windows.Forms/Utilities/HttpServer.cs) |

## Not verified, in order of risk

1. **Stdin/stdout through the OpenSSH default shell.** With DefaultShell =
   PowerShell, sshd runs `powershell -c "& '…' ssh"`. Whether Windows
   PowerShell 5.1 passes the native agent's stdin through untouched (EOF
   detection; and binary integrity for `upgrade`, which streams the new
   exe on stdin) and leaves stdout unbuffered and unconverted has not been
   tested. cmd.exe should be transparent. If PowerShell interferes, the
   fix is in the forced command (for example `cmd /c` inside it), not in
   the protocol.
2. How Win32-OpenSSH invokes the shell for a forced command (`-c` vs `/c`,
   quoting of paths with spaces, `&`, `(`, `%` in user names), and that it
   sets `SSH_ORIGINAL_COMMAND`. Documented for Unix OpenSSH, not
   explicitly for the Windows port.
3. The DXGI COM calls (vtable slots, `SyscallN` with `this`): a mistake
   here crashes the process rather than failing a source; `recover`
   cannot catch an access violation in foreign code. Also that DXGI works
   in an SSH (service, session 0) logon.
4. PDH wildcard counters picking up instances that appear after the
   counter was added (new processes using the GPU, an adapter that comes
   up). Expected from PDH; untested.
5. The LUID spelling in GPU instance names (high or low half first): both
   are accepted.
6. `NtQuerySystemInformationEx` per group on > 64 logical processors.
7. Administrator detection under UAC (deny-only group) and the
   `admin-key-file` path; the `icacls` result is what sshd accepts.
8. Renaming the running exe during upgrade/uninstall while Defender scans
   it; `MoveFileEx(DELAY_UNTIL_REBOOT)` for non-administrators (expected to
   fail quietly).
9. Connecting to a closed loopback port can take Windows up to a few
   seconds (SYN retries after RST); the LHM probe is capped at 300 ms, so
   agent start-up may take 0.3 s longer on PCs without LibreHardwareMonitor.

## First real-Windows run checklist

Run in an elevated and in a normal PowerShell, then over SSH as an
administrator and as a standard user, with DefaultShell unset (cmd) and set
to powershell.exe.

`rex-boing-agent doctor`
* CPU usage: logical processor count matches Task Manager; no "only N are measured".
* Core types: on a 12th-gen-or-later Intel or Snapdragon, P/E counts match the spec sheet.
* Performance counters: the "not on this machine" list is short and plausible
  (thermal zones may be missing; network, disk, Processor Information and
  GPU Engine should not be on a physical PC).
* Network: primary interface is the one with the default route; address right.
* GPU names: every real adapter, no Basic Render Driver. GPU utilization
  says how long one collection takes (expect well under 100 ms).
* NVIDIA: found when an NVIDIA driver is installed.
* CPU temperature and fans: with LibreHardwareMonitor's web server on, OK.
* Processes: "not readable" is small when elevated.
* OpenSSH Server: running; default shell as configured.

`rex-boing-agent stream --count 3 --detail full`
* Line 1 hello: osName says Windows 11 on build ≥ 22000, kernel
  `10.0.<build>.<ubr>`, chipName clean, model/vendor not placeholders,
  virtualization `none` on bare metal and right in a VM, bootTime matches
  `systeminfo`.
* Sample 1 has `resync: true`, zero rates. Samples 2–3: `cpu.total` close
  to Task Manager, `perCore` length = logical processors, `kinds` length
  equal to it on hybrid CPUs, `clockMHz` plausible (above nominal under
  turbo).
* memory: used/total match Task Manager's "In use"; swap total ≈ page file
  size (Settings → Virtual memory), swap used plausible.
* gpus: names, vendor, `engines` keys (`3d`, `copy`, `videodecode`, …),
  utilization tracks a video or game; memoryUsed/memoryTotal match Task
  Manager's GPU memory; NVIDIA temperature/watts present.
* network: rx/tx follow a download; interfaces carry friendly names
  ("Ethernet", "Wi-Fi") and speeds; no isatap/Teredo/vEthernet.
* disk: read/write follow a file copy; volumes start with C:, sizes match
  Explorer.
* processes: rows have pid, name, path, start, cpu, memory; ranks for cpu,
  memory, disk and gpu; `gpuAttribution: true` with a GPU counter.
* battery on a laptop: percentage, charging, pluggedIn, minutes on battery.
* thermal: `tz*` sensors only where ACPI zones exist; with LHM, CPU
  package temperature, fans and `power.cpuWatts`.
* system: uptime, rebootRequired.
* stderr: no "source failed" lines.

Then `install` (key on stdin), connect with the key and run `stream`,
`version`, `doctor`, `upgrade` (compare the hash and that the old exe was
renamed and is cleaned up on the next run), `pair-code` (decode it), and
`uninstall` (key lines gone, install folder gone, the moved exe in %TEMP%
removed by a later run or a reboot).
