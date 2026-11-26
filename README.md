# HostPosture
A modular PowerShell script module for collecting structured Windows host posture data in lab and authorized assessment environments.

## Overview
`HostPosture` separates data collection into focused functions that return consistent `[PSCustomObject]` records, coordinated by `Get-HostPosture`. Each collector is isolated so an error in one check records a message in `Errors` rather than aborting the entire snapshot.

### Collectors Included
- **`Get-HostContextPosture`**: Collects computer name, DNS/domain status, OS version/build/UBR, architecture, last boot time, current running identity, and PowerShell version.
- **`Get-HostServicePosture`**: Queries `Win32_Service` and flags non-standard service accounts (`IsNonStandardAccount`).
- **`Get-HostLocalAccountPosture`**: Enumerates local user accounts along with enabled/password state and membership in local `Administrators` and `Remote Desktop Users`.
- **`Get-HostNetworkPosture`**: Correlates network adapters, IPv4 addresses/prefixes, default gateways, DNS servers, and network profile categories by `InterfaceIndex`.
- **`Get-HostProcessPosture`**: Queries `Win32_Process` once and indexes `ProcessId` and `ParentProcessId` to map parent names and direct child processes (`ChildCount`, `ChildPids`, `ChildNames`).
- **`Get-HostPosture`**: Combines all collectors into a single timestamped snapshot object with optional filter switches and an `Errors` list.
