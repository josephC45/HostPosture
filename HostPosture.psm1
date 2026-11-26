function Get-HostLocalAccountPosture {
  [CmdletBinding()]
  param()

  $adminNames = @()
  try {
    $adminNames = @(
      Get-LocalGroupMember -Name 'Administrators' -ErrorAction 'Stop' |
        ForEach-Object { $_.Name }
    )
  } catch {}

  $rdpNames = @()
  try {
    $rdpNames = @(
      Get-LocalGroupMember -Name 'Remote Desktop Users' -ErrorAction 'Stop' |
        ForEach-Object { $_.Name }
    )
  } catch {}

  Get-LocalUser -ErrorAction 'Stop' | ForEach-Object {
    $fullMatchName = "$env:COMPUTERNAME\$($_.Name)"
    $isAdmin = ($_.Name -in $adminNames) -or ($fullMatchName -in $adminNames)
    $isRdpUser = ($_.Name -in $rdpNames) -or ($fullMatchName -in $rdpNames)

    [PSCustomObject]@{
      Name = $_.Name
      Sid = $_.SID.Value
      Enabled = [bool]$_.Enabled
      PasswordRequired = [bool]$_.PasswordRequired
      LastLogon = $_.LastLogon
      IsAdmin = [bool]$isAdmin
      IsRdpUser = [bool]$isRdpUser
    }
  }
}
function Get-HostNetworkPosture {
  [CmdletBinding()]
  param(
    [switch]$OnlyUp
  )

  $adapters = @(Get-NetAdapter -ErrorAction 'Stop')
  $ipAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction 'Stop')
  $ipConfigs = @(Get-NetIPConfiguration -ErrorAction 'Stop')
  $profiles = @(Get-NetConnectionProfile -ErrorAction 'SilentlyContinue')

  if ($OnlyUp) {
    $adapters = @($adapters | Where-Object { $_.Status -eq 'Up' })
  }

  foreach ($nic in $adapters) {
    $ifIndex = $nic.ifIndex

    $ipv4List = @(
      $ipAddresses |
        Where-Object { $_.InterfaceIndex -eq $ifIndex } |
        ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }
    )

    $cfg = $ipConfigs | Where-Object { $_.InterfaceIndex -eq $ifIndex } | Select-Object -First 1
    $gateways = @(
      if ($cfg -and $cfg.IPv4DefaultGateway) {
        $cfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop }
      }
    )
    $dnsServers = @(
      if ($cfg -and $cfg.DnsServer) {
        $cfg.DnsServer.ServerAddresses
      }
    )

    $profileInfo = $profiles | Where-Object { $_.InterfaceIndex -eq $ifIndex } | Select-Object -First 1
    $category = if ($profileInfo) { $profileInfo.NetworkCategory.ToString() } else { 'Unknown' }

    [PSCustomObject]@{
      InterfaceAlias = $nic.Name
      InterfaceIndex = $ifIndex
      Status = $nic.Status.ToString()
      MacAddress = $nic.MacAddress
      NetworkCategory = $category
      IPv4Addresses = $ipv4List
      DefaultGateways = $gateways
      DnsServers = $dnsServers
    }
  }
}
function Get-HostContextPosture {
  [CmdletBinding()]
  param()

  $computerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction 'Stop'
  $os = Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction 'Stop'
  $currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction 'Stop'
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

  [PSCustomObject]@{
    CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $computerSystem.Name
    DnsHostName = $computerSystem.DNSHostName
    Domain = $computerSystem.Domain
    PartOfDomain = [bool]$computerSystem.PartOfDomain
    DomainRole = $computerSystem.DomainRole
    OsName = $os.Caption
    DisplayVersion = $currentVersion.DisplayVersion
    BuildNumber = $os.BuildNumber
    Ubr = $currentVersion.UBR
    Architecture = $os.OSArchitecture
    LastBootUpTime = $os.LastBootUpTime
    RunningAs = $identity.Name
    PsVersion = $PSVersionTable.PSVersion.ToString()
  }
}
function Get-HostServicePosture {
  [CmdletBinding()]
  param()

  $cimParams = @{
    ClassName = 'Win32_Service'
    Property = @(
      'Name',
      'DisplayName',
      'State',
      'StartMode',
      'StartName',
      'PathName',
      'ProcessId'
    )
    ErrorAction = 'Stop'
  }

  Get-CimInstance @cimParams | ForEach-Object {
    $account = if ([string]::IsNullOrWhiteSpace($_.StartName)) { 'Unknown' } else { $_.StartName }
    $isNonStandardAccount = $account -notin @('LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService')

    [PSCustomObject]@{
      Name = $_.Name
      DisplayName = $_.DisplayName
      State = $_.State
      StartMode = $_.StartMode
      StartName = $account
      IsNonStandardAccount = $isNonStandardAccount
      ProcessId = $_.ProcessId
      PathName = $_.PathName
    }
  }
}
function Get-HostProcessPosture {
  [CmdletBinding()]
  param(
    [switch]$OnlyWithChildren
  )

  $cimParams = @{
    ClassName = 'Win32_Process'
    Property = @(
      'ProcessId',
      'ParentProcessId',
      'Name',
      'ExecutablePath',
      'CommandLine'
    )
    ErrorAction = 'Stop'
  }

  $procomputerSystem = @(Get-CimInstance @cimParams)

  $procByProcessId = @{}
  # Map ParentProcessId:List of child processes
  $childrenByParentProcessId = @{}

  foreach ($p in $procomputerSystem) {
    $procByProcessId[[int]$p.ProcessId] = $p

    $parentPid = [int]$p.ParentProcessId
    if (-not $childrenByParentProcessId.ContainsKey($parentPid)) {
      $childrenByParentPid[$ppid] = [System.Collections.Generic.List[object]]::new()
    }
    $childrenByParentProcessId[$parentPid].Add($p)
  }

  $results = foreach ($p in $procomputerSystem) {
    $processId = [int]$p.ProcessId
    $parentProcessId = [int]$p.ParentProcessId

    $parentObj = if ($procByProcessId.ContainsKey($parentProcessId)) { $procByProcessId[$parentProcessId] } else { $null }
    $childList = if ($childrenByParentProcessId.ContainsKey($processId)) { @($childrenByParentProcessId[$processId]) } else { @() }
    $childPids = @($childList | ForEach-Object { [int]$_.ProcessId })
    $childNames = @($childList | ForEach-Object { $_.Name })

    [PSCustomObject]@{
      ProcessId = $processId
      ParentProcessId = $parentProcessId
      ParentName = if ($parentObj) { $parentObj.Name } else { $null }
      Name = $p.Name
      ExecutablePath = $p.ExecutablePath
      CommandLine = $p.CommandLine
      ChildCount = $childList.Count
      ChildPids = $childPids
      ChildNames = $childNames
    }
  }

  if ($OnlyWithChildren) {
    return @($results | Where-Object { $_.ChildCount -gt 0 })
  }

  return @($results)
}
function Get-HostPosture {
  [CmdletBinding()]
  param(
    [switch]$OnlyRunningNonStandardServices,
    [switch]$OnlyEnabledAccounts,
    [switch]$OnlyUpInterfaces,
    [switch]$OnlyProcessesWithChildren
  )

  $errors = @()
  # -- Host Info
  try {
    $hostContext = Get-HostContextPosture
  }
  catch {
    $hostContext = $null
    $errors += "HostContext failed: $($_.Exception.Message)"
  }
  # -- Local Accounts
  try {
    $localAccounts = @(Get-HostLocalAccountPosture)
    if ($OnlyEnabledAccounts) {
      $localAccounts = @($localAccounts | Where-Object { $_.Enabled })
    }
  }
  catch {
    $localAccounts = @()
    $errors += "LocalAccounts failed: $($_.Exception.Message)"
  }
  # -- Networks
  try {
    $nicArgs = @{}
    if ($OnlyUpInterfaces) { $nicArgs['OnlyUp'] = $true }
    $networkInterfaces = @(Get-HostNetworkPosture @nicArgs)
  }
  catch {
    $networkInterfaces = @()
    $errors += "NetworkInterfaces failed: $($_.Exception.Message)"
  }
  # -- Services
  try {
    $services = @(Get-HostServicePosture)
    if ($OnlyRunningNonStandardServices) {
      $services = @(
        $services | Where-Object {
          $_.State -eq 'Running' -and $_.IsNonStandardAccount
        }
      )
    }
  }
  catch {
    $services = @()
    $errors += "Services failed: $($_.Exception.Message)"
  }
  # -- Processes
  try {
    $procArgs = @{}
    if ($OnlyProcessesWithChildren) { $procArgs['OnlyWithChildren'] = $true }
    $processes = @(Get-HostProcessPosture @procArgs)
  }
  catch {
    $processes = @()
    $errors += "Processes failed: $($_.Exception.Message)"
  }

  [PSCustomObject]@{
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    HostContext = $hostContext
    LocalAccounts = $localAccounts
    LocalAccountCount = $localAccounts.Count
    NetworkInterfaces = $networkInterfaces
    NetworkCount = $networkInterfaces.Count
    Services = $services
    ServiceCount = $services.Count
    Processes = $processes
    ProcessCount = $processes.Count
    Errors = $errors
  }
}

Export-ModuleMember -Function @(
  'Get-HostContextPosture',
  'Get-HostServicePosture',
  'Get-HostLocalAccountPosture',
  'Get-HostNetworkPosture',
  'Get-HostProcessPosture',
  'Get-HostPosture'
)
