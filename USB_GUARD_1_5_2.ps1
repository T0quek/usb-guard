#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    USB Guard 1.5.2 – ochrona stacji roboczej Windows przed nieautoryzowanymi nośnikami USB.

.DESCRIPTION
    USB Guard blokuje pendrive'y i dyski zewnętrzne (klasa USB Mass Storage) zasadami systemu Windows.
    Do blokowania urządzeń nie jest wymagane aktywne działanie skryptu w tle.
    Próby podłączenia nośników są zapisywane w logu, Dzienniku zdarzeń i raporcie miesięcznym.

    Akcje:
    Install   - instaluje program i włącza blokadę
    Uninstall - wyłącza ochronę i usuwa program
    Status    - pokazuje stan ochrony i podłączone nośniki
    List      - wyświetla białą listę
    Add       - dodaje nośnik do białej listy
    Remove    - usuwa nośnik z białej listy
    Purge     - czyści białą listę i usuwa z systemu niepodłączone nośniki
    Report    - tworzy raport miesięczny HTML i CSV
    Help      - wyświetla opis akcji, np. USBG Help Add

.PARAMETER Action
    Akcja do wykonania. Nazwę akcji można podać bez słowa -Action, np. USBG Status.

.PARAMETER Topic
    Akcja, której opis wyświetla USBG Help, np. USBG Help Add lub USBG Help -Topic Add (-Topic można pominąć)

.PARAMETER InstanceId
    Identyfikator nośnika, np. USB\VID_0781&PID_5567\4C530001231122117401 (akcje Add i Remove).

.PARAMETER Description
    Opis nośnika dodawanego do białej listy (akcja Add) (obowiązkowo).

.PARAMETER Owner
    Właściciel lub dział, do którego należy nośnik (akcja Add) (opcjonalnie).

.PARAMETER Month
    Miesiąc raportu w formacie RRRR-MM (akcja Report). Domyślnie poprzedni miesiąc.

.EXAMPLE
    USBG Install

    Instaluje USB Guard i włącza blokadę nośników USB.

.EXAMPLE
    USBG Add -Description "Pendrive Kadry" -Owner "Jan Kowalski"

    Wyświetla podłączone nośniki i dodaje wybrany do białej listy.

.EXAMPLE
    USBG Purge

    Czyści białą listę i usuwa z systemu niepodłączone nośniki. Przed wykonaniem prosi o potwierdzenie.

.EXAMPLE
    USBG Help Add

    Wyświetla opis akcji Add.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('Install', 'Uninstall', 'Status', 'List', 'Add', 'Remove', 'Purge', 'Report', 'Scan', 'Help')]
    [string]$Action,

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateSet('Install', 'Uninstall', 'Status', 'List', 'Add', 'Remove', 'Purge', 'Report', 'Scan', 'Help')]
    [string]$Topic,

    [string]$InstanceId,
    [string]$Description,
    [string]$Owner,

    [ValidatePattern('^\d{4}-(0[1-9]|1[0-2])$')]
    [string]$Month
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:DataPath = Join-Path $env:ProgramData 'USBGuard'
$script:Cfg = @{
    Version       = '1.5.2'
    EventSource   = 'USBGuard'
    EventLog      = 'Application'
    ProgramDir    = (Join-Path $env:ProgramFiles 'USBGuard')
    DataDir       = $script:DataPath
    LogDir        = (Join-Path $script:DataPath 'Logs')
    ReportDir     = (Join-Path $script:DataPath 'Reports')
    WhitelistFile = (Join-Path $script:DataPath 'whitelist.json')
    StateKey      = 'HKLM:\SOFTWARE\USBGuard'
    PolicyKey     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
    DenyDeviceIds = @('USB\Class_08')
    TaskPath      = '\USBGuard\'
    ScanTaskName  = 'USBGuard-Scan'
    MutexName     = 'Global\USBGuard'
    PnpAuditGuid  = '{0CCE9248-69AE-11D9-BED3-505054503030}'
    CsvDelimiter  = ';'
}

$script:EventId = @{
    TrustedConnected = 1001
    ReportGenerated  = 1100
    WhitelistChanged = 1200
    PolicySynced     = 1201
    PurgeCompleted   = 1202
    Blocked          = 2001
    UntrustedActive  = 3001
    ConsistencyError = 3100
    PolicyDrift      = 3101
    InternalError    = 3900
}

$script:ActionInfo = [ordered]@{
    Install   = @{
        Short   = 'instaluje program, włącza blokadę, dodaje skrót USBG i zadanie Scan'
        Details = @('Kopiuje skrypt do Program Files, dodaje katalog do PATH i skrót USBG do profilu PowerShell,',
                    'włącza blokadę i audyt PnP, rejestruje zadanie \USBGuard\USBGuard-Scan i uruchamia Purge.')
        Params  = 'brak'
        Example = 'USBG Install'
    }
    Uninstall = @{
        Short   = 'wyłącza ochronę i usuwa program wraz z danymi, dziennikami i raportami'
        Details = @('Po potwierdzeniu słowem TAK usuwa zasady blokady, zadania, skrót USBG, wpis w PATH, program, dane,',
                    'dzienniki i raporty. Zablokowane wcześniej nośniki są odświeżane, aby od razu działały.')
        Params  = 'brak'
        Example = 'USBG Uninstall'
    }
    Status    = @{
        Short   = 'pokazuje stan blokady, spójność białej listy i zasad oraz podłączone nośniki'
        Details = @('Najpierw rejestruje zaległe próby podłączenia (Scan), potem pokazuje stan blokady,',
                    'wynik kontroli spójności białej listy i zasad oraz podłączone nośniki z informacją, czy są zaufane.')
        Params  = 'brak'
        Example = 'USBG Status'
    }
    List      = @{
        Short   = 'wyświetla białą listę'
        Details = @('Pokazuje nośniki z opisem, właścicielem i datą dodania oraz wynik kontroli spójności.')
        Params  = 'brak'
        Example = 'USBG List'
    }
    Add       = @{
        Short   = 'dodaje nośnik do białej listy (z listy podłączonych lub przez -InstanceId)'
        Details = @('Bez -InstanceId wyświetla podłączone nośniki do wyboru; z -InstanceId dodaje nośnik także niepodłączony.',
                    'Opis jest wymagany – jeśli go pominięto, skrypt o niego zapyta.')
        Params  = '-InstanceId, -Description, -Owner (wszystkie opcjonalne)'
        Example = 'USBG Add -Description "Pendrive Kadry" -Owner "Jan Kowalski"'
    }
    Remove    = @{
        Short   = 'usuwa nośnik z białej listy (z listy lub przez -InstanceId)'
        Details = @('Bez -InstanceId wyświetla białą listę do wyboru. Podłączony nośnik zostaje od razu odłączony i zablokowany.')
        Params  = '-InstanceId (opcjonalny)'
        Example = 'USBG Remove -InstanceId "USB\VID_13FE&PID_4200\123456"'
    }
    Purge     = @{
        Short   = 'czyści białą listę i usuwa z systemu niepodłączone nośniki USB'
        Details = @('Wyświetla listę zmian i prosi o potwierdzenie słowem TAK. Usuwa wpisy białej listy, wyjątki z zasad',
                    'i węzły niepodłączonych nośników; podłączone pomija. Przywraca spójność po zmianie pliku białej listy.')
        Params  = 'brak'
        Example = 'USBG Purge'
    }
    Report    = @{
        Short   = 'tworzy raport miesięczny HTML i CSV (-Month RRRR-MM)'
        Details = @('Raport zawiera podsumowanie według urządzeń, historię zdarzeń i białą listę.',
                    'Pliki trafiają do C:\ProgramData\USBGuard\Reports.')
        Params  = '-Month RRRR-MM (domyślnie poprzedni miesiąc)'
        Example = 'USBG Report -Month 2026-10'
    }
    Scan      = @{
        Short   = '(uruchamiana automatycznie) rejestruje próby podłączenia nośników'
        Details = @('Uruchamiana przez zadanie \USBGuard\USBGuard-Scan po zdarzeniu 6416 lub 6423 oraz przez Status i Report.',
                    'Zapisuje próby podłączenia nośników w logu, Dzienniku zdarzeń i dzienniku CSV.')
        Params  = 'brak'
        Example = 'USBG Scan'
    }
    Help      = @{
        Short   = 'wyświetla tę pomoc lub opis wybranej akcji'
        Details = @('Bez nazwy akcji wyświetla menu pomocy, z nazwą akcji – jej opis.')
        Params  = '<akcja> (opcjonalna)'
        Example = 'USBG Help Add'
    }
}

$script:ParamInfo = [ordered]@{
    '-InstanceId <ID>'      = 'identyfikator nośnika (Add, Remove)'
    '-Description <opis>'   = 'opis nośnika (Add)'
    '-Owner <właściciel>'   = 'właściciel lub dział (Add)'
    '-Month <RRRR-MM>'      = 'miesiąc raportu, domyślnie poprzedni (Report)'
}

$script:PurgeHint = 'Uruchom "USBG Purge", aby wyczyścić białą listę i przywrócić spójność.'
$script:EventSourceReady    = $null
$script:LastConsistencyNote = ''

function Show-UsbGuardMenu {
    Write-Host "=== USB Guard v$($script:Cfg.Version) – Pomoc i składnia ===" -ForegroundColor Cyan
    Write-Host "Użycie: USBG [Akcja] [Opcje]`n"
    Write-Host '  Przykład: USBG Install' -ForegroundColor Gray
    Write-Host "  Przykład: $($script:ActionInfo.Add.Example)`n" -ForegroundColor Gray
    Write-Host 'Dostępne akcje:' -ForegroundColor Yellow
    foreach ($k in $script:ActionInfo.Keys) { Write-Host ('  {0,-9} - {1}' -f $k, $script:ActionInfo[$k].Short) }
    Write-Host "`nParametry:" -ForegroundColor Yellow
    foreach ($k in $script:ParamInfo.Keys) { Write-Host ('  {0,-21} {1}' -f $k, $script:ParamInfo[$k]) }
    Write-Host "`nSzczegóły akcji: USBG Help <akcja>" -ForegroundColor Cyan
}

function Show-UsbGuardActionHelp {
    param([Parameter(Mandatory = $true)][string]$Name)
    $a = $script:ActionInfo[$Name]
    Write-Host ("USBG {0} – {1}" -f $Name, $a.Short) -ForegroundColor Cyan
    foreach ($line in $a.Details) { Write-Host "  $line" }
    Write-Host "  Parametry: $($a.Params)"
    Write-Host "  Przykład:  $($a.Example)"
}

function Get-ObjProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Invoke-WithLock {
    param([Parameter(Mandatory = $true)][scriptblock]$ScriptBlock, [int]$TimeoutSeconds = 30)
    $usbgMutex = $null
    $usbgAcquired = $false
    try {
        try {
            $sec = New-Object System.Security.AccessControl.MutexSecurity
            foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
                $sid  = New-Object System.Security.Principal.SecurityIdentifier($sidText)
                $rule = New-Object System.Security.AccessControl.MutexAccessRule($sid, 'FullControl', 'Allow')
                $sec.AddAccessRule($rule)
            }
            $created = $false
            $usbgMutex = [System.Threading.Mutex]::new($false, $script:Cfg.MutexName, [ref]$created, $sec)
        }
        catch {
            $usbgMutex = [System.Threading.Mutex]::new($false, $script:Cfg.MutexName)
        }
        try { $usbgAcquired = $usbgMutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds)) }
        catch [System.Threading.AbandonedMutexException] { $usbgAcquired = $true }
        if (-not $usbgAcquired) { throw "Nie udało się uzyskać blokady $($script:Cfg.MutexName) w ciągu $TimeoutSeconds s." }
        & $ScriptBlock
    }
    finally {
        if ($usbgMutex) {
            if ($usbgAcquired) { $usbgMutex.ReleaseMutex() }
            $usbgMutex.Dispose()
        }
    }
}

function Write-UsbGuardLog {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Info', 'Warning', 'Error')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [int]$EventId = 0
    )
    $line = '{0} [{1,-7}] [PID {2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $PID, $Message

    try {
        if (Test-Path -LiteralPath $script:Cfg.LogDir) {
            $logFile = Join-Path $script:Cfg.LogDir ('USBGuard_{0}.log' -f (Get-Date -Format 'yyyy-MM'))
            Invoke-WithLock { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 }
        }
    }
    catch { Write-Warning "Nie można zapisać logu tekstowego: $($_.Exception.Message)" }

    if ($EventId -gt 0) {
        try {
            if ($null -eq $script:EventSourceReady) {
                $script:EventSourceReady = [System.Diagnostics.EventLog]::SourceExists($script:Cfg.EventSource)
            }
            if ($script:EventSourceReady) {
                $type = switch ($Level) {
                    'Info'    { [System.Diagnostics.EventLogEntryType]::Information }
                    'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
                    'Error'   { [System.Diagnostics.EventLogEntryType]::Error }
                }
                [System.Diagnostics.EventLog]::WriteEntry($script:Cfg.EventSource, $Message, $type, $EventId)
            }
        }
        catch { Write-Warning "Nie można zapisać do Dziennika zdarzeń: $($_.Exception.Message)" }
    }

    switch ($Level) {
        'Info'    { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Host "BŁĄD: $Message" -ForegroundColor Red }
    }
}

function Get-InteractiveUser {
    try {
        $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) { return [string]$u }
    } catch { }
    return ''
}

function ConvertFrom-UsbInstanceId {
    param([Parameter(Mandatory = $true)][string]$InstanceId)
    $r = [ordered]@{
        InstanceId      = $InstanceId.Trim().ToUpperInvariant()
        VendorId        = ''
        ProductId       = ''
        Interface       = ''
        Serial          = ''
        HasUniqueSerial = $false
        IsValid         = $false
    }
    if ($r.InstanceId -match '^USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:&MI_([0-9A-F]{2}))?\\(.+)$') {
        $r.VendorId        = $Matches[1]
        $r.ProductId       = $Matches[2]
        $r.Interface       = [string]$Matches[3]
        $r.Serial          = $Matches[4]
        $r.HasUniqueSerial = ($r.Serial -notmatch '&') -and ($r.Interface -eq '')
        $r.IsValid         = $true
    }
    return [pscustomobject]$r
}

function Test-IsUsbStorageId {
    param([string[]]$CompatibleIds)
    foreach ($c in @($CompatibleIds)) {
        if ($c -and ($c -match '^USB\\Class_08(&|$)')) { return $true }
    }
    return $false
}

function Get-DevicePropertyValue {
    param([string]$Id, [string]$KeyName)
    try {
        $p = Get-PnpDeviceProperty -InstanceId $Id -KeyName $KeyName -ErrorAction Stop
        return $p.Data
    } catch { return $null }
}

function Get-UsbDeviceState {
    param([Parameter(Mandatory = $true)][string]$Id)
    try { $d = Get-PnpDevice -InstanceId $Id -ErrorAction Stop | Select-Object -First 1 }
    catch { $d = $null }
    if (-not $d) {
        return [pscustomobject]@{ Present = $false; Status = 'NotPresent' }
    }
    return [pscustomobject]@{
        Present = [bool](Get-ObjProp $d 'Present')
        Status  = [string]$d.Status
    }
}

function Get-UsbStorageDevice {
    param([switch]$IncludeNotPresent)
    if ($IncludeNotPresent) { $all = @(Get-PnpDevice -ErrorAction SilentlyContinue) }
    else                    { $all = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue) }

    foreach ($d in $all) {
        if (-not $d -or $d.InstanceId -notlike 'USB\*') { continue }
        $compat = @(Get-ObjProp $d 'CompatibleID')
        if (-not ($compat | Where-Object { $_ })) {
            $compat = @(Get-DevicePropertyValue -Id $d.InstanceId -KeyName 'DEVPKEY_Device_CompatibleIds')
        }
        if (-not (Test-IsUsbStorageId $compat)) { continue }

        $info = ConvertFrom-UsbInstanceId $d.InstanceId
        $name = Get-DevicePropertyValue -Id $d.InstanceId -KeyName 'DEVPKEY_Device_BusReportedDeviceDesc'
        if (-not $name) { $name = [string]$d.FriendlyName }

        [pscustomobject]@{
            InstanceId      = $info.InstanceId
            VendorId        = $info.VendorId
            ProductId       = $info.ProductId
            Serial          = $info.Serial
            HasUniqueSerial = $info.HasUniqueSerial
            Name            = [string]$name
            Status          = [string]$d.Status
        }
    }
}

function Set-UsbGuardSecureAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    foreach ($sid in @($system, $admins)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner($admins)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-UsbGuardStateKey {
    param([switch]$Remove)
    $leaf = Split-Path $script:Cfg.StateKey -Leaf
    $sw = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]'CreateSubKey, ReadKey')
    try {
        if ($Remove) { $sw.DeleteSubKeyTree($leaf, $false) }
        else { $sw.CreateSubKey($leaf).Close() }
    }
    finally { $sw.Close() }
}

function Initialize-UsbGuardStorage {
    foreach ($dir in @($script:Cfg.DataDir, $script:Cfg.LogDir, $script:Cfg.ReportDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
    Set-UsbGuardSecureAcl -Path $script:Cfg.DataDir
    if (-not (Test-Path $script:Cfg.StateKey)) { Set-UsbGuardStateKey }
}

function Test-UsbGuardInstalled {
    return (Test-Path -LiteralPath $script:Cfg.DataDir) -and (Test-Path -LiteralPath $script:Cfg.LogDir)
}

function Assert-UsbGuardInstalled {
    if (-not (Test-UsbGuardInstalled)) {
        throw "USB Guard nie jest zainstalowany (brak $($script:Cfg.DataDir)). Uruchom najpierw: USBG Install"
    }
}

function Get-StoredWhitelistHash {
    $p = Get-ItemProperty -Path $script:Cfg.StateKey -Name 'WhitelistSHA256' -ErrorAction SilentlyContinue
    if ($p) { return [string]$p.WhitelistSHA256 }
    return $null
}

function ConvertTo-IsoDateText {
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToString('s') }
    return [string]$Value
}

function ConvertTo-UsbWhitelistEntry {
    param([Parameter(Mandatory = $true)]$Entry)
    [pscustomobject][ordered]@{
        InstanceId      = [string](Get-ObjProp $Entry 'InstanceId')
        VendorId        = [string](Get-ObjProp $Entry 'VendorId')
        ProductId       = [string](Get-ObjProp $Entry 'ProductId')
        Serial          = [string](Get-ObjProp $Entry 'Serial')
        HasUniqueSerial = [bool](Get-ObjProp $Entry 'HasUniqueSerial')
        Name            = [string](Get-ObjProp $Entry 'Name')
        Description     = [string](Get-ObjProp $Entry 'Description')
        Owner           = [string](Get-ObjProp $Entry 'Owner')
        AddedBy         = [string](Get-ObjProp $Entry 'AddedBy')
        AddedOn         = ConvertTo-IsoDateText (Get-ObjProp $Entry 'AddedOn')
    }
}

function Read-UsbWhitelist {
    param([switch]$SkipConsistencyCheck)
    $file   = $script:Cfg.WhitelistFile
    $stored = Get-StoredWhitelistHash

    if (-not (Test-Path -LiteralPath $file)) {
        if ($stored -and -not $SkipConsistencyCheck) {
            throw [System.Security.SecurityException]::new('Brak spójności białej listy: plik został usunięty, choć w rejestrze istnieje jego skrót.')
        }
        return [pscustomobject]@{ Version = 1; Updated = ''; Devices = @() }
    }

    if (-not $SkipConsistencyCheck) {
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if (-not $stored -or $actual -ne $stored) {
            throw [System.Security.SecurityException]::new("Brak spójności białej listy: plik został zmieniony poza USB Guard (oczekiwany SHA-256: $stored, bieżący: $actual).")
        }
    }

    try { $obj = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Plik białej listy jest uszkodzony (niepoprawny JSON): $($_.Exception.Message) $script:PurgeHint" }

    $rawDevices = @()
    $raw = Get-ObjProp $obj 'Devices'
    if ($raw) { $rawDevices = @($raw) }

    $devices = foreach ($d in $rawDevices) {
        if ([string]::IsNullOrWhiteSpace([string](Get-ObjProp $d 'InstanceId'))) {
            throw "Plik białej listy zawiera wpis bez pola InstanceId. $script:PurgeHint"
        }
        ConvertTo-UsbWhitelistEntry $d
    }

    return [pscustomobject][ordered]@{
        Version = 1
        Updated = ConvertTo-IsoDateText (Get-ObjProp $obj 'Updated')
        Devices = @($devices | Sort-Object InstanceId)
    }
}

function Save-UsbWhitelist {
    param([Parameter(Mandatory = $true)]$Whitelist)
    $file = $script:Cfg.WhitelistFile

    $cleanDevices = foreach ($d in @($Whitelist.Devices)) { if ($d) { ConvertTo-UsbWhitelistEntry $d } }
    $data = [ordered]@{
        Version = 1
        Updated = (Get-Date).ToString('s')
        Devices = @($cleanDevices | Sort-Object InstanceId)
    }

    $json = ConvertTo-Json -InputObject $data -Depth 5
    $tmp  = "$file.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $file -Force

    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if (-not (Test-Path $script:Cfg.StateKey)) { Set-UsbGuardStateKey }
    Set-ItemProperty -Path $script:Cfg.StateKey -Name 'WhitelistSHA256' -Value $hash
    Set-ItemProperty -Path $script:Cfg.StateKey -Name 'WhitelistUpdated' -Value $data.Updated
}

function Find-WhitelistEntry {
    param($Whitelist, [string]$Id)
    if (-not $Whitelist -or -not $Id) { return $null }
    foreach ($d in @($Whitelist.Devices)) {
        if ($d -and ([string]$d.InstanceId -eq $Id)) { return $d }
    }
    return $null
}

function Add-UsbGuardJournalEntry {
    param(
        [Parameter(Mandatory = $true)][string]$EventType,
        [string]$Id = '',
        [string]$Name = '',
        [string]$DeviceOwner = '',
        [string]$Source = 'Admin',
        [string]$DeviceStatus = '',
        [string]$Details = '',
        [datetime]$Time = (Get-Date)
    )
    $vid = ''; $prod = ''; $sn = ''
    if ($Id) {
        $info = ConvertFrom-UsbInstanceId $Id
        $vid = $info.VendorId; $prod = $info.ProductId; $sn = $info.Serial
    }
    $rec = [pscustomobject][ordered]@{
        Timestamp    = $Time.ToString('yyyy-MM-ddTHH:mm:ss')
        Computer     = $env:COMPUTERNAME
        User         = Get-InteractiveUser
        EventType    = $EventType
        Source       = $Source
        InstanceId   = $Id
        VendorId     = $vid
        ProductId    = $prod
        Serial       = $sn
        Name         = $Name
        Owner        = $DeviceOwner
        DeviceStatus = $DeviceStatus
        Details      = $Details
    }
    try {
        $journal = Join-Path $script:Cfg.LogDir ('events_{0}.csv' -f $Time.ToString('yyyy-MM'))
        Invoke-WithLock { $rec | Export-Csv -LiteralPath $journal -Append -NoTypeInformation -Encoding UTF8 }
    }
    catch { Write-Warning "Nie można zapisać dziennika CSV: $($_.Exception.Message)" }
}

function Register-ConsistencyError {
    param([string]$Message)
    if ($Message -eq $script:LastConsistencyNote) { return }
    $script:LastConsistencyNote = $Message
    Write-UsbGuardLog -Level Error -EventId $script:EventId.ConsistencyError -Message "USB Guard: $Message Zasady systemowe nie zostały zmienione. $script:PurgeHint"
    Add-UsbGuardJournalEntry -EventType 'ConsistencyError' -Source 'Consistency' -Details $Message
}

function Set-RegistryList {
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$Values)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    $clean = @($Values | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $clean.Count; $i++) {
        Set-ItemProperty -LiteralPath $Path -Name ([string]($i + 1)) -Value $clean[$i] -Type String
    }
    $keep = 1..([Math]::Max($clean.Count, 1)) | ForEach-Object { [string]$_ }
    $item = Get-Item -LiteralPath $Path
    foreach ($n in @($item.GetValueNames())) {
        if ($clean.Count -eq 0 -or $keep -notcontains $n) {
            Remove-ItemProperty -LiteralPath $Path -Name $n -ErrorAction SilentlyContinue
        }
    }
}

function Get-PolicyAllowList {
    $key = Join-Path $script:Cfg.PolicyKey 'AllowInstanceIDs'
    if (-not (Test-Path -LiteralPath $key)) { return @() }
    $item = Get-Item -LiteralPath $key
    return @($item.GetValueNames() | ForEach-Object { ([string]$item.GetValue($_)).ToUpperInvariant() } | Where-Object { $_ })
}

function Test-DenyPolicyActive {
    $base = $script:Cfg.PolicyKey
    $p = Get-ItemProperty -Path $base -ErrorAction SilentlyContinue
    if (-not $p) { return $false }
    if ((Get-ObjProp $p 'AllowDenyLayered') -ne 1 -or (Get-ObjProp $p 'DenyDeviceIDs') -ne 1) { return $false }
    $key = Join-Path $base 'DenyDeviceIDs'
    if (-not (Test-Path -LiteralPath $key)) { return $false }
    $item = Get-Item -LiteralPath $key
    $vals = @($item.GetValueNames() | ForEach-Object { [string]$item.GetValue($_) })
    foreach ($req in $script:Cfg.DenyDeviceIds) { if ($vals -notcontains $req) { return $false } }
    return $true
}

function Sync-UsbGuardPolicy {
    param([Parameter(Mandatory = $true)]$Whitelist)

    $base = $script:Cfg.PolicyKey
    if (-not (Test-Path -LiteralPath $base)) { New-Item -Path $base -Force | Out-Null }

    $ids = @($Whitelist.Devices | ForEach-Object { ([string]$_.InstanceId).ToUpperInvariant() })

    Set-RegistryList -Path (Join-Path $base 'AllowInstanceIDs') -Values $ids
    Set-ItemProperty -LiteralPath $base -Name 'AllowInstanceIDs' -Value ([int]($ids.Count -gt 0)) -Type DWord
    Set-ItemProperty -LiteralPath $base -Name 'AllowDenyLayered' -Value 1 -Type DWord
    Set-RegistryList -Path (Join-Path $base 'DenyDeviceIDs') -Values $script:Cfg.DenyDeviceIds
    Set-ItemProperty -LiteralPath $base -Name 'DenyDeviceIDs' -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $base -Name 'DenyDeviceIDsRetroactive' -Value 0 -Type DWord

    $msgKey = Join-Path $base 'DeniedPolicy'
    if (-not (Test-Path -LiteralPath $msgKey)) { New-Item -Path $msgKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $msgKey -Name 'SimpleText' -Value 'USB Guard: nośnik nie jest autoryzowany' -Type String
    Set-ItemProperty -LiteralPath $msgKey -Name 'DetailText' -Value 'Ten nośnik USB nie znajduje się na liście zaufanych urządzeń.' -Type String

    Write-UsbGuardLog -Level Info -EventId $script:EventId.PolicySynced -Message ("USB Guard: zsynchronizowano zasady (dozwolonych instancji: {0})." -f $ids.Count)
}

function Test-UsbGuardConsistency {
    try { $wl = Read-UsbWhitelist }
    catch [System.Security.SecurityException] { Register-ConsistencyError $_.Exception.Message; return $false }

    $expected = @($wl.Devices | ForEach-Object { ([string]$_.InstanceId).ToUpperInvariant() })
    $actual   = @(Get-PolicyAllowList)
    $extra    = @($actual   | Where-Object { $expected -notcontains $_ })
    $missing  = @($expected | Where-Object { $actual -notcontains $_ })
    $denyOk   = Test-DenyPolicyActive

    if ($extra.Count -eq 0 -and $missing.Count -eq 0 -and $denyOk) {
        $script:LastConsistencyNote = ''
        return $true
    }

    $msg = 'Brak spójności zasad z białą listą.'
    if ($extra.Count)   { $msg += ' Wyjątki spoza białej listy: ' + ($extra -join ', ') + '.' }
    if ($missing.Count) { $msg += ' Brakujące wyjątki: ' + ($missing -join ', ') + '.' }
    if (-not $denyOk)   { $msg += ' Blokada USB\Class_08 jest wyłączona lub zmieniona.' }

    Write-UsbGuardLog -Level Error -EventId $script:EventId.PolicyDrift -Message "USB Guard: $msg $script:PurgeHint"
    Add-UsbGuardJournalEntry -EventType 'PolicyDrift' -Source 'Consistency' -Details $msg
    return $false
}

function Enable-PnpAudit {
    $out = & auditpol.exe /set "/subcategory:$($script:Cfg.PnpAuditGuid)" /success:enable 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-UsbGuardLog -Level Warning -Message "Nie udało się włączyć audytu PnP: $out"
    } else {
        Write-UsbGuardLog -Level Info -Message 'Włączono audyt zdarzeń Plug and Play (zdarzenia 6416 i 6423).'
    }
}

function Get-SecurityNewestRecordId {
    try { return [long](Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop).RecordId }
    catch { return [long]0 }
}

function Invoke-UsbGuardScan {
    param([switch]$Wait)
    #6423 – instalację zablokowały zasady; 6416 – urządzenie zostało zainstalowane.
    if ($Wait) { Start-Sleep -Seconds 5 }

    Invoke-WithLock {
        $newest = Get-SecurityNewestRecordId
        $p = Get-ItemProperty -Path $script:Cfg.StateKey -Name 'LastAuditRecordId' -ErrorAction SilentlyContinue
        if (-not $p) {
            Set-ItemProperty -Path $script:Cfg.StateKey -Name 'LastAuditRecordId' -Value $newest -Type QWord
            return
        }
        $last = [long]$p.LastAuditRecordId
        if ($newest -lt $last) { $last = 0 }

        try {
            $events = @(Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=6416 or EventID=6423) and (EventRecordID>$last)]]" -ErrorAction Stop | Sort-Object RecordId)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $events = @()
        }

        $wl = $null
        if ($events.Count -gt 0) {
            try { $wl = Read-UsbWhitelist }
            catch {
                if ($_.Exception -is [System.Security.SecurityException]) { Register-ConsistencyError $_.Exception.Message }
                try { $wl = Read-UsbWhitelist -SkipConsistencyCheck } catch { $wl = $null }
            }
        }

        $seen = @{}
        foreach ($ev in $events) {
            $last = [long]$ev.RecordId
            $data = @{}
            foreach ($d in @(([xml]$ev.ToXml()).Event.EventData.Data)) { $data[[string]$d.Name] = [string]$d.InnerText }

            $devId = ([string]$data['DeviceId']).Trim().ToUpperInvariant()
            if ($devId -notlike 'USB\*') { continue }
            if (-not (Test-IsUsbStorageId (([string]$data['CompatibleIds']) -split '\s+'))) { continue }
            $time = $ev.TimeCreated
            $key  = "$($ev.Id)|$devId"
            if ($seen.ContainsKey($key) -and ($time - $seen[$key]).TotalSeconds -le 60) { continue }
            $seen[$key] = $time

            $info = ConvertFrom-UsbInstanceId $devId
            $name = [string](Get-DevicePropertyValue -Id $devId -KeyName 'DEVPKEY_Device_BusReportedDeviceDesc')
            if (-not $name) { $name = [string]$data['DeviceDescription'] }
            $entry = Find-WhitelistEntry -Whitelist $wl -Id $devId
            $state = Get-UsbDeviceState -Id $devId
            $devOwner = ''
            if ($entry) { $devOwner = [string]$entry.Owner }
            if ($ev.Id -eq 6423) {
                $type = 'Blocked'; $level = 'Warning'; $what = 'zablokowano nieautoryzowany nośnik'
            }
            elseif ($entry) {
                $type = 'TrustedConnected'; $level = 'Info'; $what = 'podłączono zaufany nośnik'
            }
            else {
                $type = 'UntrustedActive'; $level = 'Error'; $what = 'AKTYWNY nieautoryzowany nośnik (blokada nie zadziałała)'
            }

            Write-UsbGuardLog -Level $level -EventId $script:EventId[$type] -Message ("USB Guard: {0}: {1} (VID={2}, PID={3}, SN={4}) [{5}], czas zdarzenia {6}." -f $what, $name, $info.VendorId, $info.ProductId, $info.Serial, $devId, $time.ToString('yyyy-MM-dd HH:mm:ss'))
            Add-UsbGuardJournalEntry -EventType $type -Id $devId -Name $name -DeviceOwner $devOwner -Source 'Audit' -DeviceStatus $state.Status -Details "Zdarzenie $($ev.Id) (rekord $($ev.RecordId))" -Time $time
        }

        if ($newest -gt $last) { $last = $newest }
        Set-ItemProperty -Path $script:Cfg.StateKey -Name 'LastAuditRecordId' -Value $last -Type QWord
    }
}

function Invoke-UsbGuardCatchUpScan {
    try { Invoke-UsbGuardScan }
    catch { Write-Warning "Nie udało się przetworzyć zdarzeń 6416 i 6423: $($_.Exception.Message)" }
}

function Add-UsbWhitelistEntries {
    param([Parameter(Mandatory = $true)][object[]]$Targets, [string]$Desc, [string]$DevOwner)

    $added = Invoke-WithLock {
        $w = Read-UsbWhitelist
        $new = @()
        foreach ($t in $Targets) {
            if (Find-WhitelistEntry -Whitelist $w -Id $t.InstanceId) { continue }
            $new += [pscustomobject][ordered]@{
                InstanceId      = $t.InstanceId
                VendorId        = $t.VendorId
                ProductId       = $t.ProductId
                Serial          = $t.Serial
                HasUniqueSerial = [bool]$t.HasUniqueSerial
                Name            = $t.Name
                Description     = $Desc
                Owner           = $DevOwner
                AddedBy         = "$env:USERDOMAIN\$env:USERNAME"
                AddedOn         = (Get-Date).ToString('s')
            }
        }
        if ($new.Count -gt 0) {
            $w.Devices = @($w.Devices) + $new
            Save-UsbWhitelist -Whitelist $w
            Sync-UsbGuardPolicy -Whitelist $w
        }
        , $new
    }

    foreach ($e in @($added)) {
        if (-not $e) { continue }
        Write-UsbGuardLog -Level Info -EventId $script:EventId.WhitelistChanged -Message "USB Guard: DODANO do białej listy [$($e.InstanceId)]"
        Add-UsbGuardJournalEntry -EventType 'WhitelistAdd' -Id $e.InstanceId -Name $e.Name -DeviceOwner $e.Owner -Source 'Admin' -Details $e.Description

        $state = Get-UsbDeviceState -Id $e.InstanceId
        if ($state.Present -and $state.Status -ne 'OK') {
            & pnputil.exe /remove-device $e.InstanceId | Out-Null
            & pnputil.exe /scan-devices | Out-Null
        }
    }
    return @($added)
}

function Add-UsbWhitelistDevice {
    $candidates = @(Get-UsbStorageDevice)
    $target = $null

    if ($InstanceId) {
        $info = ConvertFrom-UsbInstanceId $InstanceId
        if (-not $info.IsValid) { throw "Nieprawidłowy identyfikator: '$InstanceId'." }
        $target = $candidates | Where-Object { $_.InstanceId -eq $info.InstanceId } | Select-Object -First 1
        if (-not $target) {
            $target = [pscustomobject]@{
                InstanceId = $info.InstanceId; VendorId = $info.VendorId; ProductId = $info.ProductId
                Serial = $info.Serial; HasUniqueSerial = $info.HasUniqueSerial; Name = '(niepodłączony)'; Status = 'NotPresent'
            }
        }
    }
    else {
        if ($candidates.Count -eq 0) { throw 'Nie wykryto żadnego podłączonego nośnika USB.' }
        Write-Host "`nWykryte nośniki USB:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $candidates.Count; $i++) {
            $c = $candidates[$i]
            Write-Host ("  [{0}] {1}  VID={2} PID={3} SN={4}" -f $i, $c.Name, $c.VendorId, $c.ProductId, $c.Serial)
        }
        $sel = Read-Host "`nPodaj numer nośnika do autoryzacji"
        $idx = -1
        if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 0 -or $idx -ge $candidates.Count) { throw "Nieprawidłowy wybór." }
        $target = $candidates[$idx]
    }

    $desc = $Description
    if ([string]::IsNullOrWhiteSpace($desc)) { $desc = Read-Host 'Opis nośnika (wymagany)' }
    if ([string]::IsNullOrWhiteSpace($desc)) { throw 'Opis jest wymagany.' }
    $own = $Owner
    if ($null -eq $own) { $own = '' }

    $res = @(Add-UsbWhitelistEntries -Targets @($target) -Desc $desc -DevOwner $own | Where-Object { $_ })
    if ($res.Count -gt 0) {
        Write-Host "Autoryzowano: $($target.InstanceId)" -ForegroundColor Green
    } else {
        Write-Host "Urządzenie $($target.InstanceId) jest już na białej liście – nic nie zmieniono." -ForegroundColor Yellow
    }
}

function Remove-UsbWhitelistDevice {
    $wl = Read-UsbWhitelist
    if (-not $wl.Devices -or $wl.Devices.Count -eq 0) {
        throw 'Biała lista jest pusta. Brak urządzeń do usunięcia.'
    }

    $targetId = ''

    if ($InstanceId) {
        $targetId = (ConvertFrom-UsbInstanceId $InstanceId).InstanceId
    }
    else {
        Write-Host "`nUrządzenia na białej liście:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $wl.Devices.Count; $i++) {
            $d = $wl.Devices[$i]
            Write-Host ("  [{0}] {1}  Opis: {2}  ID={3}" -f $i, $d.Name, $d.Description, $d.InstanceId)
        }
        $sel = Read-Host "`nPodaj numer urządzenia do usunięcia"
        $idx = -1
        if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 0 -or $idx -ge $wl.Devices.Count) {
            throw "Nieprawidłowy wybór."
        }
        $targetId = $wl.Devices[$idx].InstanceId
    }

    $removed = Invoke-WithLock {
        $w = Read-UsbWhitelist
        $hit = Find-WhitelistEntry -Whitelist $w -Id $targetId
        if (-not $hit) { throw "Urządzenia $targetId nie ma na białej liście." }
        $w.Devices = @($w.Devices | Where-Object { [string]$_.InstanceId -ne $targetId })
        Save-UsbWhitelist -Whitelist $w
        Sync-UsbGuardPolicy -Whitelist $w
        $hit
    }

    & pnputil.exe /remove-device $targetId | Out-Null
    & pnputil.exe /scan-devices | Out-Null
    Write-UsbGuardLog -Level Info -EventId $script:EventId.WhitelistChanged -Message "USB Guard: USUNIĘTO z białej listy [$targetId]"
    Add-UsbGuardJournalEntry -EventType 'WhitelistRemove' -Id $targetId -Name ([string]$removed.Name) -DeviceOwner ([string]$removed.Owner) -Source 'Admin'
    Write-Host "Pomyślnie usunięto urządzenie z białej listy: $targetId" -ForegroundColor Green
}

function Show-UsbWhitelist {
    $ok = $true
    try { $wl = Read-UsbWhitelist }
    catch [System.Security.SecurityException] {
        $ok = $false
        Write-Warning "$($_.Exception.Message) $script:PurgeHint"
        $wl = Read-UsbWhitelist -SkipConsistencyCheck
    }
    Write-Host ("Biała lista: {0} urządzeń, spójność: {1}" -f @($wl.Devices).Count, $(if ($ok) { 'zachowana' } else { 'BRAK' })) -ForegroundColor Cyan
    $wl.Devices | Select-Object InstanceId, Name, Description, Owner, AddedBy, AddedOn | Format-Table -AutoSize -Wrap | Out-Host
}

function Invoke-UsbGuardPurge {
    param([switch]$DuringInstall)

    $wlEntries = @()
    $wlNote = ''
    try { $wlEntries = @((Read-UsbWhitelist).Devices) }
    catch {
        $wlNote = ' (lista niespójna – wpisy pokazano bez weryfikacji)'
        try { $wlEntries = @((Read-UsbWhitelist -SkipConsistencyCheck).Devices) }
        catch { $wlNote = ' (plik listy jest uszkodzony – zostanie zastąpiony pustą listą)' }
    }
    $policyExceptions = @(Get-PolicyAllowList)

    $connected    = @(Get-UsbStorageDevice)
    $connectedIds = @($connected | ForEach-Object { $_.InstanceId })
    $parents      = @(Get-UsbStorageDevice -IncludeNotPresent | Where-Object { $connectedIds -notcontains $_.InstanceId })
    $children     = @()
    foreach ($c in @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'USBSTOR\*' -or $_.InstanceId -like 'SCSI\*' })) {
        $parent = [string](Get-DevicePropertyValue -Id $c.InstanceId -KeyName 'DEVPKEY_Device_Parent')
        if ($parent -like 'USB\*' -and $connectedIds -notcontains $parent.ToUpperInvariant()) {
            $children += [pscustomobject]@{ InstanceId = [string]$c.InstanceId; Name = [string]$c.FriendlyName }
        }
    }
    $nodes = @($children) + @($parents)

    Write-Host "`n=== USB Guard – Purge ===" -ForegroundColor Cyan
    if ($DuringInstall) { Write-Host 'Instalacja: usunięcie z systemu nośników używanych przed włączeniem blokady.' }

    if ($wlEntries.Count -eq 0 -and -not $wlNote -and $policyExceptions.Count -eq 0 -and $nodes.Count -eq 0) {
        Write-Host 'Biała lista jest pusta i nie ma niepodłączonych nośników do usunięcia. Nic do zrobienia.' -ForegroundColor Green
        return
    }

    Write-Host ("`n1. Wyczyszczenie białej listy – wpisów: {0}{1}" -f $wlEntries.Count, $wlNote) -ForegroundColor Yellow
    foreach ($e in $wlEntries) { Write-Host ("   - {0}  [{1}]" -f $e.Name, $e.InstanceId) }
    Write-Host ("`n2. Usunięcie wyjątków z zasad systemowych – wyjątków: {0} (blokada pozostaje włączona)" -f $policyExceptions.Count) -ForegroundColor Yellow
    Write-Host ("`n3. Usunięcie z systemu niepodłączonych nośników – węzłów: {0}" -f $nodes.Count) -ForegroundColor Yellow
    foreach ($d in $parents)  { Write-Host ("   - {0}  [{1}]" -f $d.Name, $d.InstanceId) }
    foreach ($d in $children) { Write-Host ("   - {0}  [{1}] (dysk)" -f $d.Name, $d.InstanceId) }
    if ($connected.Count -gt 0) {
        Write-Host ("`nPominięte – obecnie podłączone ({0}). Działające nośniki będą działać także po ponownym podłączeniu; aby je zablokować, odłącz je i uruchom ponownie USBG Purge:" -f $connected.Count) -ForegroundColor Gray
        foreach ($d in $connected) { Write-Host ("   - {0}  [{1}]" -f $d.Name, $d.InstanceId) -ForegroundColor Gray }
    }

    $answer = Read-Host "`nWpisz TAK, aby wykonać Purge"
    if ($answer -ne 'TAK') {
        Write-UsbGuardLog -Level Info -Message 'USB Guard: Purge anulowany przez użytkownika.'
        return
    }

    Invoke-WithLock {
        $empty = [pscustomobject]@{ Version = 1; Updated = ''; Devices = @() }
        Save-UsbWhitelist -Whitelist $empty
        Sync-UsbGuardPolicy -Whitelist $empty
    }
    $script:LastConsistencyNote = ''
    foreach ($e in $wlEntries) {
        Add-UsbGuardJournalEntry -EventType 'WhitelistRemove' -Id $e.InstanceId -Name $e.Name -DeviceOwner $e.Owner -Source 'Purge'
    }

    $removed = 0; $failed = 0
    foreach ($d in $nodes) {
        $out = & pnputil.exe /remove-device $d.InstanceId 2>&1
        if ($LASTEXITCODE -eq 0) {
            $removed++
            $usbId = ''
            if ($d.InstanceId -like 'USB\*') { $usbId = $d.InstanceId }
            Add-UsbGuardJournalEntry -EventType 'Purged' -Id $usbId -Name $d.Name -Source 'Purge' -Details $d.InstanceId
        } else {
            $failed++
            Write-UsbGuardLog -Level Warning -Message "USB Guard Purge: nie udało się usunąć $($d.InstanceId): $out"
        }
    }

    Write-UsbGuardLog -Level Info -EventId $script:EventId.PurgeCompleted -Message ("USB Guard: Purge wykonany przez {0}\{1} – usunięto wpisów z białej listy: {2}, usunięto węzłów: {3}, błędów: {4}, pominięto podłączonych: {5}." -f $env:USERDOMAIN, $env:USERNAME, $wlEntries.Count, $removed, $failed, $connected.Count)
}

function ConvertTo-HtmlSafe {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-SafeCsvRecord {
    param([Parameter(ValueFromPipeline = $true)]$Record)
    process {
        $o = [ordered]@{}
        foreach ($p in $Record.PSObject.Properties) {
            $v = [string]$p.Value
            $v = $v -replace '[\r\n\t]+', ' '
            if ($v -match '^[=+\-@]') { $v = "'" + $v }
            $o[$p.Name] = $v
        }
        [pscustomobject]$o
    }
}

function Export-SafeCsv {
    param([object[]]$Rows, [string]$Path, [string[]]$Header)
    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) {
        $line = ($Header | ForEach-Object { '"' + $_ + '"' }) -join $script:Cfg.CsvDelimiter
        [System.IO.File]::WriteAllText($Path, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true)))
        return
    }
    $rows | ConvertTo-SafeCsvRecord | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Delimiter $script:Cfg.CsvDelimiter
}

function Get-UsbGuardEventLabel {
    param([string]$EventType)
    switch ($EventType) {
        'Blocked'            { return @('Zablokowano nieautoryzowany nośnik', 'red') }
        'UntrustedActive'    { return @('Aktywny nieautoryzowany nośnik', 'red') }
        'ConsistencyError'   { return @('Brak spójności białej listy', 'red') }
        'IntegrityViolation' { return @('Brak spójności białej listy', 'red') }
        'PolicyDrift'        { return @('Brak spójności zasad', 'red') }
        'DeviceDisabled'     { return @('Wyłączono nośnik (v1.0)', 'red') }
        'WhitelistAdd'       { return @('Dodano do białej listy', 'green') }
        'TrustedConnected'   { return @('Podłączono zaufany nośnik', 'green') }
        'ReportGenerated'    { return @('Wygenerowano raport', 'yellow') }
        'WhitelistRemove'    { return @('Usunięto z białej listy', 'gray') }
        'Purged'             { return @('Usunięto z systemu (Purge)', 'gray') }
        'Disconnected'       { return @('Odłączono nośnik (v1.0)', 'gray') }
        default              { return @($EventType, 'gray') }
    }
}

function ConvertTo-HtmlTableSafe {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [hashtable]$Headers,
        [string]$EmptyText = 'Brak danych.',
        [string]$BadgeColumn = '',
        [string[]]$MonoColumns = @(),
        [string[]]$NoWrapColumns = @('Time', 'First', 'Last', 'AddedOn')
    )
    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return "<p class='empty'>$(ConvertTo-HtmlSafe $EmptyText)</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="data"><thead><tr>')
    foreach ($c in $Columns) {
        $h = $c
        if ($Headers -and $Headers.ContainsKey($c)) { $h = $Headers[$c] }
        [void]$sb.Append('<th>' + (ConvertTo-HtmlSafe $h) + '</th>')
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        $cls = ConvertTo-HtmlSafe (Get-ObjProp $r 'BadgeClass')
        $rowAttr = ''
        if ($cls -eq 'red') { $rowAttr = ' class="red-row"' }
        [void]$sb.Append("<tr$rowAttr>")
        foreach ($c in $Columns) {
            $val = ConvertTo-HtmlSafe (Get-ObjProp $r $c)
            if ($c -eq $BadgeColumn -and $val) { $val = "<span class=""badge $cls"">$val</span>" }
            elseif ($MonoColumns -contains $c) { $val = "<span class=""mono"">$val</span>" }
            elseif ($NoWrapColumns -contains $c) { $val = "<span class=""nw"">$val</span>" }
            [void]$sb.Append("<td>$val</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-UsbGuardReport {
    param([string]$ReportMonth)
    if (-not $ReportMonth) { $ReportMonth = (Get-Date).AddMonths(-1).ToString('yyyy-MM') }
    $periodStart = [datetime]::ParseExact($ReportMonth, 'yyyy-MM', [System.Globalization.CultureInfo]::InvariantCulture)
    $periodEnd   = $periodStart.AddMonths(1).AddDays(-1)

    Invoke-UsbGuardCatchUpScan
    Add-UsbGuardJournalEntry -EventType 'ReportGenerated' -Source 'Admin' -Details "Raport za $ReportMonth"

    $events = New-Object System.Collections.Generic.List[object]
    $journal = Join-Path $script:Cfg.LogDir "events_$ReportMonth.csv"
    if (Test-Path -LiteralPath $journal) {
        foreach ($r in @(Import-Csv -LiteralPath $journal -Encoding UTF8)) { if ($r) { $events.Add($r) } }
    }

    $wl = $null
    $wlOk = $true
    try { $wl = Read-UsbWhitelist }
    catch {
        $wlOk = $false
        if ($_.Exception -is [System.Security.SecurityException]) { Register-ConsistencyError $_.Exception.Message }
        try { $wl = Read-UsbWhitelist -SkipConsistencyCheck } catch { $wl = [pscustomobject]@{ Version = 1; Updated = ''; Devices = @() } }
    }
    if ($wlOk) {
        $wlStatus = 'Zachowana'
        if (Test-UsbGuardConsistency) { $policyStatus = 'Zachowana' }
        else { $policyStatus = 'BRAK – zasady w rejestrze różnią się od białej listy. Uruchom USBG Purge.' }
    } else {
        $wlStatus     = 'BRAK – plik białej listy zmieniono poza USB Guard. Uruchom USBG Purge.'
        $policyStatus = 'Nie sprawdzono (biała lista niespójna)'
    }

    $rows = @(foreach ($e in @($events | Sort-Object Timestamp)) {
        $type = [string](Get-ObjProp $e 'EventType')
        $lbl  = Get-UsbGuardEventLabel -EventType $type
        [pscustomobject][ordered]@{
            Time       = ([string](Get-ObjProp $e 'Timestamp')) -replace 'T', ' '
            Event      = $lbl[0]
            BadgeClass = $lbl[1]
            EventType  = $type
            Name       = [string](Get-ObjProp $e 'Name')
            InstanceId = [string](Get-ObjProp $e 'InstanceId')
            Owner      = [string](Get-ObjProp $e 'Owner')
            User       = [string](Get-ObjProp $e 'User')
            Details    = [string](Get-ObjProp $e 'Details')
        }
    })

    $deviceRows = @($rows | Where-Object { $_.InstanceId -like 'USB\*' } | Group-Object InstanceId | ForEach-Object {
        $g = @($_.Group)
        $named = @($g | Where-Object { $_.Name })
        $nm = ''
        if ($named.Count -gt 0) { $nm = $named[-1].Name }
        $onList = 'Nie'
        if (Find-WhitelistEntry -Whitelist $wl -Id $_.Name) { $onList = 'Tak' }
        [pscustomobject][ordered]@{
            Name        = $nm
            InstanceId  = $_.Name
            OnWhitelist = $onList
            Blocked     = @($g | Where-Object { $_.EventType -eq 'Blocked' }).Count
            Trusted     = @($g | Where-Object { $_.EventType -eq 'TrustedConnected' }).Count
            First       = $g[0].Time
            Last        = $g[-1].Time
        }
    } | Sort-Object Name, InstanceId)

    $wlRows = @(foreach ($d in @($wl.Devices)) {
        [pscustomobject][ordered]@{
            Name        = $d.Name
            Description = $d.Description
            Owner       = $d.Owner
            VendorId    = $d.VendorId
            ProductId   = $d.ProductId
            Serial      = $d.Serial
            InstanceId  = $d.InstanceId
            AddedBy     = $d.AddedBy
            AddedOn     = ([string]$d.AddedOn) -replace 'T', ' '
        }
    })

    if (-not (Test-Path -LiteralPath $script:Cfg.ReportDir)) { New-Item -ItemType Directory -Path $script:Cfg.ReportDir -Force | Out-Null }
    $baseName     = "USBGuard_Report_{0}_{1}" -f $env:COMPUTERNAME, $ReportMonth
    $csvEvents    = Join-Path $script:Cfg.ReportDir "$baseName`_events.csv"
    $csvWhitelist = Join-Path $script:Cfg.ReportDir "$baseName`_whitelist.csv"
    $htmlPath     = Join-Path $script:Cfg.ReportDir "$baseName.html"

    $eventHeader     = @('Timestamp', 'Computer', 'User', 'EventType', 'Source', 'InstanceId', 'VendorId', 'ProductId', 'Serial', 'Name', 'Owner', 'DeviceStatus', 'Details')
    $whitelistHeader = @('InstanceId', 'Name', 'Description', 'Owner', 'VendorId', 'ProductId', 'Serial', 'AddedBy', 'AddedOn')
    Export-SafeCsv -Rows @($events | Sort-Object Timestamp) -Path $csvEvents -Header $eventHeader
    Export-SafeCsv -Rows @($wl.Devices) -Path $csvWhitelist -Header $whitelistHeader

    $hdr = @{
        Time = 'Czas'; Event = 'Typ'; Name = 'Nazwa'; InstanceId = 'Identyfikator'; Owner = 'Właściciel'
        User = 'Użytkownik'; Details = 'Szczegóły'; OnWhitelist = 'Na białej liście'
        Blocked = 'Zablokowane próby'; Trusted = 'Podłączenia zaufane'; First = 'Pierwsze zdarzenie'; Last = 'Ostatnie zdarzenie'
        Description = 'Opis'; VendorId = 'VID'; ProductId = 'PID'; Serial = 'Nr seryjny'; AddedBy = 'Dodał'; AddedOn = 'Data dodania'
    }
    $mono = @('InstanceId', 'VendorId', 'ProductId', 'Serial')

    $wlCls = 'ok';  if ($wlStatus -ne 'Zachowana')     { $wlCls = 'bad' }
    $polCls = 'ok'; if ($policyStatus -ne 'Zachowana') { $polCls = 'bad' }
    $pcName = ConvertTo-HtmlSafe $env:COMPUTERNAME

    $html = @"
<!DOCTYPE html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>USB Guard – raport $ReportMonth – $pcName</title>
<style>
body{font-family:"Segoe UI",Arial,sans-serif;margin:0;color:#1f2937;background:#f8fafc;line-height:1.45;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.page{max-width:1240px;margin:0 auto;padding:28px 24px 40px}
h1{font-size:22px;margin:0 0 16px}
h2{font-size:17px;margin:36px 0 4px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
.hint{color:#64748b;font-size:13px;margin:6px 0 10px}
.kv{border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;min-width:420px}
.kv th{background:#f1f5f9;text-align:left;font-weight:600;padding:7px 14px;width:260px;border-bottom:1px solid #e2e8f0}
.kv td{padding:7px 14px;border-bottom:1px solid #e2e8f0}
.ok{color:#15803d;font-weight:600}.bad{color:#b91c1c;font-weight:600}
nav{margin:18px 0 0;font-size:14px}nav a{color:#1d4ed8;text-decoration:none;margin-right:16px}
table.data{border-collapse:collapse;width:100%;table-layout:auto;background:#fff;font-size:13px}
.data th{background:#f1f5f9;text-align:left;padding:7px 8px;border:1px solid #e2e8f0}
.data td{padding:6px 8px;border:1px solid #e2e8f0;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
.data tr{page-break-inside:avoid}
.nw{white-space:nowrap}
.data tbody tr:nth-child(even){background:#f8fafc}
.data tr.red-row td{background:#fef2f2}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.badge.red{background:#fee2e2;color:#991b1b}.badge.green{background:#dcfce7;color:#166534}
.badge.yellow{background:#fef9c3;color:#854d0e}.badge.gray{background:#e2e8f0;color:#334155}
.legend{font-size:13px;margin:6px 0 10px}.legend .badge{margin-right:4px}.legend span.item{margin-right:16px;display:inline-block}
.mono{font-family:Consolas,"Courier New",monospace;font-size:12px;word-break:break-all}
.empty{color:#64748b;font-style:italic}
footer{margin-top:36px;color:#94a3b8;font-size:12px}
@media print{nav{display:none}body{background:#fff}.page{padding:0;max-width:none}}
</style></head><body><div class="page">
<h1>USB Guard – miesięczny raport bezpieczeństwa</h1>

<table class="kv">
<tr><th>Stacja</th><td>$pcName</td></tr>
<tr><th>Okres</th><td>$($periodStart.ToString('yyyy-MM-dd')) – $($periodEnd.ToString('yyyy-MM-dd'))</td></tr>
<tr><th>Wygenerowano</th><td>$(Get-Date -Format 'yyyy-MM-dd HH:mm')</td></tr>
<tr><th>Wersja USB Guard</th><td>$($script:Cfg.Version)</td></tr>
<tr><th>Spójność białej listy</th><td class="$wlCls">$(ConvertTo-HtmlSafe $wlStatus)</td></tr>
<tr><th>Spójność zasad z białą listą</th><td class="$polCls">$(ConvertTo-HtmlSafe $policyStatus)</td></tr>
<tr><th>Wpisy na białej liście</th><td>$(@($wl.Devices).Count)</td></tr>
</table>

<nav><a href="#urzadzenia">1. Podsumowanie według urządzeń</a><a href="#historia">2. Historia zdarzeń</a><a href="#lista">3. Biała lista</a></nav>

<h2 id="urzadzenia">1. Podsumowanie według urządzeń</h2>
<p class="hint">Każdy nośnik, którego dotyczyło co najmniej jedno zdarzenie w okresie. Kolumna „Na białej liście” pokazuje stan w chwili wygenerowania raportu.</p>
$(ConvertTo-HtmlTableSafe -Rows $deviceRows -Columns @('Name','InstanceId','OnWhitelist','Blocked','Trusted','First','Last') -Headers $hdr -MonoColumns $mono -EmptyText 'Brak zdarzeń dotyczących nośników w tym okresie.')

<h2 id="historia">2. Historia zdarzeń</h2>
<p class="legend"><span class="item"><span class="badge red">czerwony</span> nieautoryzowane podłączenie, brak spójności</span><span class="item"><span class="badge green">zielony</span> dodanie do białej listy, zaufany nośnik</span><span class="item"><span class="badge yellow">żółty</span> raport</span><span class="item"><span class="badge gray">szary</span> usunięcie z białej listy, Purge, pozostałe</span></p>
$(ConvertTo-HtmlTableSafe -Rows $rows -Columns @('Time','Event','Name','InstanceId','Owner','User','Details') -Headers $hdr -BadgeColumn 'Event' -MonoColumns $mono -EmptyText 'Brak zdarzeń w tym okresie.')

<h2 id="lista">3. Biała lista</h2>
<p class="hint">Stan z dnia wygenerowania raportu ($(Get-Date -Format 'yyyy-MM-dd')), a nie na koniec okresu.</p>
$(ConvertTo-HtmlTableSafe -Rows $wlRows -Columns @('Name','Description','Owner','VendorId','ProductId','Serial','InstanceId','AddedBy','AddedOn') -Headers $hdr -MonoColumns $mono -EmptyText 'Biała lista jest pusta.')

<footer>USB Guard $($script:Cfg.Version) · Pliki CSV: $(ConvertTo-HtmlSafe (Split-Path $csvEvents -Leaf)), $(ConvertTo-HtmlSafe (Split-Path $csvWhitelist -Leaf))</footer>
</div></body></html>
"@
    [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($true)))
    Write-UsbGuardLog -Level Info -EventId $script:EventId.ReportGenerated -Message "USB Guard: wygenerowano raport $ReportMonth ($htmlPath, $csvEvents, $csvWhitelist)."
    return [pscustomobject]@{ Html = $htmlPath; EventsCsv = $csvEvents; WhitelistCsv = $csvWhitelist }
}

function Remove-UsbGuardTasks {
    foreach ($t in @(Get-ScheduledTask -TaskPath $script:Cfg.TaskPath -ErrorAction SilentlyContinue)) {
        Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
        Write-UsbGuardLog -Level Info -Message "Usunięto zadanie harmonogramu: $($t.TaskPath)$($t.TaskName)"
    }
}

function Register-UsbGuardScanTask {
    param([Parameter(Mandatory = $true)][string]$ScriptPath)
    $xml = @"
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>USB Guard: rejestruje próby podłączenia nośników USB (zdarzenia 6416 i 6423).</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=6416 or EventID=6423)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$ScriptPath" -Action Scan</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $script:Cfg.ScanTaskName -TaskPath $script:Cfg.TaskPath -Xml $xml -Force | Out-Null
    Write-UsbGuardLog -Level Info -Message "Zarejestrowano zadanie harmonogramu: $($script:Cfg.TaskPath)$($script:Cfg.ScanTaskName)"
}

function Install-UsbGuard {
    Initialize-UsbGuardStorage
    if (-not (Test-Path -LiteralPath $script:Cfg.ProgramDir)) { New-Item -ItemType Directory -Path $script:Cfg.ProgramDir -Force | Out-Null }
    $dest = Join-Path $script:Cfg.ProgramDir 'USB_Guard.ps1'
    if ($PSCommandPath -and ($PSCommandPath -ne $dest)) { Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force }

    $sysPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    if ($sysPath -notlike "*$($script:Cfg.ProgramDir)*") {
        [Environment]::SetEnvironmentVariable("Path", $sysPath.TrimEnd(';') + ";$($script:Cfg.ProgramDir)", [EnvironmentVariableTarget]::Machine)
        Write-Host "Dodano $($script:Cfg.ProgramDir) do systemowej zmiennej PATH." -ForegroundColor Cyan
    }

    if (!(Test-Path $PROFILE)) { New-Item -Type File -Force $PROFILE | Out-Null }
    $profileLines  = @(Get-Content -Path $PROFILE -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch 'function\s+USBG\b' -and $_ -notmatch 'alias\s+USBG\b' })
    $profileLines += "function USBG { <# .FORWARDHELPTARGETNAME $dest #> & `"$dest`" @args }"
    [System.IO.File]::WriteAllText($PROFILE, ($profileLines -join [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($true)))

    if (-not [System.Diagnostics.EventLog]::SourceExists($script:Cfg.EventSource)) {
        [System.Diagnostics.EventLog]::CreateEventSource($script:Cfg.EventSource, $script:Cfg.EventLog)
    }
    $script:EventSourceReady = $true

    if (-not (Test-Path -LiteralPath $script:Cfg.WhitelistFile)) {
        Invoke-WithLock { Save-UsbWhitelist -Whitelist ([pscustomobject]@{ Version = 1; Updated = ''; Devices = @() }) }
    }
    $wl = Read-UsbWhitelist

    Enable-PnpAudit
    Sync-UsbGuardPolicy -Whitelist $wl

    Set-ItemProperty -Path $script:Cfg.StateKey -Name 'LastAuditRecordId' -Value (Get-SecurityNewestRecordId) -Type QWord
    Remove-UsbGuardTasks
    Register-UsbGuardScanTask -ScriptPath $dest

    Invoke-UsbGuardPurge -DuringInstall

    Write-Host "`n✅ USB Guard $($script:Cfg.Version) został pomyślnie zainstalowany!" -ForegroundColor Green
    $wlNow = Read-UsbWhitelist -SkipConsistencyCheck
    if (@($wlNow.Devices).Count -eq 0) {
        Write-Host 'Biała lista jest pusta. Aby autoryzować nośnik, użyj polecenia: USBG Add' -ForegroundColor Yellow
    }
    $untrusted = @(Get-UsbStorageDevice | Where-Object { $_.Status -eq 'OK' -and -not (Find-WhitelistEntry -Whitelist $wlNow -Id $_.InstanceId) })
    if ($untrusted.Count -gt 0) {
        Write-Host ("UWAGA: podłączone nośniki spoza białej listy ({0}) nadal działają, także po ponownym podłączeniu." -f $untrusted.Count) -ForegroundColor Red
        foreach ($d in $untrusted) { Write-Host ("   - {0}  [{1}]" -f $d.Name, $d.InstanceId) -ForegroundColor Red }
        Write-Host 'Aby je zablokować, odłącz je i uruchom: USBG Purge' -ForegroundColor Red
    }
    Write-Host "Otwórz nowe okno PowerShell (jako administrator) i użyj polecenia: USBG Status" -ForegroundColor Yellow
}

function Uninstall-UsbGuard {
    $tasks = @(Get-ScheduledTask -TaskPath $script:Cfg.TaskPath -ErrorAction SilentlyContinue)
    $blocked = @(Get-UsbStorageDevice -IncludeNotPresent | Where-Object {
        $_.Status -eq 'Error' -or -not (Get-DevicePropertyValue -Id $_.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath')
    })
    Write-Host "`n=== USB Guard – deinstalacja ===" -ForegroundColor Cyan
    Write-Host 'Zostaną usunięte:' -ForegroundColor Yellow
    Write-Host ("   - zasady blokady nośników USB (wyjątków: {0}) – wszystkie nośniki USB znów będą działać" -f @(Get-PolicyAllowList).Count)
    foreach ($t in $tasks) { Write-Host "   - zadanie harmonogramu $($t.TaskPath)$($t.TaskName)" }
    Write-Host "   - skrót USBG z profilu PowerShell ($PROFILE)"
    Write-Host "   - wpis $($script:Cfg.ProgramDir) w systemowej zmiennej PATH"
    Write-Host "   - program: $($script:Cfg.ProgramDir)"
    Write-Host "   - dane: $($script:Cfg.DataDir) (biała lista, dzienniki, RAPORTY)"
    Write-Host "   - stan w rejestrze ($($script:Cfg.StateKey -replace ':', '')), źródło $($script:Cfg.EventSource) w Dzienniku zdarzeń, audyt zdarzeń Plug and Play"
    Write-Host ("   - węzły zablokowanych nośników (zostaną wykryte od nowa): {0}" -f $blocked.Count)
    foreach ($d in $blocked) { Write-Host ("       {0}  [{1}]" -f $d.Name, $d.InstanceId) }
    Write-Host 'Dotychczasowe wpisy USB Guard w Dzienniku zdarzeń Windows pozostaną.' -ForegroundColor Gray

    $answer = Read-Host "`nWpisz TAK, aby odinstalować"
    if ($answer -ne 'TAK') {
        Write-UsbGuardLog -Level Info -Message 'USB Guard: deinstalacja anulowana przez użytkownika.'
        return
    }

    Remove-UsbGuardTasks

    $base = $script:Cfg.PolicyKey
    if (Test-Path -LiteralPath $base) {
        foreach ($v in @('AllowDenyLayered', 'DenyDeviceIDs', 'DenyDeviceIDsRetroactive', 'AllowInstanceIDs')) {
            Remove-ItemProperty -LiteralPath $base -Name $v -ErrorAction SilentlyContinue
        }
        foreach ($k in @('DenyDeviceIDs', 'AllowInstanceIDs', 'DeniedPolicy')) {
            $sub = Join-Path $base $k
            if (Test-Path -LiteralPath $sub) { Remove-Item -LiteralPath $sub -Recurse -Force }
        }
        foreach ($k in @($base, (Split-Path $base))) {
            $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
            if ($item -and $item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) { Remove-Item -LiteralPath $k -Force }
        }
    }

    foreach ($d in $blocked) { & pnputil.exe /remove-device $d.InstanceId | Out-Null }
    & pnputil.exe /scan-devices | Out-Null

    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $svc.GetFolder('\').DeleteFolder($script:Cfg.TaskPath.Trim('\'), 0)
    } catch { }

    if (Test-Path $PROFILE) {
        $profileLines = @(Get-Content -Path $PROFILE -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch 'function\s+USBG\b' -and $_ -notmatch 'alias\s+USBG\b' })
        [System.IO.File]::WriteAllText($PROFILE, ($profileLines -join [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($true)))
    }

    $sysPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    if ($sysPath -like "*$($script:Cfg.ProgramDir)*") {
        $newPaths = ($sysPath -split ';') | Where-Object { $_ -ne $script:Cfg.ProgramDir -and $_ -ne "$($script:Cfg.ProgramDir)\" }
        [Environment]::SetEnvironmentVariable("Path", ($newPaths -join ';'), [EnvironmentVariableTarget]::Machine)
        Write-Host "Usunięto ścieżkę z systemowej zmiennej PATH." -ForegroundColor Cyan
    }

    Write-UsbGuardLog -Level Warning -EventId $script:EventId.PolicySynced -Message "USB Guard: odinstalowano przez $env:USERDOMAIN\$env:USERNAME – blokada nośników USB WYŁĄCZONA."

    & auditpol.exe /set "/subcategory:$($script:Cfg.PnpAuditGuid)" /success:disable | Out-Null
    $script:EventSourceReady = $false
    if ([System.Diagnostics.EventLog]::SourceExists($script:Cfg.EventSource)) { [System.Diagnostics.EventLog]::DeleteEventSource($script:Cfg.EventSource) }
    if (Test-Path $script:Cfg.StateKey) { Set-UsbGuardStateKey -Remove }
    foreach ($dir in @($script:Cfg.DataDir, $script:Cfg.ProgramDir)) {
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    }
    Write-Host "USB Guard został pomyślnie odinstalowany wraz z danymi. Nośniki USB działają bez ograniczeń." -ForegroundColor Yellow
}

function Show-UsbGuardStatus {
    Write-Host "`n=== USB Guard $($script:Cfg.Version) – status ===" -ForegroundColor Cyan
    if (Test-UsbGuardInstalled) { Invoke-UsbGuardCatchUpScan }
    $denyOk = Test-DenyPolicyActive
    $wl = $null
    $wlStatus = 'Zachowana'
    try { $wl = Read-UsbWhitelist }
    catch {
        $wlStatus = "BRAK – $($_.Exception.Message)"
        if ($_.Exception -is [System.Security.SecurityException]) { Register-ConsistencyError $_.Exception.Message }
    }
    $policyStatus = 'Nie sprawdzono (biała lista niespójna)'
    if ($wl) {
        if (Test-UsbGuardConsistency) { $policyStatus = 'Zachowana' } else { $policyStatus = 'BRAK – uruchom USBG Purge' }
    }
    $allow = @(Get-PolicyAllowList)
    $wlCount = if ($wl) { @($wl.Devices).Count } else { 0 }

    [pscustomobject][ordered]@{
        'Blokada USB\Class_08 (warstwowa)' = $denyOk
        'Wyjątki w zasadach (rejestr)'     = $allow.Count
        'Urządzenia na białej liście'      = $wlCount
        'Spójność białej listy'            = $wlStatus
        'Spójność zasad z białą listą'     = $policyStatus
        'Katalog danych'                   = $script:Cfg.DataDir
    } | Format-List | Out-Host

    Write-Host 'Podłączone nośniki USB Mass Storage:' -ForegroundColor Cyan
    @(Get-UsbStorageDevice) | ForEach-Object {
        $v = 'NIEAUTORYZOWANY'
        if (Find-WhitelistEntry -Whitelist $wl -Id $_.InstanceId) { $v = 'zaufany' }
        [pscustomobject]@{ Werdykt = $v; Nazwa = $_.Name; Stan = $_.Status; InstanceId = $_.InstanceId }
    } | Format-Table -AutoSize | Out-Host
}

if (-not $Action) {
    Show-UsbGuardMenu
    exit 0
}
if ($Action -eq 'Help') {
    if ($Topic) { Show-UsbGuardActionHelp -Name $Topic } else { Show-UsbGuardMenu }
    exit 0
}

try {
    if ($Action -notin @('Install', 'Uninstall', 'Status')) { Assert-UsbGuardInstalled }

    switch ($Action) {
        'Install'   { Install-UsbGuard }
        'Uninstall' { Uninstall-UsbGuard }
        'Status'    { Show-UsbGuardStatus }
        'List'      { Show-UsbWhitelist }
        'Add'       { Add-UsbWhitelistDevice }
        'Remove'    { Remove-UsbWhitelistDevice }
        'Purge'     { Invoke-UsbGuardPurge }
        'Report'    { New-UsbGuardReport -ReportMonth $Month | Format-List | Out-Host }
        'Scan'      { Invoke-UsbGuardScan -Wait }
    }
    exit 0
}
catch [System.Security.SecurityException] {
    Register-ConsistencyError $_.Exception.Message
    exit 2
}
catch {
    Write-UsbGuardLog -Level Error -EventId $script:EventId.InternalError -Message ("USB Guard ({0}): {1}`n{2}" -f $Action, $_.Exception.Message, $_.ScriptStackTrace)
    exit 1
}
