<#
.SYNOPSIS
    Installiert den ADFSCreds Credential Provider auf einem Windows-Client.

.DESCRIPTION
    - kopiert ADFSCreds.dll nach %SystemRoot%\System32
    - kopiert adfscreds-cli.exe nach %ProgramFiles%\ADFSCreds
    - schreibt die Grundkonfiguration nach HKLM\SOFTWARE\ADFSCreds
    - registriert den Provider (regsvr32)

    WICHTIG: Zuerst in einer VM / mit Snapshot testen und sicherstellen, dass ein
    lokales Administratorkonto bekannt ist (Anmeldung jederzeit mit ".\Administrator").

.EXAMPLE
    .\Install-ADFSCreds.ps1 -AdfsUrl https://sts.firma.de -RelyingParty urn:adfscreds:windows `
        -UpnSuffix firma.de -AdminValues 'Client-Admins'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AdfsUrl,
    [string]$RelyingParty = 'urn:adfscreds:windows',
    [string]$UpnSuffix = '',
    [string[]]$AdminValues = @(),
    [string[]]$RequiredValues = @(),
    [string]$RequiredClaim = '',
    [string[]]$PinnedCertThumbprints = @(),
    [string]$Title = 'Anmelden mit Firmenkonto',
    [switch]$HideOtherProviders,
    [switch]$NoOfflineLogon,
    [string]$SourceDir = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Bitte in einer PowerShell "Als Administrator ausführen" starten.'
}
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'Bitte die 64-Bit-PowerShell verwenden (der Provider ist eine 64-Bit-DLL).'
}

function Find-File($name) {
    foreach ($dir in @($SourceDir, (Join-Path $SourceDir '..'), (Join-Path $SourceDir '..\build\Release'), (Join-Path $SourceDir '..\build'))) {
        $p = Join-Path $dir $name
        if (Test-Path $p) { return (Resolve-Path $p).Path }
    }
    throw "$name nicht gefunden (SourceDir: $SourceDir)"
}

$dll = Find-File 'ADFSCreds.dll'
$cli = Find-File 'adfscreds-cli.exe'

# --- Dateien kopieren -------------------------------------------------------
$target = Join-Path $env:SystemRoot 'System32\ADFSCreds.dll'
if (Test-Path $target) {
    # Die DLL kann von LogonUI geladen sein -> umbenennen statt überschreiben.
    $old = "$target.old-$(Get-Date -Format yyyyMMddHHmmss)"
    Rename-Item $target $old
    Write-Host "Alte DLL umbenannt nach $old (kann nach dem Neustart gelöscht werden)."
}
Copy-Item $dll $target -Force

$progDir = Join-Path $env:ProgramFiles 'ADFSCreds'
New-Item -ItemType Directory -Force -Path $progDir | Out-Null
Copy-Item $cli (Join-Path $progDir 'adfscreds-cli.exe') -Force

# --- Konfiguration ------------------------------------------------------------
$key = 'HKLM:\SOFTWARE\ADFSCreds'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty $key -Name AdfsUrl -Value $AdfsUrl
Set-ItemProperty $key -Name RelyingParty -Value $RelyingParty
Set-ItemProperty $key -Name Title -Value $Title
if ($UpnSuffix) { Set-ItemProperty $key -Name UpnSuffix -Value $UpnSuffix }
if ($AdminValues.Count) { New-ItemProperty $key -Name AdminValues -PropertyType MultiString -Value $AdminValues -Force | Out-Null }
if ($RequiredClaim) { Set-ItemProperty $key -Name RequiredClaim -Value $RequiredClaim }
if ($RequiredValues.Count) { New-ItemProperty $key -Name RequiredValues -PropertyType MultiString -Value $RequiredValues -Force | Out-Null }
if ($PinnedCertThumbprints.Count) {
    New-ItemProperty $key -Name PinnedCertThumbprints -PropertyType MultiString -Value $PinnedCertThumbprints -Force | Out-Null
}
New-ItemProperty $key -Name HideOtherProviders -PropertyType DWord -Value ([int][bool]$HideOtherProviders) -Force | Out-Null
New-ItemProperty $key -Name AllowOfflineLogon -PropertyType DWord -Value ([int](-not $NoOfflineLogon)) -Force | Out-Null

# Nur SYSTEM und Administratoren dürfen die Konfiguration ändern (Standard für HKLM\SOFTWARE).

# --- Registrieren -------------------------------------------------------------
$p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\regsvr32.exe') -ArgumentList '/s', "`"$target`"" -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "regsvr32 fehlgeschlagen (Exit $($p.ExitCode))" }

Write-Host ''
Write-Host 'ADFSCreds wurde installiert.' -ForegroundColor Green
Write-Host "Verbindung testen (ohne Abmelden):  & '$progDir\adfscreds-cli.exe' test <benutzer>"
Write-Host "Log-Datei:                          $env:ProgramData\ADFSCreds\adfscreds.log"
