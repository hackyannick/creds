<#
.SYNOPSIS
    Entfernt den ADFSCreds Credential Provider.  Lokale Benutzerkonten bleiben erhalten.
.PARAMETER RemoveConfig
    Löscht zusätzlich HKLM\SOFTWARE\ADFSCreds (Konfiguration und Konto-Zuordnungen).
#>
[CmdletBinding()]
param([switch]$RemoveConfig)

$ErrorActionPreference = 'Stop'
$dll = Join-Path $env:SystemRoot 'System32\ADFSCreds.dll'

if (Test-Path $dll) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\regsvr32.exe') -ArgumentList '/u', '/s', "`"$dll`"" -Wait | Out-Null
    $old = "$dll.removed-$(Get-Date -Format yyyyMMddHHmmss)"
    Rename-Item $dll $old
    Write-Host "Provider abgemeldet. $old kann nach dem nächsten Neustart gelöscht werden."
} else {
    # Falls die DLL schon fehlt: Registrierung trotzdem entfernen
    $clsids = '{6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F01}', '{6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F02}'
    foreach ($c in $clsids) {
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$c" -Recurse -ErrorAction SilentlyContinue
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\$c" -Recurse -ErrorAction SilentlyContinue
        Remove-Item "Registry::HKEY_CLASSES_ROOT\CLSID\$c" -Recurse -ErrorAction SilentlyContinue
    }
}

Remove-Item (Join-Path $env:ProgramFiles 'ADFSCreds') -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveConfig) { Remove-Item 'HKLM:\SOFTWARE\ADFSCreds' -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'ADFSCreds wurde entfernt.' -ForegroundColor Green
