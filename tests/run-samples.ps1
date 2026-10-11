# Prüft die Auswertung von WS-Trust-Antworten mit adfscreds-cli (läuft in CI auf Windows).
param([Parameter(Mandatory)][string]$Cli)

$ErrorActionPreference = 'Stop'
$samples = Join-Path $PSScriptRoot 'samples'
$rp = 'urn:adfscreds:windows'

$cases = @(
    @{ File = 'saml2-ok.xml';          Exit = 0; Expect = @('Status:    Ok', 'Lokales Konto:   mmuster', 'Client-Admins') },
    @{ File = 'saml11-ok.xml';         Exit = 0; Expect = @('Status:    Ok', 'Lokales Konto:   max.mustermann') },
    @{ File = 'fault-badpassword.xml'; Exit = 1; Expect = @('Status:    InvalidCredentials') },
    @{ File = 'encrypted.xml';         Exit = 1; Expect = @('Status:    TokenError') }
)

$failed = 0
foreach ($c in $cases) {
    $out = & $Cli parse (Join-Path $samples $c.File) $rp 2>&1 | Out-String
    $ok = ($LASTEXITCODE -eq $c.Exit)
    foreach ($e in $c.Expect) { if ($out -notlike "*$e*") { $ok = $false } }
    if ($ok) { Write-Host "OK    $($c.File)" }
    else { Write-Host "FEHLER $($c.File) (Exit $LASTEXITCODE)`n$out"; $failed++ }
}

# Falsche Audience muss abgelehnt werden
$out = & $Cli parse (Join-Path $samples 'saml2-ok.xml') 'urn:anderer' 2>&1 | Out-String
if ($LASTEXITCODE -eq 1 -and $out -like '*TokenError*') { Write-Host 'OK    falsche Audience' }
else { Write-Host "FEHLER falsche Audience`n$out"; $failed++ }

if ($failed) { throw "$failed Test(s) fehlgeschlagen" }

Write-Host "Alle Tests bestanden."
exit 0
