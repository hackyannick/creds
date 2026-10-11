<#
.SYNOPSIS
    Richtet auf dem ADFS-2.0-Server die Vertrauensstellung (Relying Party Trust) für ADFSCreds ein.

.DESCRIPTION
    Auf dem ADFS-2.0-Server (Windows Server 2008 / 2008 R2) als Administrator ausführen.
    - aktiviert den WS-Trust-1.3-Endpunkt /adfs/services/trust/13/usernamemixed
    - legt die Vertrauensstellung ohne Token-Verschlüsselung an
    - gibt Kontoname, UPN, Vor-/Nachname und Gruppen (Rollen) als Claims aus
    - erlaubt die Anmeldung allen Benutzern oder nur Mitgliedern einer Gruppe

.EXAMPLE
    .\Setup-AdfsRelyingParty.ps1
.EXAMPLE
    .\Setup-AdfsRelyingParty.ps1 -AllowedGroupSid 'S-1-5-21-...-1234'
#>
[CmdletBinding()]
param(
    [string]$Name = 'Windows-Anmeldung (ADFSCreds)',
    [string]$Identifier = 'urn:adfscreds:windows',
    [string]$AllowedGroupSid = ''
)

$ErrorActionPreference = 'Stop'

# ADFS 2.0 liefert die Cmdlets als Snap-In, ab ADFS 3.0 als Modul.
if (-not (Get-Command Add-ADFSRelyingPartyTrust -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Adfs.PowerShell
}

# 1. Endpunkt aktivieren (ist unter ADFS 2.0 meist schon aktiv)
$ep = Get-ADFSEndpoint | Where-Object { $_.AddressPath -eq '/adfs/services/trust/13/usernamemixed' }
if (-not $ep) { throw 'Endpunkt /adfs/services/trust/13/usernamemixed nicht gefunden.' }
if (-not $ep.Enabled) {
    Enable-ADFSEndpoint -TargetAddressPath '/adfs/services/trust/13/usernamemixed'
    Write-Host 'Endpunkt usernamemixed aktiviert. Der ADFS-Dienst muss neu gestartet werden (adfssrv).' -ForegroundColor Yellow
}

# 2. Claim-Regeln
$transform = @'
@RuleName = "Windows-Kontoname durchreichen"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(claim = c);

@RuleTemplate = "LdapClaims"
@RuleName = "AD-Attribute"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory",
          types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
                   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                   "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"),
          query = ";userPrincipalName,givenName,sn,tokenGroups;{0}",
          param = c.Value);
'@

if ($AllowedGroupSid) {
    $authz = @"
@RuleName = "Nur Mitglieder der Gruppe"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "$AllowedGroupSid", Issuer == "AD AUTHORITY"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
"@
} else {
    $authz = @'
@RuleTemplate = "AllowAllAuthzRule"
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
'@
}

# 3. Vertrauensstellung anlegen bzw. aktualisieren (ohne Verschlüsselungszertifikat!)
$rp = Get-ADFSRelyingPartyTrust -Identifier $Identifier
if ($rp) {
    Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier -IssuanceTransformRules $transform -IssuanceAuthorizationRules $authz
    Write-Host "Vertrauensstellung '$($rp.Name)' aktualisiert."
} else {
    Add-ADFSRelyingPartyTrust -Name $Name -Identifier $Identifier -IssuanceTransformRules $transform `
        -IssuanceAuthorizationRules $authz
    Write-Host "Vertrauensstellung '$Name' angelegt."
}

Write-Host ''
Write-Host "Auf den Clients konfigurieren:  AdfsUrl = https://$((Get-ADFSProperties).HostName)   RelyingParty = $Identifier"
