# ADFSCreds – XCreds-ähnliche Anmeldung für Windows mit ADFS 2.0

ADFSCreds ist ein **Windows Credential Provider** (eine DLL, die LogonUI lädt) und macht für Windows,
was [XCreds](https://twocanoes.com/products/mac/xcreds/) auf dem Mac macht:

* Der Benutzer meldet sich am Windows-Anmeldebildschirm mit seinem **Firmenkonto** an.
* Das Kennwort wird **online gegen ADFS 2.0** geprüft.
* Windows nutzt ein **lokales Konto**. ADFSCreds legt es beim ersten Mal an und hält es auf dem Stand des Firmenkontos
  (**Kennwort-Synchronisierung**, Anzeigename, Administratorrechte über Gruppen).
* Ohne Netzwerk oder wenn ADFS nicht erreichbar ist, funktioniert die **Offline-Anmeldung** mit dem zuletzt
  synchronisierten Kennwort.
* Hat sich das Firmenkennwort geändert, fragt ADFSCreds einmal nach dem **bisherigen Windows-Kennwort**. So werden
  gespeicherte Anmeldedaten (DPAPI, Anmeldeinformationsverwaltung, Browser-Kennwörter, EFS) mitgenommen. Das ist das
  Gegenstück zur Schlüsselbund-Synchronisierung von XCreds.

Der Computer muss dafür **nicht in der Domäne** sein.

```
 ┌──────────────┐  Benutzer + Kennwort  ┌──────────────────────┐   WS-Trust 1.3 (HTTPS)    ┌──────────────┐
 │  LogonUI     │ ────────────────────▶ │  ADFSCreds.dll       │ ────────────────────────▶ │  ADFS 2.0    │
 │  (Kachel)    │                       │  Credential Provider │ ◀──── SAML-Token/Claims ── │  (AD)        │
 └──────────────┘                       └─────────┬────────────┘                          └──────────────┘
                                                  │ lokales Konto anlegen / Kennwort synchronisieren /
                                                  │ Administratoren-Gruppe pflegen
                                                  ▼
                                         ┌──────────────────────┐
                                         │ LSA: Anmeldung am    │
                                         │ lokalen Konto        │
                                         └──────────────────────┘
```

## Warum WS-Trust und keine Web-Anmeldung wie bei XCreds?

XCreds zeigt eine OpenID-Connect-Webanmeldung an. **ADFS 2.0 kann kein OpenID Connect und kein OAuth2.** Das gibt es
erst ab ADFS 3.0 (2012 R2) bzw. ADFS 2016. ADFS 2.0 bietet stattdessen den WS-Trust-Endpunkt
`/adfs/services/trust/13/usernamemixed`. Dorthin schickt ADFSCreds Benutzername und Kennwort über TLS und erhält ein
SAML-Token mit den Claims des Benutzers. So lässt sich das Kennwort direkt in der Windows-Kachel eingeben, und das
lokale Kennwort kann synchronisiert werden. Eine Web-Anmeldung kann das grundsätzlich nicht, weil der Provider dabei
das Kennwort nie sieht.

## Funktionsumfang

| Funktion | Beschreibung |
|---|---|
| Online-Anmeldung | WS-Trust 1.3 `usernamemixed`, SAML 2.0- oder SAML 1.1-Token |
| Konto anlegen | Lokales Konto beim ersten Login (`CreateLocalUsers`) |
| Kennwort-Sync | Lokales Kennwort = Firmenkennwort. Bei Abweichung wird das bisherige Kennwort abgefragt (Option: zurücksetzen) |
| Offline-Anmeldung | ADFS nicht erreichbar → Anmeldung am lokalen Konto mit dem zuletzt synchronisierten Kennwort |
| Administratoren | Mitglieder bestimmter Gruppen/Rollen werden lokale Administratoren (optional auch wieder entfernt) |
| Zugriffsbeschränkung | Anmeldung nur mit bestimmtem Claim (zusätzlich zu ADFS-Autorisierungsregeln) |
| Entsperren | Funktioniert auch auf dem Sperrbildschirm |
| Notfallzugang | `.\Administrator` bzw. `COMPUTER\konto` wird ohne ADFS direkt an Windows weitergereicht |
| Andere Kacheln ausblenden | Optionaler Filter blendet die Windows-Kennwortkachel aus (nicht im abgesicherten Modus, nicht bei RDP) |
| Zertifikat-Pinning | Optionale Prüfung des ADFS-TLS-Zertifikats per SHA-1-Fingerabdruck. Das Kennwort wird erst nach erfolgreicher Prüfung gesendet |
| GPO-fähig | Konfiguration unter `HKLM\SOFTWARE\Policies\ADFSCreds` hat Vorrang |

## Repository-Inhalt

```
src/                          Credential Provider (C++/COM, nur Windows-APIs, keine Fremdbibliotheken)
  AdfsClient.*                WS-Trust-Client (WinHTTP) + Token-Auswertung (MSXML6)
  LocalAccount.*              Lokale Konten (NetUser*), Kennwort-Sync, Admin-Gruppe
  Credential.* / Provider.*   ICredentialProvider / ICredentialProviderCredential
  Filter.*                    ICredentialProviderFilter (optional)
  Serialization.*             KERB_INTERACTIVE_UNLOCK_LOGON für LogonUI
tools/adfscreds-cli.cpp       Testwerkzeug: ADFS-Anmeldung prüfen, ohne sich abzumelden
scripts/                      Installation, Deinstallation, ADFS-Einrichtung
config/ADFSCreds-Beispiel.reg Alle Einstellungen mit Erklärung
tests/                        Beispielantworten von ADFS + Testskript
```

## 1. ADFS 2.0 vorbereiten

Auf dem ADFS-Server als Administrator ausführen:

```powershell
.\scripts\Setup-AdfsRelyingParty.ps1
# oder nur für Mitglieder einer Gruppe:
.\scripts\Setup-AdfsRelyingParty.ps1 -AllowedGroupSid 'S-1-5-21-…-1234'
```

Das Skript

1. aktiviert den Endpunkt `/adfs/services/trust/13/usernamemixed`. Falls er aktiviert werden musste, danach den Dienst
   neu starten: `Restart-Service adfssrv`.
2. legt die Vertrauensstellung `urn:adfscreds:windows` **ohne Token-Verschlüsselung** an,
3. gibt folgende Claims aus: `windowsaccountname`, `upn`, `givenname`, `surname` und die Gruppen als `role`.

Manuell in der ADFS-2.0-Verwaltung geht es auch: *Vertrauensstellung der vertrauenden Seite hinzufügen →
Daten manuell eingeben → kein Verschlüsselungszertifikat → Bezeichner `urn:adfscreds:windows`*. Danach die Claim-Regeln
wie im Skript anlegen.

**Wichtig bei Windows Server 2008 R2:** Windows 10/11 verlangt TLS 1.2. Dieses Protokoll ist unter 2008 R2
standardmäßig ausgeschaltet. Einschalten (danach neu starten):

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
```

Sollen Clients sich auch von außen anmelden, muss der Endpunkt zusätzlich über den ADFS-Proxy veröffentlicht werden
(`Set-ADFSEndpoint -TargetAddressPath /adfs/services/trust/13/usernamemixed -Proxy $true`). Dann sollte auch eine
Kontosperrrichtlinie aktiv sein, weil der Endpunkt Kennwortversuche aus dem Internet annimmt.

## 2. Bauen

**Visual Studio 2019/2022** (Workload „Desktopentwicklung mit C++“):

```powershell
cmake -B build -A x64
cmake --build build --config Release
# -> build\Release\ADFSCreds.dll, build\Release\adfscreds-cli.exe
```

**Unter Linux per MinGW** (Cross-Compile):

```bash
sudo apt install g++-mingw-w64-x86-64-posix cmake
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake-mingw.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

GitHub Actions baut beide Varianten und stellt ein fertiges Paket (`ADFSCreds-x64`) als Artefakt bereit.

Für den produktiven Einsatz sollte die DLL mit einem Code-Signing-Zertifikat signiert werden
(`signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ADFSCreds.dll`).

## 3. Auf dem Client installieren

> **Bitte zuerst in einer VM mit Snapshot testen** und sicherstellen, dass ein lokales Administratorkonto bekannt ist.
> Ein fehlerhafter Credential Provider kann die Anmeldung verhindern. Notfalls hilft der abgesicherte Modus.

```powershell
# PowerShell (64 Bit) als Administrator, im Ordner mit ADFSCreds.dll und adfscreds-cli.exe
.\Install-ADFSCreds.ps1 -AdfsUrl https://sts.firma.de -RelyingParty urn:adfscreds:windows `
    -UpnSuffix firma.de -AdminValues 'Client-Admins'

# Verbindung testen, ohne sich abzumelden:
& "$env:ProgramFiles\ADFSCreds\adfscreds-cli.exe" test max.mustermann
```

`adfscreds-cli test` zeigt das Ergebnis, alle Claims, das zugeordnete lokale Konto und ob der Benutzer Administrator
wird. Dabei werden keine Konten verändert.

Deinstallation: `.\Uninstall-ADFSCreds.ps1` (`-RemoveConfig` löscht auch die Konfiguration). Die lokalen Konten bleiben
erhalten.

## 4. Konfiguration

Registry-Pfad: `HKLM\SOFTWARE\ADFSCreds`. Per GPO: `HKLM\SOFTWARE\Policies\ADFSCreds` (hat Vorrang).
Eine vollständige Vorlage liegt in [`config/ADFSCreds-Beispiel.reg`](config/ADFSCreds-Beispiel.reg).
Listen sind `REG_MULTI_SZ` oder `REG_SZ` mit `;` als Trennzeichen.

| Wert | Typ | Standard | Bedeutung |
|---|---|---|---|
| `AdfsUrl` | SZ | – | **Pflicht.** `https://sts.firma.de` (Pfad wird ergänzt) oder kompletter Endpunkt-URL |
| `RelyingParty` | SZ | – | **Pflicht.** Bezeichner der Vertrauensstellung |
| `UpnSuffix` | SZ | – | Wird an Eingaben ohne `@`/`\` angehängt (`max` → `max@firma.de`) |
| `TokenType` | SZ | `SAML2` | `SAML2` oder `SAML1` (bzw. vollständiger Token-Typ-URI) |
| `TimeoutSeconds` | DWORD | 15 | Zeitlimit für die ADFS-Anfrage |
| `PinnedCertThumbprints` | Liste | – | SHA-1-Fingerabdrücke des ADFS-TLS-Zertifikats |
| `Proxy` | SZ | – | `host:port`. Leer: WinHTTP-Einstellung (`netsh winhttp show proxy`) |
| `LocalUserClaim` | SZ | `…/claims/windowsaccountname` | Claim für den lokalen Kontonamen (Domäne/`@…` wird abgeschnitten, max. 20 Zeichen) |
| `FullNameClaim` | SZ | – | Claim für den Anzeigenamen. Leer: Vorname + Nachname |
| `GivenNameClaim` / `SurnameClaim` | SZ | `givenname` / `surname` | |
| `AdminClaim` | SZ | `…/claims/role` | Claim für die Administrator-Zuordnung |
| `AdminValues` | Liste | – | Werte (z. B. Gruppennamen), die lokale Adminrechte geben |
| `RemoveAdminIfNotMember` | DWORD | 0 | 1 = Adminrechte entziehen, wenn der Wert fehlt |
| `RequiredClaim` / `RequiredValues` | SZ / Liste | – | Anmeldung nur, wenn der Claim einen dieser Werte hat |
| `CreateLocalUsers` | DWORD | 1 | Fehlende lokale Konten anlegen |
| `AllowOfflineLogon` | DWORD | 1 | Anmeldung mit lokalem Kennwort, wenn ADFS nicht erreichbar ist |
| `PasswordMismatchAction` | DWORD | 0 | 0 = bisheriges Kennwort abfragen, 1 = lokales Kennwort sofort zurücksetzen |
| `HideOtherProviders` | DWORD | 0 | 1 = Kacheln aus `HiddenProviders` ausblenden |
| `HiddenProviders` | Liste | Windows-Kennwortprovider | CLSIDs der auszublendenden Provider |
| `ExcludedUsers` | Liste | – | Lokale Konten, die ADFSCreds nie verändert (eingebaute Konten sind immer ausgeschlossen) |
| `Title` / `HelpText` | SZ | | Texte auf der Kachel |
| `TileImage` | SZ | – | Pfad zu einer `.bmp` (z. B. 192×192) |
| `LogLevel` | DWORD | 3 | 1 Fehler … 4 Debug (bei 4 werden auch die Claims geloggt) |

Log-Datei: `%ProgramData%\ADFSCreds\adfscreds.log`. **Kennwörter werden nie geloggt.**

## Anmeldeablauf im Detail

1. Eingabe `max` → mit `UpnSuffix` wird `max@firma.de` daraus. Eingaben wie `FIRMA\max` gehen unverändert an ADFS.
   Eingaben mit `.\` oder `COMPUTERNAME\` gehen **ohne ADFS** an Windows (Notfallzugang).
2. WS-Trust-Anfrage an ADFS. Mögliche Ergebnisse:
   * **Kennwort falsch / Konto gesperrt:** Fehlermeldung. Es gibt *keine* Offline-Anmeldung.
   * **Durch Autorisierungsregel abgelehnt:** Fehlermeldung.
   * **ADFS nicht erreichbar** (kein Netz, Zeitüberschreitung, TLS-/Pinning-Fehler, Serverfehler): Offline-Anmeldung.
     Windows prüft das Kennwort gegen das lokale Konto.
3. Token prüfen: Gültigkeitszeitraum (±5 min), Audience = `RelyingParty`. Verschlüsselte Token werden mit einem
   Hinweis abgelehnt.
4. Lokales Konto bestimmen: `LocalUserClaim`, sonst `windowsaccountname`, `upn`, NameID.
5. Konto fehlt → anlegen (Mitglied von *Benutzer*, Kennwort läuft nicht ab).
   Konto vorhanden → Kennwort prüfen. Ist es anders:
   * Standard: Kachel fragt das **bisherige Windows-Kennwort** ab und ändert es per `NetUserChangePassword`. Die
     DPAPI-Schlüssel bleiben dabei erhalten.
   * Mit dem Haken „Bisheriges Kennwort vergessen“ oder `PasswordMismatchAction=1` wird das Kennwort zurückgesetzt.
     **Lokal verschlüsselte Daten des Benutzers sind danach verloren**, genau wie beim Zurücksetzen durch einen Admin.
6. Anzeigename und Administratoren-Gruppe abgleichen. Die Zuordnung „Eingabe → lokales Konto“ wird für spätere
   Offline-Anmeldungen gespeichert.
7. Die Anmeldedaten gehen an Windows (LSA), das den Benutzer am lokalen Konto anmeldet.

## Sicherheitshinweise

* Das Kennwort geht nur per **HTTPS ohne Weiterleitungen** an den konfigurierten ADFS-Server. Das Zertifikat wird
  von Windows geprüft und kann zusätzlich gepinnt werden. Mit Pinning wird das Kennwort erst *nach* der Prüfung
  übertragen.
* Das Token kommt direkt über diese TLS-Verbindung vom ADFS-Server und wird nicht von Dritten weitergereicht. Deshalb
  wird die XML-Signatur des Tokens nicht zusätzlich geprüft. Die Vertrauensbasis ist die TLS-Verbindung zum
  ADFS-Server (wie bei jedem WS-Trust-Client).
* **Mehrstufige Authentifizierung (MFA)** kann `usernamemixed` grundsätzlich nicht abbilden. Unter ADFS 2.0 gibt es
  ohnehin keine eingebaute MFA.
* Offline gilt das zuletzt synchronisierte Kennwort. Ein in AD gesperrtes Konto kann sich **ohne Netz** also weiter
  lokal anmelden, bis wieder eine Verbindung besteht. Wenn das nicht akzeptabel ist: `AllowOfflineLogon=0`.
* Eingebaute Konten (RID < 1000, z. B. Administrator) verändert ADFSCreds nie.
* Kennwörter werden im Speicher nach Gebrauch überschrieben und an LogonUI nur per `CredProtect` geschützt übergeben.

## Einschränkungen / bekannte Punkte

* Nur **x64**, getestet sind Windows 10/11 als Ziel. Anmeldung und Entsperren werden unterstützt. UAC-/CredUI-Dialoge
  und Kennwortänderung über Strg+Alt+Entf übernimmt weiterhin Windows.
* Das Firmenkennwort muss die lokale Kennwortrichtlinie erfüllen. Bei Standalone-Rechnern ist das praktisch immer so.
* Läuft das AD-Kennwort ab, meldet ADFS 2.0 nur „Anmeldung fehlgeschlagen“. Ändern muss der Benutzer es dann über
  ein anderes Werkzeug (z. B. OWA oder Self-Service).
* Bei RDP mit NLA wird die normale Windows-Kachel genutzt. Der Filter blendet in RDP-Sitzungen deshalb nichts aus.
* WLAN-Profile, die erst nach der Benutzeranmeldung verbinden, bieten am Anmeldebildschirm kein Netz. Dann greift die
  Offline-Anmeldung. Für die Erstanmeldung muss ein Netz vor der Anmeldung verfügbar sein (LAN, Maschinen-WLAN-Profil).

## Fehlersuche

| Symptom | Ursache / Lösung |
|---|---|
| Kachel erscheint nicht | `regsvr32 C:\Windows\System32\ADFSCreds.dll` erneut ausführen. Die DLL muss 64-Bit sein |
| „Anmeldeserver nicht erreichbar“ | `adfscreds-cli test` ausführen und Log prüfen. Häufige Ursachen: TLS 1.2 auf 2008 R2, Proxy, DNS |
| `TokenError … verschlüsselt` | In der Vertrauensstellung das Verschlüsselungszertifikat entfernen |
| `Audience … passt nicht` | `RelyingParty` muss exakt dem Bezeichner in ADFS entsprechen |
| `ServerError … ID3082` / `MSIS…` | Vertrauensstellung fehlt oder der Endpunkt ist deaktiviert |
| Token „noch nicht gültig“ / „abgelaufen“ | Uhrzeit von Client oder Server falsch (`w32tm /resync`) |
| Nichts geht mehr | Abgesicherter Modus → `Uninstall-ADFSCreds.ps1`. Oder mit `.\Administrator` anmelden |
