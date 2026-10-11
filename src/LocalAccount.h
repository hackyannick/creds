#pragma once
#include <windows.h>
#include <string>
#include "Config.h"
#include "AdfsClient.h"

// Verwaltung der lokalen Windows-Konten, die mit dem ADFS-Konto synchronisiert werden.
namespace local {

std::wstring ComputerName();

// Leitet aus einem Wert (UPN, DOMAIN\user, Name) einen gültigen lokalen Kontonamen ab.
std::wstring SanitizeName(const std::wstring& value);

// Lokaler Kontoname aus den Claims (LocalUserClaim -> windowsaccountname -> upn -> NameID -> Eingabe).
std::wstring NameFromClaims(const Config& cfg, const AdfsResult& r, const std::wstring& typedLogin);

// Lokaler Kontoname ohne ADFS (Offline): gespeicherte Zuordnung oder Ableitung aus der Eingabe.
std::wstring NameOffline(const std::wstring& typedLogin);

// Merkt sich die Zuordnung "eingegebener Name -> lokales Konto" für Offline-Anmeldungen.
void RememberMapping(const std::wstring& typedLogin, const std::wstring& localName);
std::wstring LastLogin();

bool  IsExcluded(const Config& cfg, const std::wstring& name);
bool  Exists(const std::wstring& name);
DWORD Create(const std::wstring& name, const std::wstring& password, const std::wstring& fullName);

// Prüft das lokale Passwort.  Liefert ERROR_SUCCESS, ERROR_LOGON_FAILURE, ...
// Ein gesperrtes Konto wird entsperrt, ein "muss geändert werden"-Flag zurückgesetzt.
DWORD VerifyPassword(const std::wstring& name, const std::wstring& password);

// Passwortwechsel mit altem Passwort (DPAPI-Schlüssel, gespeicherte Anmeldedaten bleiben erhalten).
DWORD ChangePassword(const std::wstring& name, const std::wstring& oldPassword, const std::wstring& newPassword);

// Administratives Zurücksetzen (DPAPI-geschützte Daten des Benutzers gehen verloren!).
DWORD ResetPassword(const std::wstring& name, const std::wstring& newPassword);

DWORD SetFullName(const std::wstring& name, const std::wstring& fullName);
DWORD SetAdministrator(const std::wstring& name, bool admin);

} // namespace local
