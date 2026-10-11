#pragma once
#include <string>
#include <vector>
#include <utility>
#include "Config.h"

// Authentifizierung gegen ADFS 2.0 über WS-Trust 1.3 (Endpunkt usernamemixed).
// Der Client spricht per TLS direkt mit dem ADFS-Server; das zurückgegebene
// SAML-Token wird ausgewertet, um Claims (UPN, Name, Gruppen ...) zu erhalten.
struct AdfsResult {
    enum Status {
        Ok,
        InvalidCredentials,  // Benutzer/Passwort falsch, Konto gesperrt/deaktiviert
        AccessDenied,        // ADFS-Autorisierungsregel hat abgelehnt
        NetworkError,        // ADFS nicht erreichbar (-> Offline-Anmeldung möglich)
        ServerError,         // ADFS erreichbar, aber unerwartete Antwort / Fehlkonfiguration
        TokenError,          // Token unbrauchbar (verschlüsselt, abgelaufen, falsche Audience ...)
        ConfigError,         // lokale Konfiguration fehlt/ungültig
    };

    Status status = ServerError;
    std::wstring message;    // technische Beschreibung für das Log
    std::wstring nameId;
    std::vector<std::pair<std::wstring, std::wstring>> claims; // (Claim-Typ, Wert)

    std::vector<std::wstring> Values(const std::wstring& claimType) const;
    std::wstring First(const std::wstring& claimType) const;
    bool Has(const std::wstring& claimType, const std::vector<std::wstring>& anyOf) const;
};

const wchar_t* StatusName(AdfsResult::Status s);

class AdfsClient {
public:
    explicit AdfsClient(const Config& cfg) : cfg_(cfg) {}

    // username: so wie eingegeben (ggf. bereits mit UPN-Suffix ergänzt)
    AdfsResult Authenticate(const std::wstring& username, const std::wstring& password) const;

    // Nur für Tests: wertet eine bereits empfangene SOAP-Antwort aus.
    AdfsResult ParseResponse(DWORD httpStatus, const std::string& body) const;

private:
    std::string BuildRequest(const std::wstring& endpoint, const std::wstring& username,
                             const std::wstring& password) const;
    const Config& cfg_;
};
