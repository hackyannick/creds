#pragma once
#include <string>
#include <vector>
#include <windows.h>

// Konfiguration aus der Registry.
// Gelesen wird zuerst HKLM\SOFTWARE\Policies\ADFSCreds (GPO), dann HKLM\SOFTWARE\ADFSCreds.
struct Config {
    // --- ADFS ---
    std::wstring adfsUrl;          // z. B. https://sts.firma.de  (oder kompletter Endpunkt-URL)
    std::wstring relyingParty;     // Bezeichner der Vertrauensstellung, z. B. urn:adfscreds:windows
    std::wstring tokenType;        // SAML 2.0 (Standard) oder SAML 1.1
    std::wstring upnSuffix;        // wird an "max" angehängt -> "max@firma.de"
    std::wstring proxy;            // optional "proxy:8080"; leer = WinHTTP-Standard
    std::vector<std::wstring> pinnedThumbprints; // optionale SHA-1-Fingerabdrücke des ADFS-TLS-Zertifikats
    DWORD timeoutSeconds = 15;

    // --- Zuordnung zum lokalen Konto ---
    std::wstring localUserClaim;   // Claim, aus dem der lokale Kontoname abgeleitet wird
    std::wstring fullNameClaim;    // optional, Anzeigename
    std::wstring givenNameClaim;
    std::wstring surnameClaim;

    // --- Berechtigungen ---
    std::wstring adminClaim;                 // z. B. Rollen-/Gruppen-Claim
    std::vector<std::wstring> adminValues;   // Werte, die Admin-Rechte geben
    bool removeAdminIfNotMember = false;
    std::wstring requiredClaim;              // optional: Anmeldung nur mit diesem Claim ...
    std::vector<std::wstring> requiredValues;//          ... und einem dieser Werte

    // --- Verhalten ---
    bool createLocalUsers = true;
    bool allowOffline = true;       // Anmeldung mit lokalem Passwort, wenn ADFS nicht erreichbar ist
    DWORD mismatchAction = 0;       // 0 = altes lokales Passwort abfragen, 1 = sofort zurücksetzen
    bool hideOtherProviders = false;
    std::vector<std::wstring> hiddenProviders; // CLSIDs, die der Filter ausblendet
    std::vector<std::wstring> excludedUsers;   // lokale Konten, die nie angefasst werden

    // --- Oberfläche ---
    std::wstring title;
    std::wstring tileImagePath;     // optional .bmp
    std::wstring helpText;          // kleiner Hinweistext unter dem Formular

    DWORD logLevel = 3;

    static Config Load();
    std::wstring Endpoint() const;  // vollständiger usernamemixed-Endpunkt
    bool IsConfigured() const { return !adfsUrl.empty() && !relyingParty.empty(); }
};
