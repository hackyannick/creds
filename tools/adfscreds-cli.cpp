// Kommandozeilenwerkzeug zum Testen der ADFS-Anbindung ohne Abmelden.
//
//   adfscreds-cli config                       wirksame Konfiguration anzeigen
//   adfscreds-cli test [benutzer]              Anmeldung gegen ADFS testen (ändert keine Konten)
//   adfscreds-cli parse <antwort.xml> [rp]     gespeicherte WS-Trust-Antwort auswerten
//
// Optionen für "test": --url <ADFS-URL>  --rp <RelyingParty>
#include "../src/AdfsClient.h"
#include "../src/Config.h"
#include "../src/LocalAccount.h"
#include "../src/Log.h"
#include "../src/Util.h"
#include <windows.h>
#include <objbase.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <io.h>
#include <fcntl.h>

namespace {

std::wstring ReadPassword() {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool console = GetConsoleMode(in, &mode) != 0;
    if (console) SetConsoleMode(in, mode & ~ENABLE_ECHO_INPUT);
    std::wstring pw;
    std::getline(std::wcin, pw);
    if (console) SetConsoleMode(in, mode);
    fwprintf(stdout, L"\n");
    return pw;
}

void PrintResult(const Config& cfg, const AdfsResult& r, const std::wstring& typed) {
    wprintf(L"Status:    %ls\n", StatusName(r.status));
    wprintf(L"Meldung:   %ls\n", r.message.c_str());
    if (r.status != AdfsResult::Ok) return;
    wprintf(L"NameID:    %ls\n", r.nameId.c_str());
    wprintf(L"Claims:\n");
    for (const auto& c : r.claims) wprintf(L"  %ls\n      = %ls\n", c.first.c_str(), c.second.c_str());
    wprintf(L"\nLokales Konto:   %ls\n", local::NameFromClaims(cfg, r, typed).c_str());
    if (!cfg.adminValues.empty())
        wprintf(L"Administrator:   %ls\n", r.Has(cfg.adminClaim, cfg.adminValues) ? L"ja" : L"nein");
    if (!cfg.requiredClaim.empty())
        wprintf(L"Zugelassen:      %ls\n", r.Has(cfg.requiredClaim, cfg.requiredValues) ? L"ja" : L"NEIN");
}

int Usage() {
    fwprintf(stderr,
             L"Verwendung:\n"
             L"  adfscreds-cli config\n"
             L"  adfscreds-cli test [benutzer] [--url URL] [--rp RELYINGPARTY]\n"
             L"  adfscreds-cli parse <antwort.xml> [relyingparty]\n");
    return 2;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (argc < 2) return Usage();

    Config cfg = Config::Load();
    std::wstring cmd = argv[1];

    if (cmd == L"config") {
        wprintf(L"AdfsUrl:            %ls\n", cfg.adfsUrl.c_str());
        wprintf(L"Endpunkt:           %ls\n", cfg.IsConfigured() ? cfg.Endpoint().c_str() : L"-");
        wprintf(L"RelyingParty:       %ls\n", cfg.relyingParty.c_str());
        wprintf(L"TokenType:          %ls\n", cfg.tokenType.c_str());
        wprintf(L"UpnSuffix:          %ls\n", cfg.upnSuffix.c_str());
        wprintf(L"LocalUserClaim:     %ls\n", cfg.localUserClaim.c_str());
        wprintf(L"AdminClaim:         %ls\n", cfg.adminClaim.c_str());
        for (const auto& v : cfg.adminValues) wprintf(L"  AdminValue:       %ls\n", v.c_str());
        wprintf(L"RequiredClaim:      %ls\n", cfg.requiredClaim.c_str());
        for (const auto& v : cfg.requiredValues) wprintf(L"  RequiredValue:    %ls\n", v.c_str());
        wprintf(L"CreateLocalUsers:   %d\n", cfg.createLocalUsers);
        wprintf(L"AllowOfflineLogon:  %d\n", cfg.allowOffline);
        wprintf(L"PasswordMismatch:   %lu\n", cfg.mismatchAction);
        wprintf(L"HideOtherProviders: %d\n", cfg.hideOtherProviders);
        for (const auto& v : cfg.pinnedThumbprints) wprintf(L"  Pin:              %ls\n", v.c_str());
        return 0;
    }

    if (cmd == L"test") {
        std::wstring user;
        for (int i = 2; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--url" && i + 1 < argc) cfg.adfsUrl = argv[++i];
            else if (a == L"--rp" && i + 1 < argc) cfg.relyingParty = argv[++i];
            else if (user.empty()) user = a;
            else return Usage();
        }
        logx::SetConsoleEcho(true);
        if (user.empty()) {
            wprintf(L"Benutzername: ");
            std::getline(std::wcin, user);
        }
        std::wstring login = util::Trim(user);
        if (login.find(L'@') == std::wstring::npos && login.find(L'\\') == std::wstring::npos && !cfg.upnSuffix.empty())
            login += L"@" + cfg.upnSuffix;
        wprintf(L"Kennwort für %ls: ", login.c_str());
        std::wstring pw = ReadPassword();

        AdfsClient client(cfg);
        AdfsResult r = client.Authenticate(login, pw);
        util::Wipe(pw);
        PrintResult(cfg, r, user);
        return r.status == AdfsResult::Ok ? 0 : 1;
    }

    if (cmd == L"parse" && argc >= 3) {
        std::ifstream f(argv[2], std::ios::binary);
        if (!f) {
            fwprintf(stderr, L"Datei nicht lesbar: %ls\n", argv[2]);
            return 2;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        if (argc >= 4) cfg.relyingParty = argv[3];
        AdfsClient client(cfg);
        AdfsResult r = client.ParseResponse(200, ss.str());
        PrintResult(cfg, r, L"");
        return r.status == AdfsResult::Ok ? 0 : 1;
    }

    return Usage();
}
