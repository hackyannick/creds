#include "Config.h"
#include "Util.h"
#include "Log.h"

namespace {

const wchar_t* kPolicyKey = L"SOFTWARE\\Policies\\ADFSCreds";
const wchar_t* kKey = L"SOFTWARE\\ADFSCreds";

class Reader {
public:
    Reader() {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPolicyKey, 0, KEY_READ | KEY_WOW64_64KEY, &policy_);
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ | KEY_WOW64_64KEY, &normal_);
    }
    ~Reader() {
        if (policy_) RegCloseKey(policy_);
        if (normal_) RegCloseKey(normal_);
    }

    std::wstring Str(const wchar_t* name, const std::wstring& def) {
        std::wstring v;
        if (ReadStr(policy_, name, &v) || ReadStr(normal_, name, &v)) return util::Trim(v);
        return def;
    }

    DWORD Dword(const wchar_t* name, DWORD def) {
        DWORD v;
        if (ReadDword(policy_, name, &v) || ReadDword(normal_, name, &v)) return v;
        return def;
    }

    bool Bool(const wchar_t* name, bool def) { return Dword(name, def ? 1 : 0) != 0; }

    // REG_MULTI_SZ oder REG_SZ mit ';'-getrennten Werten.
    std::vector<std::wstring> List(const wchar_t* name) {
        std::vector<std::wstring> out;
        if (!ReadList(policy_, name, &out)) ReadList(normal_, name, &out);
        return out;
    }

private:
    static bool ReadStr(HKEY k, const wchar_t* name, std::wstring* out) {
        if (!k) return false;
        DWORD type = 0, cb = 0;
        if (RegQueryValueExW(k, name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS) return false;
        if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
        std::wstring buf(cb / sizeof(wchar_t) + 1, L'\0');
        if (RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<BYTE*>(&buf[0]), &cb) != ERROR_SUCCESS)
            return false;
        buf.resize(wcslen(buf.c_str()));
        if (type == REG_EXPAND_SZ) {
            wchar_t exp[2048];
            if (ExpandEnvironmentStringsW(buf.c_str(), exp, _countof(exp))) buf = exp;
        }
        *out = buf;
        return true;
    }

    static bool ReadDword(HKEY k, const wchar_t* name, DWORD* out) {
        if (!k) return false;
        DWORD type = 0, cb = sizeof(DWORD);
        return RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<BYTE*>(out), &cb) == ERROR_SUCCESS &&
               type == REG_DWORD;
    }

    static bool ReadList(HKEY k, const wchar_t* name, std::vector<std::wstring>* out) {
        if (!k) return false;
        DWORD type = 0, cb = 0;
        if (RegQueryValueExW(k, name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS) return false;
        std::wstring buf(cb / sizeof(wchar_t) + 2, L'\0');
        if (RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<BYTE*>(&buf[0]), &cb) != ERROR_SUCCESS)
            return false;
        if (type == REG_MULTI_SZ) {
            for (const wchar_t* p = buf.c_str(); *p; p += wcslen(p) + 1) {
                std::wstring v = util::Trim(p);
                if (!v.empty()) out->push_back(v);
            }
        } else if (type == REG_SZ) {
            std::wstring s = buf.c_str();
            size_t start = 0;
            while (start <= s.size()) {
                size_t end = s.find(L';', start);
                if (end == std::wstring::npos) end = s.size();
                std::wstring v = util::Trim(s.substr(start, end - start));
                if (!v.empty()) out->push_back(v);
                start = end + 1;
            }
        } else {
            return false;
        }
        return true;
    }

    HKEY policy_ = nullptr;
    HKEY normal_ = nullptr;
};

} // namespace

Config Config::Load() {
    Reader r;
    Config c;
    c.adfsUrl        = r.Str(L"AdfsUrl", L"");
    c.relyingParty   = r.Str(L"RelyingParty", L"");
    c.tokenType      = r.Str(L"TokenType", L"urn:oasis:names:tc:SAML:2.0:assertion");
    c.upnSuffix      = r.Str(L"UpnSuffix", L"");
    c.proxy          = r.Str(L"Proxy", L"");
    c.pinnedThumbprints = r.List(L"PinnedCertThumbprints");
    c.timeoutSeconds = r.Dword(L"TimeoutSeconds", 15);

    c.localUserClaim = r.Str(L"LocalUserClaim", L"http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname");
    c.fullNameClaim  = r.Str(L"FullNameClaim", L"");
    c.givenNameClaim = r.Str(L"GivenNameClaim", L"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
    c.surnameClaim   = r.Str(L"SurnameClaim", L"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");

    c.adminClaim     = r.Str(L"AdminClaim", L"http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
    c.adminValues    = r.List(L"AdminValues");
    c.removeAdminIfNotMember = r.Bool(L"RemoveAdminIfNotMember", false);
    c.requiredClaim  = r.Str(L"RequiredClaim", L"");
    c.requiredValues = r.List(L"RequiredValues");

    c.createLocalUsers   = r.Bool(L"CreateLocalUsers", true);
    c.allowOffline       = r.Bool(L"AllowOfflineLogon", true);
    c.mismatchAction     = r.Dword(L"PasswordMismatchAction", 0);
    c.hideOtherProviders = r.Bool(L"HideOtherProviders", false);
    c.hiddenProviders    = r.List(L"HiddenProviders");
    if (c.hiddenProviders.empty()) c.hiddenProviders.push_back(L"{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}");
    c.excludedUsers      = r.List(L"ExcludedUsers");

    c.title         = r.Str(L"Title", L"Anmelden mit Firmenkonto");
    c.tileImagePath = r.Str(L"TileImage", L"");
    c.helpText      = r.Str(L"HelpText", L"");
    c.logLevel      = r.Dword(L"LogLevel", 3);

    if (c.tokenType == L"SAML2") c.tokenType = L"urn:oasis:names:tc:SAML:2.0:assertion";
    if (c.tokenType == L"SAML1") c.tokenType = L"urn:oasis:names:tc:SAML:1.0:assertion";

    logx::SetLevel((int)c.logLevel);
    return c;
}

std::wstring Config::Endpoint() const {
    std::wstring u = adfsUrl;
    if (!util::StartsWithI(u, L"https://") && !util::StartsWithI(u, L"http://")) u = L"https://" + u;
    // Nur Basis-URL angegeben -> Standardpfad von ADFS 2.0 ergänzen.
    if (u.find(L"/adfs/") == std::wstring::npos) {
        while (!u.empty() && u.back() == L'/') u.pop_back();
        u += L"/adfs/services/trust/13/usernamemixed";
    }
    return u;
}
