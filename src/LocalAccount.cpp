#include "LocalAccount.h"
#include "Util.h"
#include "Log.h"
#include <lm.h>
#include <sddl.h>

namespace local {

namespace {

const wchar_t* kUsersKey = L"SOFTWARE\\ADFSCreds\\Users";
const wchar_t* kStateKey = L"SOFTWARE\\ADFSCreds\\State";

std::wstring AdministratorsGroupName() {
    // Name ist sprachabhängig ("Administratoren", "Administrators" ...), daher über die SID auflösen.
    PSID sid = nullptr;
    std::wstring result = L"Administrators";
    if (ConvertStringSidToSidW(L"S-1-5-32-544", &sid)) {
        wchar_t name[256], domain[256];
        DWORD cn = _countof(name), cd = _countof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, sid, name, &cn, domain, &cd, &use)) result = name;
        LocalFree(sid);
    }
    return result;
}

bool IsMemberOf(const std::wstring& user, const std::wstring& group) {
    LOCALGROUP_USERS_INFO_0* buf = nullptr;
    DWORD read = 0, total = 0;
    bool member = false;
    if (NetUserGetLocalGroups(nullptr, user.c_str(), 0, 0, reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
                              &read, &total) == NERR_Success) {
        for (DWORD i = 0; i < read; ++i)
            if (util::EqualsI(buf[i].lgrui0_name, group)) member = true;
    }
    if (buf) NetApiBufferFree(buf);
    return member;
}

std::wstring MappingKeyName(const std::wstring& typedLogin) {
    // '\' ist in Registry-Wertnamen erlaubt, aber wir normalisieren auf Kleinbuchstaben.
    return util::ToLower(util::Trim(typedLogin));
}

} // namespace

std::wstring ComputerName() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = _countof(buf);
    if (GetComputerNameW(buf, &n)) return buf;
    return L".";
}

std::wstring SanitizeName(const std::wstring& value) {
    std::wstring v = util::Trim(value);
    size_t bs = v.find_last_of(L'\\');
    if (bs != std::wstring::npos) v = v.substr(bs + 1);
    size_t at = v.find(L'@');
    if (at != std::wstring::npos) v = v.substr(0, at);

    static const std::wstring invalid = L"\"/\\[]:;|=,+*?<>@%";
    std::wstring out;
    for (wchar_t c : v) {
        if (c < 32 || invalid.find(c) != std::wstring::npos) continue;
        out += c;
    }
    while (!out.empty() && (out.back() == L'.' || out.back() == L' ')) out.pop_back();
    if (out.size() > 20) out.resize(20);  // Grenze für lokale SAM-Kontonamen
    return out;
}

std::wstring NameFromClaims(const Config& cfg, const AdfsResult& r, const std::wstring& typedLogin) {
    std::wstring v = r.First(cfg.localUserClaim);
    if (v.empty()) v = r.First(L"http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname");
    if (v.empty()) v = r.First(L"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");
    if (v.empty()) v = r.nameId;
    if (v.empty()) v = typedLogin;
    return SanitizeName(v);
}

std::wstring NameOffline(const std::wstring& typedLogin) {
    HKEY k;
    std::wstring result;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUsersKey, 0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        wchar_t buf[256] = {};
        DWORD cb = sizeof(buf) - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(k, MappingKeyName(typedLogin).c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf), &cb) ==
                ERROR_SUCCESS && type == REG_SZ)
            result = buf;
        RegCloseKey(k);
    }
    if (result.empty()) result = SanitizeName(typedLogin);
    return result;
}

void RememberMapping(const std::wstring& typedLogin, const std::wstring& localName) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kUsersKey, 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &k, nullptr) ==
        ERROR_SUCCESS) {
        RegSetValueExW(k, MappingKeyName(typedLogin).c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(localName.c_str()),
                       (DWORD)((localName.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kStateKey, 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &k, nullptr) ==
        ERROR_SUCCESS) {
        std::wstring t = util::Trim(typedLogin);
        RegSetValueExW(k, L"LastLogin", 0, REG_SZ, reinterpret_cast<const BYTE*>(t.c_str()),
                       (DWORD)((t.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
    }
}

std::wstring LastLogin() {
    HKEY k;
    std::wstring result;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStateKey, 0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        wchar_t buf[512] = {};
        DWORD cb = sizeof(buf) - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(k, L"LastLogin", nullptr, &type, reinterpret_cast<BYTE*>(buf), &cb) == ERROR_SUCCESS &&
            type == REG_SZ)
            result = buf;
        RegCloseKey(k);
    }
    return result;
}

bool IsExcluded(const Config& cfg, const std::wstring& name) {
    for (const auto& e : cfg.excludedUsers)
        if (util::EqualsI(e, name)) return true;

    // Eingebaute Konten (RID < 1000, z. B. Administrator 500, Gast 501) niemals anfassen.
    USER_INFO_23* info = nullptr;
    bool builtin = false;
    if (NetUserGetInfo(nullptr, name.c_str(), 23, reinterpret_cast<LPBYTE*>(&info)) == NERR_Success && info) {
        PSID sid = info->usri23_user_sid;
        if (sid && IsValidSid(sid)) {
            DWORD rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
            builtin = rid < 1000;
        }
    }
    if (info) NetApiBufferFree(info);
    return builtin;
}

bool Exists(const std::wstring& name) {
    USER_INFO_0* info = nullptr;
    NET_API_STATUS st = NetUserGetInfo(nullptr, name.c_str(), 0, reinterpret_cast<LPBYTE*>(&info));
    if (info) NetApiBufferFree(info);
    return st == NERR_Success;
}

DWORD Create(const std::wstring& name, const std::wstring& password, const std::wstring& fullName) {
    USER_INFO_1 ui = {};
    std::wstring pw = password;
    std::wstring comment = L"Verwaltet von ADFSCreds";
    ui.usri1_name = const_cast<LPWSTR>(name.c_str());
    ui.usri1_password = &pw[0];
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_comment = &comment[0];
    ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    DWORD parmErr = 0;
    NET_API_STATUS st = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &parmErr);
    util::Wipe(pw);
    if (st != NERR_Success) {
        LOGE(L"NetUserAdd(%ls) fehlgeschlagen: %lu (Parameter %lu)", name.c_str(), st, parmErr);
        return st;
    }
    LOGI(L"Lokales Konto '%ls' angelegt", name.c_str());

    // Mitgliedschaft in "Benutzer" sicherstellen (S-1-5-32-545).
    PSID usersSid = nullptr;
    if (ConvertStringSidToSidW(L"S-1-5-32-545", &usersSid)) {
        wchar_t group[256], domain[256];
        DWORD cg = _countof(group), cd = _countof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, usersSid, group, &cg, domain, &cd, &use)) {
            LOCALGROUP_MEMBERS_INFO_3 m;
            std::wstring qualified = ComputerName() + L"\\" + name;
            m.lgrmi3_domainandname = const_cast<LPWSTR>(qualified.c_str());
            NetLocalGroupAddMembers(nullptr, group, 3, reinterpret_cast<LPBYTE>(&m), 1);
        }
        LocalFree(usersSid);
    }

    if (!fullName.empty()) SetFullName(name, fullName);
    return NERR_Success;
}

DWORD VerifyPassword(const std::wstring& name, const std::wstring& password) {
    // Gesperrtes Konto entsperren – der Benutzer hat sich gerade erfolgreich bei ADFS angemeldet.
    USER_INFO_4* info = nullptr;
    if (NetUserGetInfo(nullptr, name.c_str(), 4, reinterpret_cast<LPBYTE*>(&info)) == NERR_Success && info) {
        bool changed = false;
        if (info->usri4_flags & UF_LOCKOUT) { info->usri4_flags &= ~UF_LOCKOUT; changed = true; }
        if (!(info->usri4_flags & UF_DONT_EXPIRE_PASSWD)) { info->usri4_flags |= UF_DONT_EXPIRE_PASSWD; changed = true; }
        if (info->usri4_password_expired) { info->usri4_password_expired = 0; changed = true; }
        if (info->usri4_flags & UF_ACCOUNTDISABLE) {
            NetApiBufferFree(info);
            return ERROR_ACCOUNT_DISABLED;
        }
        if (changed) {
            info->usri4_password = nullptr;  // Passwort nicht anfassen
            DWORD parmErr = 0;
            NET_API_STATUS st = NetUserSetInfo(nullptr, name.c_str(), 4, reinterpret_cast<LPBYTE>(info), &parmErr);
            LOGI(L"Kontoflags von '%ls' angepasst (Ergebnis %lu)", name.c_str(), st);
        }
        NetApiBufferFree(info);
    }

    HANDLE token = nullptr;
    std::wstring pw = password;
    BOOL ok = LogonUserW(name.c_str(), L".", pw.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    if (err == ERROR_LOGON_TYPE_NOT_GRANTED) {
        // Gehärtete Clients verweigern lokalen Konten oft die Netzwerkanmeldung -> interaktiv prüfen.
        ok = LogonUserW(name.c_str(), L".", pw.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
        err = ok ? ERROR_SUCCESS : GetLastError();
    }
    util::Wipe(pw);
    if (token) CloseHandle(token);
    LOGD(L"Prüfung lokales Passwort für '%ls': %lu", name.c_str(), err);
    return err;
}

DWORD ChangePassword(const std::wstring& name, const std::wstring& oldPassword, const std::wstring& newPassword) {
    NET_API_STATUS st = NetUserChangePassword(nullptr, name.c_str(), oldPassword.c_str(), newPassword.c_str());
    if (st == NERR_Success) LOGI(L"Lokales Passwort von '%ls' synchronisiert (geändert)", name.c_str());
    else LOGW(L"NetUserChangePassword(%ls): %lu", name.c_str(), st);
    return st;
}

DWORD ResetPassword(const std::wstring& name, const std::wstring& newPassword) {
    USER_INFO_1003 ui;
    std::wstring pw = newPassword;
    ui.usri1003_password = &pw[0];
    DWORD parmErr = 0;
    NET_API_STATUS st = NetUserSetInfo(nullptr, name.c_str(), 1003, reinterpret_cast<LPBYTE>(&ui), &parmErr);
    util::Wipe(pw);
    if (st == NERR_Success) LOGW(L"Lokales Passwort von '%ls' zurückgesetzt (DPAPI-Daten nicht mehr lesbar)", name.c_str());
    else LOGE(L"Zurücksetzen des Passworts von '%ls' fehlgeschlagen: %lu", name.c_str(), st);
    return st;
}

DWORD SetFullName(const std::wstring& name, const std::wstring& fullName) {
    USER_INFO_1011 ui;
    std::wstring fn = fullName;
    ui.usri1011_full_name = &fn[0];
    DWORD parmErr = 0;
    return NetUserSetInfo(nullptr, name.c_str(), 1011, reinterpret_cast<LPBYTE>(&ui), &parmErr);
}

DWORD SetAdministrator(const std::wstring& name, bool admin) {
    std::wstring group = AdministratorsGroupName();
    bool member = IsMemberOf(name, group);
    if (member == admin) return NERR_Success;

    LOCALGROUP_MEMBERS_INFO_3 m;
    std::wstring qualified = ComputerName() + L"\\" + name;
    m.lgrmi3_domainandname = const_cast<LPWSTR>(qualified.c_str());
    NET_API_STATUS st = admin ? NetLocalGroupAddMembers(nullptr, group.c_str(), 3, reinterpret_cast<LPBYTE>(&m), 1)
                              : NetLocalGroupDelMembers(nullptr, group.c_str(), 3, reinterpret_cast<LPBYTE>(&m), 1);
    LOGI(L"%ls '%ls' %ls Gruppe '%ls': %lu", admin ? L"Füge" : L"Entferne", name.c_str(), admin ? L"zur" : L"aus der",
         group.c_str(), st);
    return st;
}

} // namespace local
