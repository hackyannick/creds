#include "Serialization.h"
#include "Util.h"
#include <wincred.h>
#include <vector>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace {

// Verschlüsselt das Passwort mit CredProtect (nur für den angemeldeten Kontext lesbar),
// so wie es Microsofts Beispiel-Provider für Anmeldung und Entsperren macht.
HRESULT ProtectPassword(const std::wstring& password, std::wstring* out) {
    if (password.empty()) { out->clear(); return S_OK; }

    CRED_PROTECTION_TYPE type;
    std::wstring copy = password;
    if (CredIsProtectedW(&copy[0], &type) && type != CredUnprotected) {
        *out = copy;
        util::Wipe(copy);
        return S_OK;
    }

    DWORD cch = 0;
    CredProtectW(FALSE, &copy[0], (DWORD)copy.size() + 1, nullptr, &cch, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || cch == 0) {
        util::Wipe(copy);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    std::wstring prot(cch, L'\0');
    if (!CredProtectW(FALSE, &copy[0], (DWORD)copy.size() + 1, &prot[0], &cch, nullptr)) {
        DWORD err = GetLastError();
        util::Wipe(copy);
        return HRESULT_FROM_WIN32(err);
    }
    util::Wipe(copy);
    prot.resize(wcslen(prot.c_str()));
    *out = prot;
    util::Wipe(prot);
    return S_OK;
}

HRESULT LookupNegotiatePackage(ULONG* package) {
    HANDLE lsa = nullptr;
    NTSTATUS st = LsaConnectUntrusted(&lsa);
    if (st != STATUS_SUCCESS) return HRESULT_FROM_NT(st);

    char name[] = "Negotiate";
    LSA_STRING ls;
    ls.Buffer = name;
    ls.Length = (USHORT)strlen(name);
    ls.MaximumLength = ls.Length + 1;
    st = LsaLookupAuthenticationPackage(lsa, &ls, package);
    LsaDeregisterLogonProcess(lsa);
    return st == STATUS_SUCCESS ? S_OK : HRESULT_FROM_NT(st);
}

} // namespace

HRESULT BuildKerbSerialization(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const std::wstring& domain,
                               const std::wstring& user, const std::wstring& password, REFCLSID providerClsid,
                               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    std::wstring prot;
    HRESULT hr = ProtectPassword(password, &prot);
    if (FAILED(hr)) return hr;

    const DWORD cbDomain = (DWORD)(domain.size() * sizeof(wchar_t));
    const DWORD cbUser = (DWORD)(user.size() * sizeof(wchar_t));
    const DWORD cbPass = (DWORD)(prot.size() * sizeof(wchar_t));
    if (cbDomain > 0xFFFF || cbUser > 0xFFFF || cbPass > 0xFFFF) { util::Wipe(prot); return E_INVALIDARG; }

    const DWORD cb = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbDomain + cbUser + cbPass;
    BYTE* buf = static_cast<BYTE*>(CoTaskMemAlloc(cb));
    if (!buf) { util::Wipe(prot); return E_OUTOFMEMORY; }
    ZeroMemory(buf, cb);

    auto* kiul = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buf);
    KERB_INTERACTIVE_LOGON* kil = &kiul->Logon;
    kil->MessageType = (cpus == CPUS_UNLOCK_WORKSTATION) ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;

    // Gepackte Form: Die Buffer-Zeiger enthalten Offsets relativ zum Anfang der Struktur.
    BYTE* p = buf + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    auto pack = [&](UNICODE_STRING* us, const std::wstring& s, DWORD cbs) {
        us->Length = (USHORT)cbs;
        us->MaximumLength = (USHORT)cbs;
        us->Buffer = reinterpret_cast<PWSTR>(p - buf);
        if (cbs) memcpy(p, s.data(), cbs);
        p += cbs;
    };
    pack(&kil->LogonDomainName, domain, cbDomain);
    pack(&kil->UserName, user, cbUser);
    pack(&kil->Password, prot, cbPass);
    util::Wipe(prot);

    ULONG package = 0;
    hr = LookupNegotiatePackage(&package);
    if (FAILED(hr)) {
        SecureZeroMemory(buf, cb);
        CoTaskMemFree(buf);
        return hr;
    }

    pcpcs->ulAuthenticationPackage = package;
    pcpcs->clsidCredentialProvider = providerClsid;
    pcpcs->cbSerialization = cb;
    pcpcs->rgbSerialization = buf;
    return S_OK;
}
