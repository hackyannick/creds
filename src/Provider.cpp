#include "Provider.h"
#include "Credential.h"
#include "Dll.h"
#include "Fields.h"
#include "Log.h"
#include <new>
#include "Util.h"

namespace {

struct FieldDescriptor {
    DWORD id;
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    const wchar_t* label;
};

const FieldDescriptor kFields[FI_NUM_FIELDS] = {
    { FI_TILEIMAGE,      CPFT_TILE_IMAGE,     L"Bild" },
    { FI_TITLE,          CPFT_LARGE_TEXT,     L"Firmenanmeldung" },
    { FI_USERNAME,       CPFT_EDIT_TEXT,      L"Benutzername" },
    { FI_PASSWORD,       CPFT_PASSWORD_TEXT,  L"Kennwort" },
    { FI_OLD_PASSWORD,   CPFT_PASSWORD_TEXT,  L"Bisheriges Windows-Kennwort" },
    { FI_RESET_CHECKBOX, CPFT_CHECKBOX,       L"Zurücksetzen" },
    { FI_SUBMIT,         CPFT_SUBMIT_BUTTON,  L"Anmelden" },
    { FI_INFO,           CPFT_SMALL_TEXT,     L"Hinweis" },
};

} // namespace

Provider::Provider() { DllAddRef(); }

Provider::~Provider() {
    if (credential_) credential_->Release();
    DllRelease();
}

IFACEMETHODIMP_(ULONG) Provider::AddRef() { return InterlockedIncrement(&refs_); }

IFACEMETHODIMP_(ULONG) Provider::Release() {
    LONG c = InterlockedDecrement(&refs_);
    if (!c) delete this;
    return c;
}

IFACEMETHODIMP Provider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProvider)) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP Provider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) {
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        break;
    default:
        // CredUI (UAC, RDP-Client) und Kennwortänderung übernimmt weiterhin Windows.
        return E_NOTIMPL;
    }

    cpus_ = cpus;
    cfg_ = Config::Load();
    LOGI(L"SetUsageScenario(%d), ADFS-Endpunkt: %ls", (int)cpus, cfg_.IsConfigured() ? cfg_.Endpoint().c_str() : L"(nicht konfiguriert)");

    if (credential_) {
        credential_->Release();
        credential_ = nullptr;
    }
    credential_ = new (std::nothrow) Credential();
    if (!credential_) return E_OUTOFMEMORY;
    HRESULT hr = credential_->Initialize(cpus, cfg_);
    if (FAILED(hr)) {
        credential_->Release();
        credential_ = nullptr;
    }
    return hr;
}

IFACEMETHODIMP Provider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }

IFACEMETHODIMP Provider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }

IFACEMETHODIMP Provider::UnAdvise() { return S_OK; }

IFACEMETHODIMP Provider::GetFieldDescriptorCount(DWORD* pdwCount) {
    *pdwCount = FI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP Provider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (dwIndex >= FI_NUM_FIELDS || !ppcpfd) return E_INVALIDARG;
    auto* d = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!d) return E_OUTOFMEMORY;
    ZeroMemory(d, sizeof(*d));
    d->dwFieldID = kFields[dwIndex].id;
    d->cpft = kFields[dwIndex].type;
    d->guidFieldType = GUID_NULL;
    HRESULT hr = util::DupString(kFields[dwIndex].label, &d->pszLabel);
    if (FAILED(hr)) {
        CoTaskMemFree(d);
        return hr;
    }
    *ppcpfd = d;
    return S_OK;
}

IFACEMETHODIMP Provider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    *pdwCount = credential_ ? 1 : 0;
    *pdwDefault = credential_ ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP Provider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (dwIndex != 0 || !ppcpc || !credential_) return E_INVALIDARG;
    return credential_->QueryInterface(__uuidof(ICredentialProviderCredential), reinterpret_cast<void**>(ppcpc));
}

HRESULT Provider_CreateInstance(REFIID riid, void** ppv) {
    Provider* p = new (std::nothrow) Provider();
    if (!p) return E_OUTOFMEMORY;
    HRESULT hr = p->QueryInterface(riid, ppv);
    p->Release();
    return hr;
}
