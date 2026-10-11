#include "Filter.h"
#include "Config.h"
#include "Dll.h"
#include "Log.h"
#include <new>

ProviderFilter::ProviderFilter() { DllAddRef(); }
ProviderFilter::~ProviderFilter() { DllRelease(); }

IFACEMETHODIMP_(ULONG) ProviderFilter::AddRef() { return InterlockedIncrement(&refs_); }

IFACEMETHODIMP_(ULONG) ProviderFilter::Release() {
    LONG c = InterlockedDecrement(&refs_);
    if (!c) delete this;
    return c;
}

IFACEMETHODIMP ProviderFilter::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderFilter)) {
        *ppv = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP ProviderFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD, GUID* rgclsidProviders,
                                      BOOL* rgbAllow, DWORD cProviders) {
    if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION) return S_OK;
    if (GetSystemMetrics(SM_CLEANBOOT) != 0) return S_OK;      // abgesicherter Modus
    if (GetSystemMetrics(SM_REMOTESESSION) != 0) return S_OK;  // RDP (NLA braucht den Kennwort-Provider)

    Config cfg = Config::Load();
    if (!cfg.hideOtherProviders || !cfg.IsConfigured()) return S_OK;

    for (DWORD i = 0; i < cProviders; ++i) {
        for (const auto& s : cfg.hiddenProviders) {
            CLSID clsid;
            if (SUCCEEDED(CLSIDFromString(s.c_str(), &clsid)) && IsEqualCLSID(clsid, rgclsidProviders[i])) {
                rgbAllow[i] = FALSE;
                LOGD(L"Filter: Provider %ls ausgeblendet", s.c_str());
            }
        }
    }
    return S_OK;
}

IFACEMETHODIMP ProviderFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,
                                                      CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) {
    return E_NOTIMPL;
}

HRESULT Filter_CreateInstance(REFIID riid, void** ppv) {
    ProviderFilter* f = new (std::nothrow) ProviderFilter();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}
