#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <credentialprovider.h>

// Blendet optional andere Provider (z. B. den Windows-Kennwort-Provider) aus,
// damit nur noch die ADFS-Anmeldung angeboten wird.  Aktiv nur mit HideOtherProviders=1,
// nie im abgesicherten Modus, nie in Remotedesktop-Sitzungen und nie in CredUI.
class ProviderFilter final : public ICredentialProviderFilter {
public:
    ProviderFilter();

    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders,
                          BOOL* rgbAllow, DWORD cProviders) override;
    IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
                                          CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut) override;

private:
    ~ProviderFilter();
    LONG refs_ = 1;
};

HRESULT Filter_CreateInstance(REFIID riid, void** ppv);
