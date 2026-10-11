#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <credentialprovider.h>
#include <string>

// Verpackt Benutzer/Passwort als KERB_INTERACTIVE_UNLOCK_LOGON für LogonUI/LSA.
HRESULT BuildKerbSerialization(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                               const std::wstring& domain,
                               const std::wstring& user,
                               const std::wstring& password,
                               REFCLSID providerClsid,
                               CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
