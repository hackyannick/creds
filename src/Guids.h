#pragma once
#include <windows.h>

// CLSID des Credential Providers.  {6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F01}
// Bei einem eigenen Fork bitte eine neue GUID erzeugen (z. B. mit [guid]::NewGuid()).
static const CLSID CLSID_AdfsCredentialProvider =
    { 0x6f7a3c2e, 0x4b1d, 0x4e8a, { 0x9c, 0x35, 0x1d, 0x2e, 0x7b, 0x8a, 0x9f, 0x01 } };

// CLSID des optionalen Filters, der andere Provider ausblendet.  {6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F02}
static const CLSID CLSID_AdfsCredentialProviderFilter =
    { 0x6f7a3c2e, 0x4b1d, 0x4e8a, { 0x9c, 0x35, 0x1d, 0x2e, 0x7b, 0x8a, 0x9f, 0x02 } };

#define ADFSCREDS_CLSID_STR        L"{6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F01}"
#define ADFSCREDS_FILTER_CLSID_STR L"{6F7A3C2E-4B1D-4E8A-9C35-1D2E7B8A9F02}"

// Microsofts eingebauter Passwort-Provider (wird vom Filter optional ausgeblendet).
static const CLSID CLSID_MsPasswordCredentialProvider =
    { 0x60b78e88, 0xead8, 0x445c, { 0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd } };
