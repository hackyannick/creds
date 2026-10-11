#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <credentialprovider.h>
#include <string>
#include "Fields.h"
#include "Config.h"
#include "AdfsClient.h"

class Credential final : public ICredentialProviderCredential {
public:
    Credential();

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const Config& cfg);

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppszLabel) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppszItem) override;
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR psz) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

private:
    ~Credential();

    enum class Phase { Normal, NeedOldPassword };

    // Ergebnis eines Anmeldeschritts.
    struct Outcome {
        bool serialize = false;      // true -> Anmeldedaten an LogonUI übergeben
        std::wstring localUser;      // lokales Konto für die Serialisierung
        std::wstring error;          // Fehlermeldung für den Benutzer
        std::wstring info;           // Hinweis (z. B. bei Offline-Anmeldung)
        bool warning = false;        // Meldung als Warnung statt als Fehler anzeigen
    };

    Outcome DoOnlineLogon(const std::wstring& typed, const std::wstring& login, const std::wstring& password);
    Outcome DoOldPasswordStep();
    Outcome FinishSync();
    Outcome OfflineLogon(const std::wstring& typed, const std::wstring& reason);

    void SetPhase(Phase p);
    void SetInfo(const std::wstring& text);
    void SetField(DWORD id, const std::wstring& value);
    void ClearPending();

    LONG refs_ = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_ = CPUS_INVALID;
    Config cfg_;
    ICredentialProviderCredentialEvents* events_ = nullptr;

    FieldStatePair states_[FI_NUM_FIELDS];
    std::wstring values_[FI_NUM_FIELDS];
    bool resetChecked_ = false;

    // Zustand zwischen zwei Absende-Vorgängen (Passwort-Abgleich).
    Phase phase_ = Phase::Normal;
    std::wstring pendingTyped_;
    std::wstring pendingLocal_;
    std::wstring pendingPassword_;
    AdfsResult pendingResult_;
    int oldPasswordFailures_ = 0;
};
