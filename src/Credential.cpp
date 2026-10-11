#include "Credential.h"
#include "Dll.h"
#include "Guids.h"
#include "LocalAccount.h"
#include "Log.h"
#include "Serialization.h"
#include "Util.h"
#include <lm.h>

#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif
#ifndef STATUS_ACCOUNT_DISABLED
#define STATUS_ACCOUNT_DISABLED ((NTSTATUS)0xC0000072L)
#endif
#ifndef STATUS_PASSWORD_EXPIRED
#define STATUS_PASSWORD_EXPIRED ((NTSTATUS)0xC0000071L)
#endif
#ifndef STATUS_PASSWORD_MUST_CHANGE
#define STATUS_PASSWORD_MUST_CHANGE ((NTSTATUS)0xC0000224L)
#endif
#ifndef STATUS_ACCOUNT_LOCKED_OUT
#define STATUS_ACCOUNT_LOCKED_OUT ((NTSTATUS)0xC0000234L)
#endif

namespace {

const wchar_t* kMsgEmptyUser     = L"Bitte geben Sie Ihren Benutzernamen ein.";
const wchar_t* kMsgEmptyPassword = L"Bitte geben Sie Ihr Kennwort ein.";
const wchar_t* kMsgBadCreds      = L"Benutzername oder Kennwort ist falsch.";
const wchar_t* kMsgDenied        = L"Ihr Konto ist für die Anmeldung an diesem Computer nicht freigegeben.";
const wchar_t* kMsgNeedOld       = L"Ihr Firmenkennwort wurde geändert. Bitte geben Sie Ihr bisheriges Windows-Kennwort ein, "
                                   L"damit gespeicherte Anmeldedaten erhalten bleiben.";

std::wstring NetErrorText(DWORD e) {
    switch (e) {
    case NERR_PasswordTooShort:
        return L"Das Kennwort erfüllt die lokale Kennwortrichtlinie nicht (Länge, Komplexität, Verlauf oder Mindestalter).";
    case NERR_UserExists:
        return L"Das lokale Konto existiert bereits.";
    case ERROR_ACCESS_DENIED:
        return L"Zugriff verweigert beim Bearbeiten des lokalen Kontos.";
    default:
        return L"Das lokale Konto konnte nicht aktualisiert werden: " + util::ErrorText(e);
    }
}

HBITMAP CreateDefaultTile() {
    const int size = 192;
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = size;
    bmi.bmiHeader.biHeight = size;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bmp) return nullptr;
    HDC dc = CreateCompatibleDC(nullptr);
    HGDIOBJ old = SelectObject(dc, bmp);
    RECT rc = { 0, 0, size, size };
    HBRUSH bg = CreateSolidBrush(RGB(0, 95, 184));
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    HBRUSH fg = CreateSolidBrush(RGB(255, 255, 255));
    HPEN pen = CreatePen(PS_NULL, 0, 0);
    HGDIOBJ oldBrush = SelectObject(dc, fg);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    Ellipse(dc, 66, 30, 126, 90);           // Kopf
    Chord(dc, 36, 100, 156, 220, 156, 160, 36, 160); // Oberkörper
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(fg);
    DeleteObject(pen);
    SelectObject(dc, old);
    DeleteDC(dc);
    return bmp;
}

} // namespace

Credential::Credential() { DllAddRef(); }

Credential::~Credential() {
    for (auto& v : values_) util::Wipe(v);
    ClearPending();
    if (events_) events_->Release();
    DllRelease();
}

HRESULT Credential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const Config& cfg) {
    cpus_ = cpus;
    cfg_ = cfg;

    values_[FI_TITLE] = cfg_.title;
    values_[FI_USERNAME] = local::LastLogin();
    values_[FI_INFO] = cfg_.helpText;

    states_[FI_TILEIMAGE]      = { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE };
    states_[FI_TITLE]          = { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE };
    states_[FI_USERNAME]       = { CPFS_DISPLAY_IN_SELECTED_TILE, values_[FI_USERNAME].empty() ? CPFIS_FOCUSED : CPFIS_NONE };
    states_[FI_PASSWORD]       = { CPFS_DISPLAY_IN_SELECTED_TILE, values_[FI_USERNAME].empty() ? CPFIS_NONE : CPFIS_FOCUSED };
    states_[FI_OLD_PASSWORD]   = { CPFS_HIDDEN, CPFIS_NONE };
    states_[FI_RESET_CHECKBOX] = { CPFS_HIDDEN, CPFIS_NONE };
    states_[FI_SUBMIT]         = { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE };
    states_[FI_INFO]           = { values_[FI_INFO].empty() ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE };
    return S_OK;
}

// --- IUnknown ---------------------------------------------------------------

IFACEMETHODIMP_(ULONG) Credential::AddRef() { return InterlockedIncrement(&refs_); }

IFACEMETHODIMP_(ULONG) Credential::Release() {
    LONG c = InterlockedDecrement(&refs_);
    if (!c) delete this;
    return c;
}

IFACEMETHODIMP Credential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    if (riid == __uuidof(IUnknown) || riid == __uuidof(ICredentialProviderCredential)) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// --- Hilfsfunktionen ---------------------------------------------------------

void Credential::SetField(DWORD id, const std::wstring& value) {
    util::Wipe(values_[id]);
    values_[id] = value;
    if (events_) events_->SetFieldString(this, id, value.c_str());
}

void Credential::SetInfo(const std::wstring& text) {
    SetField(FI_INFO, text);
    states_[FI_INFO].cpfs = text.empty() ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
    if (events_) events_->SetFieldState(this, FI_INFO, states_[FI_INFO].cpfs);
}

void Credential::SetPhase(Phase p) {
    phase_ = p;
    bool show = (p == Phase::NeedOldPassword);
    states_[FI_OLD_PASSWORD].cpfs = show ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    states_[FI_RESET_CHECKBOX].cpfs = show ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    resetChecked_ = false;
    if (events_) {
        events_->SetFieldState(this, FI_OLD_PASSWORD, states_[FI_OLD_PASSWORD].cpfs);
        events_->SetFieldState(this, FI_RESET_CHECKBOX, states_[FI_RESET_CHECKBOX].cpfs);
        events_->SetFieldCheckbox(this, FI_RESET_CHECKBOX, FALSE, nullptr);
        events_->SetFieldSubmitButton(this, FI_SUBMIT, show ? FI_OLD_PASSWORD : FI_PASSWORD);
        if (show) events_->SetFieldInteractiveState(this, FI_OLD_PASSWORD, CPFIS_FOCUSED);
    }
    SetField(FI_OLD_PASSWORD, L"");
    if (!show) SetInfo(cfg_.helpText);
}

void Credential::ClearPending() {
    util::Wipe(pendingTyped_);
    util::Wipe(pendingLocal_);
    util::Wipe(pendingPassword_);
    pendingResult_ = AdfsResult();
    oldPasswordFailures_ = 0;
}

// --- ICredentialProviderCredential -------------------------------------------

IFACEMETHODIMP Credential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (events_) events_->Release();
    events_ = pcpce;
    if (events_) events_->AddRef();
    return S_OK;
}

IFACEMETHODIMP Credential::UnAdvise() {
    if (events_) events_->Release();
    events_ = nullptr;
    return S_OK;
}

IFACEMETHODIMP Credential::SetSelected(BOOL* pbAutoLogon) {
    *pbAutoLogon = FALSE;
    return S_OK;
}

IFACEMETHODIMP Credential::SetDeselected() {
    SetField(FI_PASSWORD, L"");
    if (phase_ != Phase::Normal) {
        ClearPending();
        SetPhase(Phase::Normal);
    }
    return S_OK;
}

IFACEMETHODIMP Credential::GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                         CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    if (id >= FI_NUM_FIELDS || !pcpfs || !pcpfis) return E_INVALIDARG;
    *pcpfs = states_[id].cpfs;
    *pcpfis = states_[id].cpfis;
    return S_OK;
}

IFACEMETHODIMP Credential::GetStringValue(DWORD id, PWSTR* ppsz) {
    if (id >= FI_NUM_FIELDS || !ppsz) return E_INVALIDARG;
    return util::DupString(values_[id], ppsz);
}

IFACEMETHODIMP Credential::GetBitmapValue(DWORD id, HBITMAP* phbmp) {
    if (id != FI_TILEIMAGE || !phbmp) return E_INVALIDARG;
    HBITMAP bmp = nullptr;
    if (!cfg_.tileImagePath.empty())
        bmp = (HBITMAP)LoadImageW(nullptr, cfg_.tileImagePath.c_str(), IMAGE_BITMAP, 0, 0,
                                  LR_LOADFROMFILE | LR_CREATEDIBSECTION);
    if (!bmp) bmp = CreateDefaultTile();
    if (!bmp) return HRESULT_FROM_WIN32(GetLastError());
    *phbmp = bmp;
    return S_OK;
}

IFACEMETHODIMP Credential::GetCheckboxValue(DWORD id, BOOL* pbChecked, PWSTR* ppszLabel) {
    if (id != FI_RESET_CHECKBOX || !pbChecked || !ppszLabel) return E_INVALIDARG;
    *pbChecked = resetChecked_;
    return util::DupString(L"Bisheriges Kennwort vergessen – lokal zurücksetzen", ppszLabel);
}

IFACEMETHODIMP Credential::GetSubmitButtonValue(DWORD id, DWORD* pdwAdjacentTo) {
    if (id != FI_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = (phase_ == Phase::NeedOldPassword) ? FI_OLD_PASSWORD : FI_PASSWORD;
    return S_OK;
}

IFACEMETHODIMP Credential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
IFACEMETHODIMP Credential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }
IFACEMETHODIMP Credential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
IFACEMETHODIMP Credential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::SetStringValue(DWORD id, PCWSTR psz) {
    if (id != FI_USERNAME && id != FI_PASSWORD && id != FI_OLD_PASSWORD) return E_INVALIDARG;
    util::Wipe(values_[id]);
    values_[id] = psz ? psz : L"";
    return S_OK;
}

IFACEMETHODIMP Credential::SetCheckboxValue(DWORD id, BOOL bChecked) {
    if (id != FI_RESET_CHECKBOX) return E_INVALIDARG;
    resetChecked_ = bChecked != FALSE;
    if (resetChecked_)
        SetInfo(L"Achtung: Beim Zurücksetzen gehen lokal gespeicherte Anmeldedaten (z. B. Browser-Kennwörter, "
                L"Anmeldeinformationsverwaltung, EFS) verloren.");
    else
        SetInfo(kMsgNeedOld);
    return S_OK;
}

// --- Anmeldelogik ------------------------------------------------------------

Credential::Outcome Credential::OfflineLogon(const std::wstring& typed, const std::wstring& reason) {
    Outcome o;
    if (!cfg_.allowOffline) {
        LOGW(L"ADFS nicht verfügbar (%ls), Offline-Anmeldung deaktiviert", reason.c_str());
        o.error = L"Der Anmeldeserver ist nicht erreichbar. Bitte versuchen Sie es später erneut.";
        return o;
    }
    std::wstring localName = local::NameOffline(typed);
    if (localName.empty() || !local::Exists(localName)) {
        LOGW(L"ADFS nicht verfügbar (%ls), kein lokales Konto für '%ls'", reason.c_str(), typed.c_str());
        o.error = L"Der Anmeldeserver ist nicht erreichbar und auf diesem Computer existiert noch kein Konto für Sie. "
                  L"Bitte melden Sie sich einmal mit Netzwerkverbindung an.";
        return o;
    }
    LOGW(L"ADFS nicht verfügbar (%ls) – Offline-Anmeldung als lokales Konto '%ls'", reason.c_str(), localName.c_str());
    o.serialize = true;
    o.localUser = localName;
    o.info = L"Offline-Anmeldung";
    return o;
}

Credential::Outcome Credential::DoOnlineLogon(const std::wstring& typed, const std::wstring& login,
                                              const std::wstring& password) {
    Outcome o;
    AdfsClient client(cfg_);
    AdfsResult r = client.Authenticate(login, password);
    LOGI(L"ADFS-Ergebnis für '%ls': %ls – %ls", login.c_str(), StatusName(r.status), r.message.c_str());

    switch (r.status) {
    case AdfsResult::Ok:
        break;
    case AdfsResult::InvalidCredentials:
        o.error = kMsgBadCreds;
        return o;
    case AdfsResult::AccessDenied:
        o.error = kMsgDenied;
        return o;
    default:
        return OfflineLogon(typed, r.message);
    }

    for (const auto& c : r.claims) LOGD(L"  Claim %ls = %ls", c.first.c_str(), c.second.c_str());

    if (!cfg_.requiredClaim.empty() && !r.Has(cfg_.requiredClaim, cfg_.requiredValues)) {
        LOGW(L"'%ls' fehlt der erforderliche Claim %ls", login.c_str(), cfg_.requiredClaim.c_str());
        o.error = kMsgDenied;
        return o;
    }

    std::wstring localName = local::NameFromClaims(cfg_, r, typed);
    if (localName.empty()) {
        o.error = L"Aus dem Firmenkonto konnte kein lokaler Benutzername abgeleitet werden.";
        return o;
    }
    if (local::IsExcluded(cfg_, localName)) {
        LOGW(L"Lokales Konto '%ls' ist von der Synchronisierung ausgeschlossen", localName.c_str());
        o.error = L"Dieses Konto darf nicht über die Firmenanmeldung verwendet werden.";
        return o;
    }

    pendingTyped_ = typed;
    pendingLocal_ = localName;
    pendingPassword_ = password;
    pendingResult_ = r;

    if (!local::Exists(localName)) {
        if (!cfg_.createLocalUsers) {
            o.error = L"Auf diesem Computer existiert kein lokales Konto für Sie.";
            return o;
        }
        std::wstring fullName = r.First(cfg_.fullNameClaim);
        DWORD e = local::Create(localName, password, fullName);
        if (e != NERR_Success) {
            o.error = NetErrorText(e);
            return o;
        }
        return FinishSync();
    }

    DWORD v = local::VerifyPassword(localName, password);
    switch (v) {
    case ERROR_SUCCESS:
    case ERROR_PASSWORD_EXPIRED:
    case ERROR_PASSWORD_MUST_CHANGE:
        return FinishSync();
    case ERROR_ACCOUNT_DISABLED:
        o.error = L"Das lokale Konto ist deaktiviert. Bitte wenden Sie sich an die IT.";
        return o;
    case ERROR_LOGON_FAILURE:
    case ERROR_WRONG_PASSWORD:
        break;
    default:
        // Prüfung nicht möglich (z. B. Richtlinie) -> nichts ändern, Windows entscheidet bei der Anmeldung.
        LOGW(L"Lokales Passwort von '%ls' nicht prüfbar (Fehler %lu) – keine Synchronisierung", localName.c_str(), v);
        return FinishSync();
    }

    // Lokales Passwort weicht vom Firmenkennwort ab.
    LOGI(L"Lokales Passwort von '%ls' weicht ab (Fehler %lu)", localName.c_str(), v);
    if (cfg_.mismatchAction == 1) {
        DWORD e = local::ResetPassword(localName, password);
        if (e != NERR_Success) {
            o.error = NetErrorText(e);
            return o;
        }
        return FinishSync();
    }

    SetPhase(Phase::NeedOldPassword);
    SetInfo(kMsgNeedOld);
    o.error = kMsgNeedOld;
    o.warning = true;
    return o;
}

Credential::Outcome Credential::DoOldPasswordStep() {
    Outcome o;
    if (resetChecked_) {
        DWORD e = local::ResetPassword(pendingLocal_, pendingPassword_);
        if (e != NERR_Success) {
            o.error = NetErrorText(e);
            return o;
        }
        return FinishSync();
    }

    std::wstring oldPw = values_[FI_OLD_PASSWORD];
    if (oldPw.empty()) {
        o.error = L"Bitte geben Sie Ihr bisheriges Windows-Kennwort ein oder wählen Sie die Option zum Zurücksetzen.";
        o.warning = true;
        return o;
    }

    DWORD e = local::ChangePassword(pendingLocal_, oldPw, pendingPassword_);
    util::Wipe(oldPw);
    SetField(FI_OLD_PASSWORD, L"");
    if (e == NERR_Success) return FinishSync();

    if (e == ERROR_INVALID_PASSWORD) {
        ++oldPasswordFailures_;
        o.error = L"Das bisherige Windows-Kennwort ist falsch.";
        if (oldPasswordFailures_ >= 3)
            o.error += L" Wenn Sie es nicht mehr wissen, wählen Sie die Option zum Zurücksetzen.";
        return o;
    }
    o.error = NetErrorText(e);
    return o;
}

Credential::Outcome Credential::FinishSync() {
    const AdfsResult& r = pendingResult_;

    std::wstring fullName = r.First(cfg_.fullNameClaim);
    if (fullName.empty()) {
        std::wstring gn = r.First(cfg_.givenNameClaim), sn = r.First(cfg_.surnameClaim);
        fullName = util::Trim(gn + L" " + sn);
    }
    if (!fullName.empty()) local::SetFullName(pendingLocal_, fullName);

    if (!cfg_.adminValues.empty()) {
        bool admin = r.Has(cfg_.adminClaim, cfg_.adminValues);
        if (admin || cfg_.removeAdminIfNotMember) local::SetAdministrator(pendingLocal_, admin);
    }

    local::RememberMapping(pendingTyped_, pendingLocal_);

    Outcome o;
    o.serialize = true;
    o.localUser = pendingLocal_;
    return o;
}

IFACEMETHODIMP Credential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                            PWSTR* ppszOptionalStatusText,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    std::wstring typed = util::Trim(values_[FI_USERNAME]);
    std::wstring password = values_[FI_PASSWORD];
    Outcome o;
    bool handled = false;

    if (phase_ == Phase::NeedOldPassword) {
        if (util::EqualsI(typed, pendingTyped_) && password == pendingPassword_) {
            o = DoOldPasswordStep();
            handled = true;
        } else {
            // Benutzername oder neues Kennwort wurden geändert -> von vorne beginnen.
            ClearPending();
            SetPhase(Phase::Normal);
        }
    }

    if (!handled) {
        if (typed.empty()) {
            o.error = kMsgEmptyUser;
        } else if (password.empty()) {
            o.error = kMsgEmptyPassword;
        } else {
            std::wstring computerPrefix = local::ComputerName() + L"\\";
            if (util::StartsWithI(typed, L".\\") || util::StartsWithI(typed, computerPrefix)) {
                // Lokales Konto (z. B. Notfall-Administrator): direkt an Windows durchreichen.
                o.serialize = true;
                o.localUser = typed.substr(typed.find(L'\\') + 1);
                LOGI(L"Lokale Anmeldung als '%ls' (ohne ADFS)", o.localUser.c_str());
            } else {
                std::wstring login = typed;
                if (login.find(L'@') == std::wstring::npos && login.find(L'\\') == std::wstring::npos &&
                    !cfg_.upnSuffix.empty())
                    login += L"@" + cfg_.upnSuffix;
                o = DoOnlineLogon(typed, login, password);
            }
        }
    }

    HRESULT hr = S_OK;
    if (o.serialize) {
        hr = BuildKerbSerialization(cpus_, local::ComputerName(), o.localUser, password,
                                    CLSID_AdfsCredentialProvider, pcpcs);
        if (SUCCEEDED(hr)) {
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            if (phase_ != Phase::Normal) SetPhase(Phase::Normal);
            ClearPending();
        } else {
            LOGE(L"Serialisierung fehlgeschlagen: 0x%08lx", (unsigned long)hr);
            o.error = L"Interner Fehler bei der Anmeldung.";
        }
    }

    if (!o.error.empty()) {
        LOGI(L"Meldung an Benutzer: %ls", o.error.c_str());
        util::DupString(o.error, ppszOptionalStatusText);
        *pcpsiOptionalStatusIcon = o.warning ? CPSI_WARNING : CPSI_ERROR;
        if (phase_ == Phase::Normal) {
            SetField(FI_PASSWORD, L"");
            ClearPending();
        }
        hr = S_OK;
    }

    util::Wipe(password);
    return hr;
}

IFACEMETHODIMP Credential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, PWSTR* ppszOptionalStatusText,
                                        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    if (ntsStatus == 0) return S_OK;

    LOGW(L"Windows-Anmeldung fehlgeschlagen: Status 0x%08lx / 0x%08lx", (unsigned long)ntsStatus,
         (unsigned long)ntsSubstatus);
    SetField(FI_PASSWORD, L"");

    const wchar_t* msg = nullptr;
    if (ntsStatus == STATUS_LOGON_FAILURE)
        msg = L"Die Anmeldung ist fehlgeschlagen. Ohne Verbindung zum Anmeldeserver gilt das zuletzt auf diesem "
              L"Computer verwendete Kennwort.";
    else if (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus == STATUS_ACCOUNT_DISABLED)
        msg = L"Das lokale Konto ist deaktiviert.";
    else if (ntsStatus == STATUS_ACCOUNT_LOCKED_OUT)
        msg = L"Das lokale Konto ist gesperrt. Bitte melden Sie sich mit Netzwerkverbindung an.";
    else if (ntsStatus == STATUS_PASSWORD_MUST_CHANGE || ntsStatus == STATUS_PASSWORD_EXPIRED)
        msg = L"Das lokale Kennwort ist abgelaufen. Bitte melden Sie sich mit Netzwerkverbindung an.";

    if (msg) {
        util::DupString(msg, ppszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    return S_OK;
}
