#include "Dll.h"
#include "Filter.h"
#include "Guids.h"
#include "Provider.h"
#include <new>
#include <string>

HINSTANCE g_hinst = nullptr;
static LONG g_refs = 0;

void DllAddRef() { InterlockedIncrement(&g_refs); }
void DllRelease() { InterlockedDecrement(&g_refs); }

namespace {

typedef HRESULT (*CreateFn)(REFIID, void**);

class ClassFactory final : public IClassFactory {
public:
    explicit ClassFactory(CreateFn fn) : fn_(fn) { DllAddRef(); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IClassFactory)) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG c = InterlockedDecrement(&refs_);
        if (!c) delete this;
        return c;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        return fn_(riid, ppv);
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) DllAddRef(); else DllRelease();
        return S_OK;
    }

private:
    ~ClassFactory() { DllRelease(); }
    LONG refs_ = 1;
    CreateFn fn_;
};

HRESULT SetKeyValue(HKEY root, const std::wstring& key, const wchar_t* name, const std::wstring& value) {
    HKEY k;
    LONG r = RegCreateKeyExW(root, key.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);
    r = RegSetValueExW(k, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                       (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return HRESULT_FROM_WIN32(r);
}

HRESULT RegisterComClass(const wchar_t* clsid, const wchar_t* name, const wchar_t* category) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(g_hinst, path, MAX_PATH)) return HRESULT_FROM_WIN32(GetLastError());

    std::wstring clsKey = std::wstring(L"CLSID\\") + clsid;
    HRESULT hr = SetKeyValue(HKEY_CLASSES_ROOT, clsKey, nullptr, name);
    if (SUCCEEDED(hr)) hr = SetKeyValue(HKEY_CLASSES_ROOT, clsKey + L"\\InprocServer32", nullptr, path);
    if (SUCCEEDED(hr)) hr = SetKeyValue(HKEY_CLASSES_ROOT, clsKey + L"\\InprocServer32", L"ThreadingModel", L"Apartment");
    if (SUCCEEDED(hr))
        hr = SetKeyValue(HKEY_LOCAL_MACHINE,
                         std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\") + category +
                             L"\\" + clsid,
                         nullptr, name);
    return hr;
}

void UnregisterComClass(const wchar_t* clsid, const wchar_t* category) {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE,
                   (std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\") + category + L"\\" +
                    clsid).c_str());
    RegDeleteTreeW(HKEY_CLASSES_ROOT, (std::wstring(L"CLSID\\") + clsid).c_str());
}

} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

extern "C" HRESULT __stdcall DllCanUnloadNow() { return g_refs > 0 ? S_FALSE : S_OK; }

extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    CreateFn fn = nullptr;
    if (IsEqualCLSID(rclsid, CLSID_AdfsCredentialProvider)) fn = Provider_CreateInstance;
    else if (IsEqualCLSID(rclsid, CLSID_AdfsCredentialProviderFilter)) fn = Filter_CreateInstance;
    else return CLASS_E_CLASSNOTAVAILABLE;

    ClassFactory* cf = new (std::nothrow) ClassFactory(fn);
    if (!cf) return E_OUTOFMEMORY;
    HRESULT hr = cf->QueryInterface(riid, ppv);
    cf->Release();
    return hr;
}

extern "C" HRESULT __stdcall DllRegisterServer() {
    HRESULT hr = RegisterComClass(ADFSCREDS_CLSID_STR, L"ADFSCreds Credential Provider", L"Credential Providers");
    if (SUCCEEDED(hr))
        hr = RegisterComClass(ADFSCREDS_FILTER_CLSID_STR, L"ADFSCreds Credential Provider Filter",
                           L"Credential Provider Filters");
    return hr;
}

extern "C" HRESULT __stdcall DllUnregisterServer() {
    UnregisterComClass(ADFSCREDS_FILTER_CLSID_STR, L"Credential Provider Filters");
    UnregisterComClass(ADFSCREDS_CLSID_STR, L"Credential Providers");
    return S_OK;
}
