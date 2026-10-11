#include "Util.h"
#include <objbase.h>
#include <cwchar>
#include <cwctype>
#include <cstdio>
#include <algorithm>

namespace util {

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::wstring Trim(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return {};
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool EqualsI(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), (int)a.size(), b.c_str(), (int)b.size(), TRUE) == CSTR_EQUAL;
}

bool StartsWithI(const std::wstring& s, const std::wstring& prefix) {
    return s.size() >= prefix.size() && EqualsI(s.substr(0, prefix.size()), prefix);
}

bool EndsWithI(const std::wstring& s, const std::wstring& suffix) {
    return s.size() >= suffix.size() && EqualsI(s.substr(s.size() - suffix.size()), suffix);
}

std::wstring XmlEscape(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size() + 16);
    for (wchar_t c : s) {
        switch (c) {
        case L'&':  r += L"&amp;";  break;
        case L'<':  r += L"&lt;";   break;
        case L'>':  r += L"&gt;";   break;
        case L'"':  r += L"&quot;"; break;
        case L'\'': r += L"&apos;"; break;
        default:    r += c;
        }
    }
    return r;
}

std::wstring NewUuid() {
    GUID g;
    CoCreateGuid(&g);
    wchar_t buf[64];
    swprintf(buf, 64, L"%08lx-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x",
             (unsigned long)g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2],
             g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

std::wstring IsoUtcNow(int offsetSeconds) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (LONGLONG)offsetSeconds * 10000000LL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

bool ParseIsoUtc(const std::wstring& s, FILETIME* ft) {
    SYSTEMTIME st = {};
    unsigned y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (swscanf_s(s.c_str(), L"%4u-%2u-%2uT%2u:%2u:%2u", &y, &mo, &d, &h, &mi, &se) != 6) return false;
    st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d;
    st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)se;
    return SystemTimeToFileTime(&st, ft) != FALSE;
}

std::wstring ErrorText(DWORD err) {
    wchar_t* msg = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, 0, (LPWSTR)&msg, 0, nullptr);
    std::wstring r;
    if (n && msg) r = Trim(msg);
    if (msg) LocalFree(msg);
    wchar_t code[32];
    swprintf(code, 32, L" (%lu)", err);
    return r + code;
}

HRESULT DupString(const std::wstring& s, PWSTR* out) {
    if (!out) return E_INVALIDARG;
    size_t cb = (s.size() + 1) * sizeof(wchar_t);
    *out = static_cast<PWSTR>(CoTaskMemAlloc(cb));
    if (!*out) return E_OUTOFMEMORY;
    memcpy(*out, s.c_str(), cb);
    return S_OK;
}

} // namespace util
