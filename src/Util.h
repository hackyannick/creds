#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace util {

// Überschreibt den Inhalt eines Strings (z. B. Passwort) mit Nullen.
inline void Wipe(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}
inline void Wipe(std::string& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size());
    s.clear();
}

std::string  ToUtf8(const std::wstring& w);
std::wstring FromUtf8(const std::string& s);
std::wstring ToLower(std::wstring s);
std::wstring Trim(const std::wstring& s);
bool         EqualsI(const std::wstring& a, const std::wstring& b);
bool         StartsWithI(const std::wstring& s, const std::wstring& prefix);
bool         EndsWithI(const std::wstring& s, const std::wstring& suffix);
std::wstring XmlEscape(const std::wstring& s);
std::wstring NewUuid();                     // "xxxxxxxx-xxxx-..." (ohne Klammern)
std::wstring IsoUtcNow(int offsetSeconds);  // "2026-10-11T11:03:00.000Z"
bool         ParseIsoUtc(const std::wstring& s, FILETIME* ft);
std::wstring ErrorText(DWORD err);

// CoTaskMem-Kopie für Rückgaben an LogonUI.
HRESULT DupString(const std::wstring& s, PWSTR* out);

} // namespace util
