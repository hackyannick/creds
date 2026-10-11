#include "Log.h"
#include "Util.h"
#include <windows.h>
#include <shlobj.h>
#include <cstdarg>
#include <cstdio>

namespace logx {

static int  g_level = Info;
static bool g_echo = false;
static SRWLOCK g_lock = SRWLOCK_INIT;

void SetLevel(int level) { g_level = level; }
void SetConsoleEcho(bool echo) { g_echo = echo; }

static std::wstring LogPath() {
    wchar_t base[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"ProgramData", base, MAX_PATH)) wcscpy_s(base, L"C:\\ProgramData");
    std::wstring dir = std::wstring(base) + L"\\ADFSCreds";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\adfscreds.log";
}

void Write(Level level, const wchar_t* fmt, ...) {
    if (level > g_level) return;

    wchar_t msg[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(msg, _countof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);

    static const wchar_t* names[] = { L"", L"ERROR", L"WARN ", L"INFO ", L"DEBUG" };
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[2300];
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%5lu] %ls %ls\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 GetCurrentProcessId(), names[level], msg);

    if (g_echo) fwprintf(stderr, L"%ls", line);

    AcquireSRWLockExclusive(&g_lock);
    HANDLE h = CreateFileW(LogPath().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        // Log-Rotation bei > 5 MB
        LARGE_INTEGER size;
        if (GetFileSizeEx(h, &size) && size.QuadPart > 5 * 1024 * 1024) {
            CloseHandle(h);
            std::wstring p = LogPath();
            MoveFileExW(p.c_str(), (p + L".1").c_str(), MOVEFILE_REPLACE_EXISTING);
            h = CreateFileW(p.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (h != INVALID_HANDLE_VALUE) {
            std::string u = util::ToUtf8(line);
            DWORD written = 0;
            WriteFile(h, u.data(), (DWORD)u.size(), &written, nullptr);
            CloseHandle(h);
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace logx
