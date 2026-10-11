#pragma once
#include <string>

// Einfaches Datei-Log unter %ProgramData%\ADFSCreds\adfscreds.log.
// Passwörter werden niemals geloggt.
namespace logx {

enum Level { Error = 1, Warn = 2, Info = 3, Debug = 4 };

void SetLevel(int level);
void Write(Level level, const wchar_t* fmt, ...);
void SetConsoleEcho(bool echo);  // für das Kommandozeilen-Testwerkzeug

} // namespace logx

#define LOGE(...) logx::Write(logx::Error, __VA_ARGS__)
#define LOGW(...) logx::Write(logx::Warn, __VA_ARGS__)
#define LOGI(...) logx::Write(logx::Info, __VA_ARGS__)
#define LOGD(...) logx::Write(logx::Debug, __VA_ARGS__)
