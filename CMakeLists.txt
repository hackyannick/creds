cmake_minimum_required(VERSION 3.16)
project(ADFSCreds VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "ADFSCreds ist ein Windows Credential Provider und muss für Windows gebaut werden.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 WINVER=0x0A00)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /sdl /guard:cf)
  add_link_options(/guard:cf /DYNAMICBASE /NXCOMPAT)
  # Statische CRT: keine Abhängigkeit vom VC++-Redistributable in LogonUI.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
  add_compile_options(-Wall -Wextra -Wno-unknown-pragmas -Wno-missing-field-initializers -Wno-cast-function-type)
  add_link_options(-static -static-libgcc -static-libstdc++)
endif()

set(CORE_SOURCES
  src/AdfsClient.cpp
  src/Config.cpp
  src/LocalAccount.cpp
  src/Log.cpp
  src/Util.cpp)

set(CORE_LIBS winhttp crypt32 netapi32 advapi32 ole32 oleaut32 secur32)

add_library(adfscreds_core STATIC ${CORE_SOURCES})
target_link_libraries(adfscreds_core PUBLIC ${CORE_LIBS})

add_library(ADFSCreds SHARED
  src/Credential.cpp
  src/Dll.cpp
  src/Filter.cpp
  src/Provider.cpp
  src/Serialization.cpp
  src/ADFSCreds.def)
target_link_libraries(ADFSCreds PRIVATE adfscreds_core gdi32 user32 uuid)
set_target_properties(ADFSCreds PROPERTIES PREFIX "" OUTPUT_NAME "ADFSCreds")
if(NOT MSVC)
  target_link_options(ADFSCreds PRIVATE -Wl,--kill-at)
endif()

add_executable(adfscreds-cli tools/adfscreds-cli.cpp)
target_link_libraries(adfscreds-cli PRIVATE adfscreds_core)
if(NOT MSVC)
  target_link_options(adfscreds-cli PRIVATE -municode)
endif()
