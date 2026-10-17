cmake_minimum_required(VERSION 3.21)

project(WezCryptAegis
  VERSION 1.0.0
  DESCRIPTION "WezCrypt Aegis - security-focused Chromium-based browser"
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(WIN32)
  set(_aegis_browser_default ON)
else()
  set(_aegis_browser_default OFF)
endif()

option(AEGIS_BUILD_TESTS "Build the security-core test suites" ON)
option(AEGIS_BUILD_BROWSER "Build the Windows CEF browser (requires CEF_ROOT)" ${_aegis_browser_default})
option(AEGIS_ENABLE_SANITIZERS "Build tests with ASan/UBSan (GCC/Clang)" OFF)
if(MSVC)
  # CEF requires the static runtime; every linked target must match.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  set(_aegis_werror_default OFF)
else()
  set(_aegis_werror_default ON)
endif()
option(AEGIS_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ${_aegis_werror_default})
set(AEGIS_UPDATE_PUBLIC_KEYS "" CACHE STRING
    "Comma-separated Ed25519 public keys (base64 or hex) trusted for release manifests")
set(AEGIS_UPDATE_MANIFEST_URL "" CACHE STRING
    "HTTPS URL of the signed release manifest (empty disables online update checks)")
set(AEGIS_UPDATE_CHANNEL "stable" CACHE STRING "Release channel expected in manifests")

include(cmake/AegisHardening.cmake)
include(cmake/AegisBuildInfo.cmake)

# ---------------------------------------------------------------------------
# Third-party: Monocypher 4.0.2 (Ed25519 + SHA-512), vendored, BSD-2/CC0.
add_library(aegis_monocypher STATIC
  third_party/monocypher/monocypher.c
  third_party/monocypher/monocypher-ed25519.c)
target_include_directories(aegis_monocypher PUBLIC third_party/monocypher)
set_target_properties(aegis_monocypher PROPERTIES POSITION_INDEPENDENT_CODE ON)
aegis_apply_hardening(aegis_monocypher)
if(MSVC)
  target_compile_options(aegis_monocypher PRIVATE /W3)
endif()

# ---------------------------------------------------------------------------
# Portable security core (no browser-engine dependency; fully unit-tested).
add_library(aegis_core STATIC
  src/common/base64.cc
  src/common/idna.cc
  src/common/json.cc
  src/common/strings.cc
  src/common/url.cc
  src/common/utf8.cc
  src/downloads/download_safety.cc
  src/filtering/filter_engine.cc
  src/filtering/filter_list_manager.cc
  src/filtering/filter_parser.cc
  src/filtering/public_suffix_list.cc
  src/networking/network_policy.cc
  src/networking/unattributed_request_gate.cc
  src/permissions/permission_policy.cc
  src/privacy/profile.cc
  src/security/engine_switches.cc
  src/security/security_events.cc
  src/security/security_mode.cc
  src/security/security_policy.cc
  src/storage/atomic_file.cc
  src/storage/browsing_data.cc
  src/storage/settings.cc
  src/storage/settings_store.cc
  src/ui/internal_pages.cc
  src/ui/omnibox.cc
  src/updates/update_verifier.cc)
target_include_directories(aegis_core PUBLIC src ${AEGIS_GENERATED_DIR})
target_link_libraries(aegis_core PUBLIC aegis_monocypher)
aegis_apply_hardening(aegis_core)
aegis_apply_warnings(aegis_core)
if(WIN32)
  target_compile_definitions(aegis_core PUBLIC UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(AEGIS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(AEGIS_BUILD_BROWSER)
  if(NOT WIN32)
    message(FATAL_ERROR "The WezCrypt Aegis browser target supports Windows x64 only.")
  endif()
  add_subdirectory(src/app)
endif()

# Release / diagnostics tool built on the same core.
add_executable(aegis_tool tools/aegis_tool.cc)
target_link_libraries(aegis_tool PRIVATE aegis_core)
aegis_apply_hardening(aegis_tool)
aegis_apply_warnings(aegis_tool)
