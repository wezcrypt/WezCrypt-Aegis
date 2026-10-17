# WezCrypt Aegis - Windows browser target (CEF M138+ bootstrap sandbox model).
#
# Produces, in ${CEF_TARGET_OUT_DIR}:
#   WezCryptAegis.dll   - the application (exports RunWinMain)
#   WezCryptAegis.exe   - CEF's prebuilt bootstrap.exe, renamed; it creates
#                         the sandbox and loads WezCryptAegis.dll
#   libcef.dll and the other CEF runtime files, resources and locales
#   assets/             - filter lists, Public Suffix List, branding

if(NOT CEF_ROOT)
  message(FATAL_ERROR
    "CEF_ROOT is not set. Run scripts/fetch_cef.py and configure with "
    "-DCEF_ROOT=<path to cef_binary_<version>_windows64_minimal>.")
endif()
if(NOT EXISTS "${CEF_ROOT}/cmake/FindCEF.cmake")
  message(FATAL_ERROR "CEF_ROOT does not contain a CEF binary distribution: ${CEF_ROOT}")
endif()

# The sandbox is not optional. USE_SANDBOX selects the bootstrap build mode.
set(USE_SANDBOX ON CACHE BOOL "Use the Chromium sandbox (required)" FORCE)

list(APPEND CMAKE_MODULE_PATH "${CEF_ROOT}/cmake")
find_package(CEF REQUIRED)
if(NOT OS_WINDOWS)
  message(FATAL_ERROR "The WezCrypt Aegis browser target requires Windows.")
endif()
if(NOT EXISTS "${CEF_BINARY_DIR_RELEASE}/bootstrap.exe")
  message(FATAL_ERROR
    "bootstrap.exe not found in ${CEF_BINARY_DIR_RELEASE}. CEF M138 or newer is required "
    "for sandboxed builds of applications compiled outside the Chromium toolchain.")
endif()
PRINT_CEF_CONFIG()

add_subdirectory(${CEF_LIBCEF_DLL_WRAPPER_PATH} libcef_dll_wrapper)
ADD_LOGICAL_TARGET("libcef_lib" "${CEF_LIB_DEBUG}" "${CEF_LIB_RELEASE}")
SET_CEF_TARGET_OUT_DIR()

set(AEGIS_TARGET WezCryptAegis)
set(AEGIS_BROWSER_SRCS
  main_win.cc
  ../browser/aegis_app.cc
  ../browser/aegis_context.cc
  ../browser/client_handler.cc
  ../browser/request_handlers.cc
  ../browser/sandbox_check.cc
  ../browser/sandbox_verifier_win.cc
  ../browser/scheme_handler.cc
  ../browser/test_hooks.cc
  ../browser/update_service.cc
  ../ui/browser_window.cc
  ../ui/prompt_window.cc
  ${CMAKE_SOURCE_DIR}/packaging/windows/WezCryptAegis.rc)

add_library(${AEGIS_TARGET} SHARED ${AEGIS_BROWSER_SRCS})
SET_LIBRARY_TARGET_PROPERTIES(${AEGIS_TARGET})
# CEF's flags enable /WX; MSVC-only diagnostics are reported but do not fail
# the build of the application layer (the portable core keeps its own
# warning policy and is built warning-free on GCC/Clang with -Werror).
target_compile_options(${AEGIS_TARGET} PRIVATE /WX- /guard:cf /Zc:__cplusplus)
target_link_options(${AEGIS_TARGET} PRIVATE /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT)
target_include_directories(${AEGIS_TARGET} PRIVATE
  ${CEF_ROOT} ${CMAKE_SOURCE_DIR}/src ${AEGIS_GENERATED_DIR})
add_dependencies(${AEGIS_TARGET} libcef_dll_wrapper)
target_link_libraries(${AEGIS_TARGET} PRIVATE
  libcef_lib libcef_dll_wrapper ${CEF_STANDARD_LIBS}
  aegis_core shell32 ole32 shlwapi advapi32 user32)

# The bootstrap executable becomes WezCryptAegis.exe and loads
# WezCryptAegis.dll from the same directory.
COPY_SINGLE_FILE(${AEGIS_TARGET} "${CEF_BINARY_DIR}/bootstrap.exe" "${CEF_TARGET_OUT_DIR}/${AEGIS_TARGET}.exe")
COPY_FILES(${AEGIS_TARGET} "${CEF_BINARY_FILES}" "${CEF_BINARY_DIR}" "${CEF_TARGET_OUT_DIR}")
COPY_FILES(${AEGIS_TARGET} "${CEF_RESOURCE_FILES}" "${CEF_RESOURCE_DIR}" "${CEF_TARGET_OUT_DIR}")

# Application assets.
foreach(_dir data filters branding)
  add_custom_command(TARGET ${AEGIS_TARGET} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/assets/${_dir}" "${CEF_TARGET_OUT_DIR}/assets/${_dir}"
    VERBATIM)
endforeach()

# Grant the Low-Privilege AppContainer read/execute access to the output
# directory, required by the Windows sandbox for sandboxed processes.
SET_LPAC_ACLS(${AEGIS_TARGET})

if(CMAKE_GENERATOR MATCHES "Visual Studio")
  set_target_properties(${AEGIS_TARGET} PROPERTIES
    VS_DEBUGGER_COMMAND "${CEF_TARGET_OUT_DIR}/${AEGIS_TARGET}.exe")
endif()

set(AEGIS_BROWSER_OUT_DIR "${CEF_TARGET_OUT_DIR}" PARENT_SCOPE)
