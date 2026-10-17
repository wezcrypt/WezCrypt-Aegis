# Generates aegis_build_info.h. The build timestamp honours SOURCE_DATE_EPOCH
# so release builds are reproducible.

if(DEFINED ENV{SOURCE_DATE_EPOCH})
  set(AEGIS_BUILD_UNIX "$ENV{SOURCE_DATE_EPOCH}")
else()
  string(TIMESTAMP AEGIS_BUILD_UNIX "%s" UTC)
endif()

find_package(Git QUIET)
set(AEGIS_GIT_REVISION "unknown")
if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
                  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                  OUTPUT_VARIABLE AEGIS_GIT_REVISION
                  OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(NOT AEGIS_GIT_REVISION)
    set(AEGIS_GIT_REVISION "unknown")
  endif()
endif()

foreach(_v AEGIS_UPDATE_PUBLIC_KEYS AEGIS_UPDATE_MANIFEST_URL AEGIS_UPDATE_CHANNEL)
  if("${${_v}}" MATCHES "[\"\\\\\n]")
    message(FATAL_ERROR "${_v} contains characters that are not allowed")
  endif()
endforeach()
if(AEGIS_UPDATE_MANIFEST_URL AND NOT AEGIS_UPDATE_MANIFEST_URL MATCHES "^https://")
  message(FATAL_ERROR "AEGIS_UPDATE_MANIFEST_URL must use https://")
endif()

set(AEGIS_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
configure_file("${CMAKE_SOURCE_DIR}/cmake/aegis_build_info.h.in"
               "${AEGIS_GENERATED_DIR}/aegis_build_info.h" @ONLY)
