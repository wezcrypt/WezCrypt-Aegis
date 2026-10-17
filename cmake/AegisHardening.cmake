# Compiler and linker hardening shared by all WezCrypt Aegis targets.

function(aegis_apply_hardening target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /guard:cf        # Control Flow Guard
      /sdl             # additional security checks
      /GS              # buffer security checks
      /Qspectre        # Spectre variant 1 mitigations
      /utf-8
      /Zc:__cplusplus
      /permissive-)
    target_link_options(${target} INTERFACE
      /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT)
  else()
    target_compile_options(${target} PRIVATE
      -fstack-protector-strong
      -fno-strict-overflow
      -fno-delete-null-pointer-checks)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
      target_compile_definitions(${target} PRIVATE _FORTIFY_SOURCE=2)
    endif()
    target_compile_definitions(${target} PRIVATE _GLIBCXX_ASSERTIONS)
    if(AEGIS_ENABLE_SANITIZERS)
      target_compile_options(${target} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

function(aegis_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /w14242 /w14254 /w14263 /w14265 /w14287
                                             /w14296 /w14311 /w14826 /w14905 /w14906 /w14928)
    if(AEGIS_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow
                                             -Wnon-virtual-dtor -Wcast-align -Wformat=2
                                             -Wimplicit-fallthrough)
    if(AEGIS_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()
