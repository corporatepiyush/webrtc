function(wr_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
    if(WR_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    # Strict, security-oriented warning set. Keep this in sync with the CI
    # matrix: AppleClang, Homebrew Clang, and GCC.
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic
      -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes
      -Wmissing-prototypes -Wundef -Wpointer-arith -Wwrite-strings
      -Wformat=2 -Wformat-security
      -Wnull-dereference -Wdouble-promotion -Wimplicit-fallthrough
      -Wswitch-enum -Wfloat-equal -Wvla -Walloca
      -Warray-bounds -Wbool-operation -Wtautological-compare
      -Wdeprecated -Wstrict-overflow=3
      -Wstack-protector
    )
    if(WR_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()