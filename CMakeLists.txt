cmake_minimum_required(VERSION 3.20)
project(wr C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(WR_BUILD_TESTS "Build unit and integration tests" ON)
option(WR_BUILD_FUZZ "Build fuzz targets" ON)
option(WR_FUZZ_ENGINE "none|libfuzzer|afl" "none")
option(WR_SANITIZERS "none|asan|tsan" "none")
option(WR_BACKEND "openssl|stub" "openssl")
option(WR_WERROR "Treat warnings as errors" ON)
option(WR_BUILD_BENCH "Build the hot-path benchmark" ON)
set(WR_OPT_LEVEL "2" CACHE STRING "Optimization level for release builds")
option(WR_MEDIA "Build FFmpeg-backed media codec and RTP payload layers" OFF)
option(WR_HARDENING "Enable stack/fortify/PIE hardening flags" ON)

include(cmake/Warnings.cmake)

# OpenSSL LTS 3.5.x is the supported crypto backend. Homebrew installs it
# side-by-side with 4.x; pin the search path so the default does not silently
# pick 4.x. Override with -DOPENSSL_ROOT_DIR=... or -DWR_OPENSSL_ROOT=...
if(NOT DEFINED OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
  foreach(_cand /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
    if(EXISTS "${_cand}")
      set(OPENSSL_ROOT_DIR "${_cand}" CACHE PATH "OpenSSL root")
      break()
    endif()
  endforeach()
endif()

find_package(OpenSSL 3.5 REQUIRED)
find_package(Threads REQUIRED)

add_library(wr STATIC
  src/base/arena.c
  src/base/bitio.c
  src/base/bitmap.c
  src/base/crc32.c
  src/base/crc32c.c
  src/base/hash.c
  src/base/log.c
  src/base/map_str.c
  src/base/map_u64.c
  src/base/pool.c
  src/base/rng.c
  src/base/sb.c
  src/base/span.c
  src/base/status.c
  src/crypto/openssl_crypto.c
  src/net/endpoint.c
  src/net/io.c
  src/net/timer.c
  src/sdp/sdp_attr.c
  src/sdp/sdp_jsep.c
  src/sdp/sdp_parse.c
  src/sdp/sdp_serialize.c
  src/stun/stun_addr.c
  src/stun/stun_integrity.c
  src/stun/stun_msg.c
  src/ice/ice.c
  src/ice/ice_cand.c
  src/ice/ice_check.c
  src/srtp/srtp.c
  src/rtp/rtcp.c
  src/rtp/rtp.c
  src/rtp/streams.c
  src/sctp/dcep.c
  src/sctp/sctp.c
  src/sctp/tsn.c
  src/dtls/dtls.c
  src/dtls/dtls_crypto.c
  src/dtls/handshake.c
  src/pc/pc.c
  src/pc/pc_jsep.c
  src/turn/channel.c
  src/turn/turn.c
  src/media/payload.c
)

if(WR_MEDIA)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET
    libavcodec libavutil libavformat libswscale)
  target_sources(wr PRIVATE src/media/codec.c)
  target_include_directories(wr PRIVATE ${FFMPEG_INCLUDE_DIRS})
  target_link_libraries(wr PUBLIC PkgConfig::FFMPEG)
  target_compile_definitions(wr PUBLIC WR_MEDIA=1)
endif()

target_include_directories(wr
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(wr PUBLIC c_std_17)
target_link_libraries(wr PUBLIC OpenSSL::Crypto Threads::Threads)
# SRTP keeps reusable HMAC/EVP contexts; the one-shot HMAC API is deprecated
# in OpenSSL 3.x but is still the right primitive for the cached context path.
set_source_files_properties(src/srtp/srtp.c PROPERTIES
  COMPILE_OPTIONS -Wno-deprecated-declarations)
if(WR_HARDENING)
  target_compile_options(wr PUBLIC
    -fstack-protector-strong
    -fno-common
    -fvisibility=hidden
    $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
  )
  if(APPLE)
    # ld64 already emits chained fixups; the old -bind_at_load spelling is
    # deprecated and warns on current linkers.
    target_link_options(wr PUBLIC -Wl,-dead_strip)
  else()
    target_link_options(wr PUBLIC -Wl,-z,relro -Wl,-z,now -pie)
    target_compile_options(wr PUBLIC -fPIE)
  endif()
endif()
target_compile_options(wr PRIVATE
  $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-O${WR_OPT_LEVEL}>
)
if(WR_SANITIZERS STREQUAL "asan")
  # use-after-scope is not on by default in every clang build; without it a
  # builder that stores a span to its own stack frame passes ASan unnoticed.
  target_compile_options(wr PUBLIC -fsanitize=address,undefined
    -fsanitize-address-use-after-scope -fno-omit-frame-pointer)
  target_link_options(wr PUBLIC -fsanitize=address,undefined)
elseif(WR_SANITIZERS STREQUAL "tsan")
  target_compile_options(wr PUBLIC -fsanitize=thread -fno-omit-frame-pointer)
  target_link_options(wr PUBLIC -fsanitize=thread)
endif()

if(WR_FUZZ_ENGINE STREQUAL "libfuzzer")
  target_compile_options(wr PUBLIC -fsanitize=fuzzer-no-link)
endif()

wr_apply_warnings(wr)

if(WR_BUILD_FUZZ)
  function(wr_add_fuzz_target name src)
    if(WR_FUZZ_ENGINE STREQUAL "libfuzzer")
      add_executable(${name} ${src})
      target_link_libraries(${name} PRIVATE wr)
      target_compile_options(${name} PRIVATE -fsanitize=fuzzer-no-link,address,undefined)
      target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    else()
      add_executable(${name} ${src} fuzz/standalone_main.c)
      target_link_libraries(${name} PRIVATE wr)
    endif()
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
    wr_apply_warnings(${name})
  endfunction()
  wr_add_fuzz_target(wr_fuzz_sdp fuzz/target_sdp.c)
  wr_add_fuzz_target(wr_fuzz_stun fuzz/target_stun.c)
  wr_add_fuzz_target(wr_fuzz_srtp fuzz/target_srtp.c)
  wr_add_fuzz_target(wr_fuzz_rtp fuzz/target_rtp.c)
  wr_add_fuzz_target(wr_fuzz_sctp fuzz/target_sctp.c)
  wr_add_fuzz_target(wr_fuzz_dtls fuzz/target_dtls.c)
  wr_add_fuzz_target(wr_fuzz_rtppay fuzz/target_rtppay.c)
  wr_add_fuzz_target(wr_fuzz_sctp_fsm fuzz/target_sctp_fsm.c)
  wr_add_fuzz_target(wr_fuzz_ice_fsm fuzz/target_ice_fsm.c)
  wr_add_fuzz_target(wr_fuzz_sdp_jsep fuzz/target_sdp_jsep.c)
  wr_add_fuzz_target(wr_fuzz_stun_ext fuzz/target_stun_ext.c)
  wr_add_fuzz_target(wr_fuzz_rtcp fuzz/target_rtcp.c)
  wr_add_fuzz_target(wr_fuzz_rtp_ext fuzz/target_rtp_ext.c)
  wr_add_fuzz_target(wr_fuzz_srtp_gcm fuzz/target_srtp_gcm.c)
  wr_add_fuzz_target(wr_fuzz_dtls_record fuzz/target_dtls_record.c)
  wr_add_fuzz_target(wr_fuzz_dtls_hs_fsm fuzz/target_dtls_hs_fsm.c)
  wr_add_fuzz_target(wr_fuzz_sctp_chunks fuzz/target_sctp_chunks.c)
  wr_add_fuzz_target(wr_fuzz_sctp_fsm2 fuzz/target_sctp_fsm2.c)
  wr_add_fuzz_target(wr_fuzz_ice_ext fuzz/target_ice_ext.c)
  wr_add_fuzz_target(wr_fuzz_turn_fsm fuzz/target_turn_fsm.c)
  wr_add_fuzz_target(wr_fuzz_pc_jsep fuzz/target_pc_jsep.c)
  wr_add_fuzz_target(wr_fuzz_base_bitmap fuzz/target_base_bitmap.c)
  wr_add_fuzz_target(wr_fuzz_base_bitio fuzz/target_base_bitio.c)
  wr_add_fuzz_target(wr_fuzz_base_map fuzz/target_base_map.c)
  wr_add_fuzz_target(wr_fuzz_base_pool fuzz/target_base_pool.c)
  wr_add_fuzz_target(wr_fuzz_timer fuzz/target_timer.c)
  wr_add_fuzz_target(wr_fuzz_endpoint fuzz/target_endpoint.c)
  wr_add_fuzz_target(wr_fuzz_misc fuzz/target_misc.c)
endif()

if(WR_BUILD_TESTS)
  enable_testing()
  add_executable(wr_tests
    tests/test_main.c
    tests/test_base.c
    tests/test_sdp.c
    tests/test_stun.c
    tests/test_ice.c
    tests/test_srtp.c
    tests/test_rtp.c
    tests/test_sctp.c
    tests/test_dtls.c
    tests/test_dtls_hs.c
    tests/test_pc.c
    tests/test_turn.c
    tests/test_crypto.c
    tests/test_data.c
    tests/test_media.c
  )
  if(WR_MEDIA)
    target_sources(wr_tests PRIVATE tests/test_media_codec.c)
  endif()
  target_link_libraries(wr_tests PRIVATE wr)
  wr_apply_warnings(wr_tests)
  add_test(NAME wr_tests COMMAND wr_tests)
endif()

if(WR_BUILD_BENCH)
  add_executable(wr_bench bench/bench_main.c)
  target_link_libraries(wr_bench PRIVATE wr)
  target_compile_options(wr_bench PRIVATE
    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-O${WR_OPT_LEVEL}>
  )
  wr_apply_warnings(wr_bench)
endif()