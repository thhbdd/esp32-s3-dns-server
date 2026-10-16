# Host (Linux) build of the portable components: unit tests, the filter
# compiler CLI (flc), the DNS server simulator (dnsd_host) and tools.
#
#   cmake -S host -B build-host -DCMAKE_BUILD_TYPE=Release && cmake --build build-host -j
#   ctest --test-dir build-host
cmake_minimum_required(VERSION 3.16)
project(esp32_dns_host C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
option(SANITIZE "Build with ASan/UBSan" OFF)
add_compile_options(-Wall -Wextra -Wshadow -Wno-unused-parameter)
if(SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
find_package(Threads REQUIRED)

add_library(dc_base STATIC
  ${ROOT}/components/dc_base/src/dc_util.c
  ${ROOT}/components/dc_base/src/dc_net.c
  ${ROOT}/components/dc_base/src/dc_port_posix.c)
target_include_directories(dc_base PUBLIC ${ROOT}/components/dc_base/include)
target_link_libraries(dc_base PUBLIC Threads::Threads)

file(GLOB FL_SRCS ${ROOT}/components/fl_filter/src/*.c)
add_library(fl_filter STATIC ${FL_SRCS})
target_include_directories(fl_filter PUBLIC ${ROOT}/components/fl_filter/include
                                     PRIVATE ${ROOT}/components/fl_filter/src)
target_link_libraries(fl_filter PUBLIC dc_base)

add_executable(flc ${ROOT}/tools/flc/flc.c)
target_link_libraries(flc fl_filter)

enable_testing()
add_executable(test_filter ${ROOT}/tests/unit/test_filter.c)
target_include_directories(test_filter PRIVATE ${ROOT}/components/fl_filter/src)
target_link_libraries(test_filter fl_filter)
add_test(NAME filter COMMAND test_filter)

# Host-only linker fault injection; no changes to the ESP32-S3 firmware.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX)
  add_executable(test_fsst_oom ${ROOT}/tests/unit/test_fsst_oom.c)
  target_include_directories(test_fsst_oom PRIVATE ${ROOT}/components/fl_filter/src)
  target_link_libraries(test_fsst_oom fl_filter)
  target_link_options(test_fsst_oom PRIVATE "-Wl,--wrap=fl_fsst_build")
  add_test(NAME fsst_oom_fallback COMMAND test_fsst_oom)
endif()

file(GLOB DNS_SRCS ${ROOT}/components/dns_core/src/*.c)
add_library(dns_core STATIC ${DNS_SRCS})
target_include_directories(dns_core PUBLIC ${ROOT}/components/dns_core/include
                                    PRIVATE ${ROOT}/components/dns_core/src)
target_link_libraries(dns_core PUBLIC fl_filter dc_base)

if(EXISTS ${ROOT}/tests/unit/test_dns.c)
  add_executable(test_dns ${ROOT}/tests/unit/test_dns.c)
  target_include_directories(test_dns PRIVATE ${ROOT}/components/dns_core/src)
  target_link_libraries(test_dns dns_core)
  add_test(NAME dns COMMAND test_dns)
endif()

# randomized robustness tests: build with -DSANITIZE=ON, run "fuzz all 60"
add_executable(fuzz ${ROOT}/tests/fuzz/fuzz.c)
target_link_libraries(fuzz dns_core)

if(EXISTS ${ROOT}/tools/dnsd_host/dnsd_host.c)
  add_executable(dnsd_host ${ROOT}/tools/dnsd_host/dnsd_host.c)
  target_link_libraries(dnsd_host dns_core)
endif()

if(EXISTS ${ROOT}/tools/dnsbench/dnsbench.c)
  add_executable(dnsbench ${ROOT}/tools/dnsbench/dnsbench.c)
  target_link_libraries(dnsbench Threads::Threads m)
endif()
