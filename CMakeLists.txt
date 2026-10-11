cmake_minimum_required(VERSION 3.20)
project(streamlink_native VERSION 0.1.0 LANGUAGES CXX)
if(NOT MINGW)
  message(FATAL_ERROR "This initial native port requires Windows x64 MinGW-w64")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(U transport/udp2raw)
set(SOURCES
  ${U}/main.cpp ${U}/common.cpp ${U}/network.cpp ${U}/connection.cpp
  ${U}/client.cpp ${U}/server.cpp ${U}/misc.cpp ${U}/fd_manager.cpp
  ${U}/encrypt.cpp ${U}/log.cpp ${U}/my_ev.cpp
  ${U}/lib/md5.cpp ${U}/lib/pbkdf2-sha1.cpp ${U}/lib/pbkdf2-sha256.cpp
  ${U}/lib/aes_faster_c/aes.cpp ${U}/lib/aes_faster_c/wrapper.cpp
  ${U}/native_backend.cpp ${U}/native_server.cpp ${U}/native_attach.cpp ${U}/native_so.cpp ${U}/native_broker.cpp)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/git_version.h"
  "const char *gitversion = \"c4995ea+streamlink-native-experimental\";\n")
function(native_target name)
  add_executable(${name} ${SOURCES})
  target_include_directories(${name} PRIVATE ${U} third-party/windivert "${CMAKE_CURRENT_BINARY_DIR}")
  target_include_directories(${name} SYSTEM PRIVATE ${U}/libev)
  target_compile_definitions(${name} PRIVATE UDP2RAW_MP UDP2RAW_NATIVE _WIN32_WINNT=0x0602)
  target_compile_options(${name} PRIVATE -O2 -Wall -Wextra -Wno-unused-parameter
    -Wno-unused-variable -Wno-sign-compare -Wno-missing-field-initializers -Wno-cast-function-type -UNDEBUG)
  target_link_options(${name} PRIVATE -static)
  target_link_libraries(${name} PRIVATE ws2_32 iphlpapi bcrypt pthread)
endfunction()
native_target(udp2raw-native)
# This is a distinct test binary. The shipped binary cannot enable test I/O.
native_target(udp2raw-protocol-test)
target_compile_definitions(udp2raw-protocol-test PRIVATE UDP2RAW_TEST_IO)
enable_testing()
add_executable(native-so-state-test tests/native_so_state_test.cpp)
target_include_directories(native-so-state-test PRIVATE ${U})
target_link_options(native-so-state-test PRIVATE -static)
add_test(NAME native-so-state COMMAND native-so-state-test)
add_library(streamlink-tun SHARED transport/tun/adapter.cpp)
set_target_properties(streamlink-tun PROPERTIES PREFIX "")
target_include_directories(streamlink-tun PRIVATE third-party/wintun)
target_compile_definitions(streamlink-tun PRIVATE _WIN32_WINNT=0x0602)
target_compile_options(streamlink-tun PRIVATE -O2 -Wall -Wextra)
target_link_options(streamlink-tun PRIVATE -static -static-libgcc -static-libstdc++)
target_link_libraries(streamlink-tun PRIVATE iphlpapi ws2_32)
