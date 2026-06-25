cmake_minimum_required (VERSION 3.10.2)
project(net-rule)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address  -fno-omit-frame-pointer")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address  -fno-omit-frame-pointer")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

find_package(fmt)
find_package(glog 0.6.0 REQUIRED)
find_package(llhttp REQUIRED)

# find_package(NGHTTP2 REQUIRED)
# message(NGHTTP2_VERSION)

enable_testing()
find_package(GTest REQUIRED)

# add_subdirectory(third-party/llhttp-release-v9.0.1)
include(FetchContent)

# FetchContent_Declare(llhttp
#   URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz"
# )

# set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
# set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
# FetchContent_MakeAvailable(llhttp)

add_compile_definitions(GLOG_CUSTOM_PREFIX_SUPPORT)

set(SOURCES
    net/utility.cc
    net/filter.cc
    net/filter_factory.cc
    http/header.cc
    http/http_filter_factory.cc
    http/codec.cc
    http/packet.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    cjson.c
    net/ip.cc
    net/tcp.cc
    net/udp.cc
    http/extension/log.cc
    admin/profile.cc
    net-policy.cpp
    rule-detail.cpp
    waf/plugin.cc
    waf/rule.cc
)

add_subdirectory(libnfnetlink)
add_subdirectory(libmnl)
add_subdirectory(libnetfilter_conntrack)
add_subdirectory(libnetfilter_queue)

add_executable(net-rule ${SOURCES})
# add_definitions("-Wall -g")
add_executable(net_rule_test
    net/utility.cc
    net/filter.cc
    net/filter_factory.cc
    cjson.c
    http/header.cc
    http/codec.cc
    http/packet.cc
    http/http_filter_factory.cc
    http/filter.cc
    http/http1/http_parser.c
    http/http1/codec.cc
    http/http2/codec.cc
    http/url.cc
    http/http_inspector.cc
    http/connection.cc
    tests/http_inspector_test.cc
    tests/codec_test.cc
    tests/connection_manager_test.cc
    tests/http2/codec_tests.cc
)

set (PRIVATE_CXX_FLAGS
  -UNDEBUG
  -Wall
  -Werror
  -Wno-array-bounds # Disabled because of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=93437
  -Wno-error=deprecated-declarations)

target_compile_options(${PROJECT_NAME}
  PRIVATE ${PRIVATE_CXX_FLAGS})


target_include_directories(net-rule PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/)
target_link_libraries(net-rule 
  libnfnetlink 
  libnetfilter_queue 
  libnetfilter_conntrack 
  libnghttp2.a 
  libpcre2-8.a 
  libpcre2-posix.a 
  fmt::fmt-header-only 
  llhttp::llhttp_static 
  glog.a 
  gflags.a 
  ${CMAKE_THREAD_LIBS_INIT}
  libunwind.a
  liblzma.a
  libz.a
  libtcmalloc_and_profiler.a
)

# target_link_libraries(net-rule 
# libnfnetlink 
# libnetfilter_queue 
# libnetfilter_conntrack 
# libnghttp2.a 
# libpcre2-8.a 
# libpcre2-posix.a 
# fmt::fmt-header-only 
# llhttp::llhttp_static 
# glog.a gflags.a 
# ${CMAKE_THREAD_LIBS_INIT} 
# unwind 
# tcmalloc) 

target_link_libraries(net_rule_test 
libnfnetlink 
libnetfilter_queue 
libnetfilter_conntrack 
libnghttp2.a 
libpcre2-8.a 
libpcre2-posix.a 
fmt::fmt-header-only
llhttp::llhttp_static 
glog.a 
gflags.a 
${CMAKE_THREAD_LIBS_INIT}
libunwind.a
liblzma.a
libz.a
GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(net_rule_test)





# include(ExternalProject)
