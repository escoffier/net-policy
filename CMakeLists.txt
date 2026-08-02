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

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

# add_subdirectory(third-party/llhttp-release-v9.0.1)
include(FetchContent)

# FetchContent_Declare(llhttp
#   URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz"
# )

# set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
# set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
# FetchContent_MakeAvailable(llhttp)

FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG v0.5
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)

corrosion_add_cxxbridge(ffi_smoke_cxxbridge
  CRATE ffi_smoke
  FILES lib.rs
)

corrosion_add_cxxbridge(waf_rules_core_cxxbridge
  CRATE waf_rules_core
  FILES lib.rs
)

corrosion_add_cxxbridge(net_policy_control_cxxbridge
  CRATE net_policy_control
  FILES lib.rs
)
# lib.rs's cxx bridge does `include!("grpc/control_dispatch.h")`, resolved
# relative to the repo root -- unlike waf_rules_core_cxxbridge, which has no
# C++ #include of its own and so never needed this.
target_include_directories(net_policy_control_cxxbridge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

corrosion_add_cxxbridge(net_policy_events_cxxbridge
  CRATE net_policy_events
  FILES lib.rs
)

corrosion_add_cxxbridge(net_policy_engine_cxxbridge
  CRATE net_policy_engine
  FILES lib.rs
)

add_compile_definitions(GLOG_CUSTOM_PREFIX_SUPPORT)

set(SOURCES
    net/utility.cc
    net/filter.cc
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
    main.cpp
    net-policy.cpp
    rule-detail.cpp
    waf/plugin.cc
    waf/rule.cc
    grpc/control_dispatch.cc
)

add_subdirectory(libnfnetlink)
add_subdirectory(libmnl)
add_subdirectory(libnetfilter_conntrack)
add_subdirectory(libnetfilter_queue)

# --- gRPC/protobuf codegen for proto/*.proto (see grpc/ and proto/ for the control-plane
# gRPC migration; this runs alongside the existing raw-socket control plane, not instead
# of it) ---
set(NET_POLICY_PROTO_FILES
    proto/net_policy_common.proto
    proto/net_policy_control.proto
)
set(NET_POLICY_PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-gen/proto)
file(MAKE_DIRECTORY ${NET_POLICY_PROTO_GEN_DIR})

# Generates the .pb.cc/.pb.h/.grpc.pb.cc/.grpc.pb.h for one proto_file and appends the
# two compiled sources (pb.cc, grpc.pb.cc) to the list named by out_var.
macro(net_policy_add_proto proto_file out_var)
  get_filename_component(proto_name ${proto_file} NAME_WE)
  set(pb_cc      ${NET_POLICY_PROTO_GEN_DIR}/${proto_name}.pb.cc)
  set(pb_h       ${NET_POLICY_PROTO_GEN_DIR}/${proto_name}.pb.h)
  set(grpc_pb_cc ${NET_POLICY_PROTO_GEN_DIR}/${proto_name}.grpc.pb.cc)
  set(grpc_pb_h  ${NET_POLICY_PROTO_GEN_DIR}/${proto_name}.grpc.pb.h)
  add_custom_command(
    OUTPUT ${pb_cc} ${pb_h} ${grpc_pb_cc} ${grpc_pb_h}
    COMMAND protobuf::protoc
    ARGS --cpp_out=${CMAKE_CURRENT_BINARY_DIR}/proto-gen
         --grpc_out=${CMAKE_CURRENT_BINARY_DIR}/proto-gen
         --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
         -I ${CMAKE_CURRENT_SOURCE_DIR}
         ${CMAKE_CURRENT_SOURCE_DIR}/${proto_file}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${proto_file}
    COMMENT "Generating gRPC/protobuf code for ${proto_file}"
    VERBATIM)
  list(APPEND ${out_var} ${pb_cc} ${grpc_pb_cc})
endmacro()

set(NET_POLICY_PROTO_GENERATED_SRCS "")
foreach(proto_file ${NET_POLICY_PROTO_FILES})
  net_policy_add_proto(${proto_file} NET_POLICY_PROTO_GENERATED_SRCS)
endforeach()

# proto/net_policy_events.proto is kept out of NET_POLICY_PROTO_FILES/SOURCES above:
# no C++ in net-rule references its generated types anymore (net-policy.cpp and
# waf/plugin.cc only include net_policy_events_cxxbridge/lib.h, which carries no
# proto-generated C++ types across the FFI boundary -- the Rust net_policy_events
# crate is the actual EventService server now). The only remaining C++ consumer of
# this proto's generated code is tests/grpc_rust_events_e2e_test.cc, which needs the
# generated gRPC CLIENT stub to talk to the Rust server as a test client. Generated
# into its own list, and added only to net_rule_grpc_test below, so net-rule doesn't
# compile/link the unused ~679KB NetPolicyEvents::Service server-side scaffolding.
set(NET_POLICY_EVENTS_PROTO_FILES
    proto/net_policy_events.proto
)
set(NET_POLICY_EVENTS_PROTO_GENERATED_SRCS "")
foreach(proto_file ${NET_POLICY_EVENTS_PROTO_FILES})
  net_policy_add_proto(${proto_file} NET_POLICY_EVENTS_PROTO_GENERATED_SRCS)
endforeach()

# Generated code isn't held to this project's -Wall -Werror (see target_compile_options
# below, which applies only to the net-rule target) -- protobuf/grpc generated sources
# routinely trip -Wunused-parameter/-Wshadow that would otherwise break the build.
set_source_files_properties(${NET_POLICY_PROTO_GENERATED_SRCS} ${NET_POLICY_EVENTS_PROTO_GENERATED_SRCS}
  PROPERTIES COMPILE_OPTIONS "-w")

list(APPEND SOURCES ${NET_POLICY_PROTO_GENERATED_SRCS})

add_executable(net-rule ${SOURCES})
# add_definitions("-Wall -g")
add_executable(net_rule_test
    net/utility.cc
    net/filter.cc
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
    tests/ffi_smoke_test.cc
)

set (PRIVATE_CXX_FLAGS
  -UNDEBUG
  -Wall
  -Werror
  -Wno-array-bounds # Disabled because of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=93437
  -Wno-error=deprecated-declarations)

target_compile_options(${PROJECT_NAME}
  PRIVATE ${PRIVATE_CXX_FLAGS})


target_include_directories(net-rule PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ ${CMAKE_CURRENT_BINARY_DIR}/proto-gen)
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
  gRPC::grpc++
  protobuf::libprotobuf
  waf_rules_core_cxxbridge
  net_policy_control_cxxbridge
  net_policy_events_cxxbridge
  net_policy_engine_cxxbridge
)
# waf_rules_core_cxxbridge, net_policy_control_cxxbridge, net_policy_events_cxxbridge,
# and net_policy_engine_cxxbridge are separate Rust staticlib crates that all depend
# on the `cxx` crate; since each staticlib statically embeds its own copy of
# cxx's internal runtime shim symbols (e.g. cxxbridge1$rust_vec$bool$...),
# linking multiple such crates into the same binary trips the linker's ODR check
# even though the duplicated bodies are byte-identical. --allow-multiple-definition
# is the standard workaround (see cxx-rs upstream issues on multi-crate staticlib
# linking).
set_target_properties(net-rule PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")

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
ffi_smoke_cxxbridge
GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(net_rule_test)

# --- gRPC control-plane tests ---
# Kept separate from net_rule_test (which deliberately excludes NFQUEUE/iptables/policy-engine
# code) since these tests link net-policy.cpp/rule-detail.cpp/waf/* to exercise real
# g_microseg/WAF state through the new gRPC control service. Safe to link GTest::gtest_main
# alongside net-policy.cpp now that net-policy.cpp no longer defines main() (see main.cpp).
add_executable(net_rule_grpc_test
    net/utility.cc
    net/filter.cc
    net/ip.cc
    net/tcp.cc
    net/udp.cc
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
    http/extension/log.cc
    admin/profile.cc
    net-policy.cpp
    rule-detail.cpp
    waf/plugin.cc
    waf/rule.cc
    grpc/control_dispatch.cc
    ${NET_POLICY_PROTO_GENERATED_SRCS}
    ${NET_POLICY_EVENTS_PROTO_GENERATED_SRCS}
    tests/grpc_rust_control_e2e_test.cc
    tests/grpc_rust_events_e2e_test.cc
    tests/waf_rules_test.cc
)
target_include_directories(net_rule_grpc_test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ ${CMAKE_CURRENT_BINARY_DIR}/proto-gen)
target_link_libraries(net_rule_grpc_test
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
  gRPC::grpc++
  protobuf::libprotobuf
  waf_rules_core_cxxbridge
  net_policy_control_cxxbridge
  net_policy_events_cxxbridge
  net_policy_engine_cxxbridge
  GTest::gtest_main)
# See the matching comment on net-rule's LINK_FLAGS above.
set_target_properties(net_rule_grpc_test PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")
gtest_discover_tests(net_rule_grpc_test)




# include(ExternalProject)
