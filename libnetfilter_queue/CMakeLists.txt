project(libnetfilter_queue)

set(SOURCES
    libnetfilter_queue.c
    nlmsg.c
)

add_library(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} libnfnetlink)

set (PRIVATE_CXX_FLAGS
  -UNDEBUG
  -Wall
  -Werror
  -Wno-array-bounds # Disabled because of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=93437
  -Wno-error=deprecated-declarations)

target_compile_options(${PROJECT_NAME}
  PRIVATE ${PRIVATE_CXX_FLAGS})

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/)
# target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/)
