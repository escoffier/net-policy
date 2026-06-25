project(libmnl)

set(SOURCES
    attr.c
    callback.c
    mnlmsg.c
    socket.c
)

add_library(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/)
