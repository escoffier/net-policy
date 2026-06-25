project(libnfnetlink)

message(${CMAKE_SOURCE_DIR}/../)

add_library(${PROJECT_NAME} libnfnetlink.c rtnl.c)

target_link_libraries(${PROJECT_NAME} libmnl)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/ ${CMAKE_SOURCE_DIR}/)
# target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/)
message(${CMAKE_SOURCE_DIR}/)