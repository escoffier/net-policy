project(libnetfilter_conntrack)

set(SOURCES
  api.c
  build_mnl.c
  callback.c
  compare.c
  conn-main.c
  copy.c
  filter.c
  getter.c
  labels.c
  objopt.c
  parse_mnl.c
  setter.c
  snprintf.c
  snprintf_default.c
)

add_library(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} libmnl)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/ ${CMAKE_SOURCE_DIR}/)
# target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/)
