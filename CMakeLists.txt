cmake_minimum_required(VERSION 3.16)

project(win_linux_protect LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(src)
add_executable(win_linux_protect ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp)
set(MYAPP win_linux_protect)

set(ARCHPLATFORM x86)

set(THIRD_PATH ${CMAKE_CURRENT_LIST_DIR}/release/${ARCHPLATFORM})
set(SPDLOG_ROOT ${THIRD_PATH}/spdlog)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf)

include(GNUInstallDirs)
install(TARGETS win_linux_protect
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

target_link_libraries(${MYAPP}
    PRIVATE
    mylib
    ${LIBBPF_LIBRARIES}
)
target_include_directories(${MYAPP} PRIVATE ${SPDLOG_ROOT}/include)
target_include_directories(${MYAPP} PRIVATE ${LIBBPF_INCLUDE_DIRS})