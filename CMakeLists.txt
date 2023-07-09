cmake_minimum_required(VERSION 3.25)
project(uvw_http_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig)
find_package(Threads REQUIRED)


pkg_check_modules(LIBUV REQUIRED libuv>=1.30)
pkg_check_modules(LIBGNUTLS REQUIRED gnutls>=3.3)
pkg_search_module(LIBNGHTTP2 REQUIRED nghttp2 libnghttp2)


add_library(uvw_http_client
        httpssession.cpp
        tcpsession.cpp
        url_parser.c
        )

target_include_directories(uvw_http_client
        PUBLIC
        ./
        ${LIBUV_INCLUDE_DIRS}
        ${LIBGNUTLS_INCLUDE_DIRS}
        ${LIBNGHTTP2_INCLUDE_DIRS})

add_executable(
        uvw_http_client_test
        test_driver.cpp
)

target_link_libraries(uvw_http_client_test
        PRIVATE Threads::Threads
        PRIVATE ${LIBUV_LDFLAGS}
        PRIVATE ${LIBUV_LIBRARIES}
        PRIVATE ${httplib_LIBRARIES}
        uvw_http_client)