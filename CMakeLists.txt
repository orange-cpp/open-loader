cmake_minimum_required(VERSION 3.25)

include(cmake/vcpkg.cmake)

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_compile_options(-O3 -static )
endif ()

vcpkg_install_if_not_found(openssl)
vcpkg_install_if_not_found(glfw3)
vcpkg_install_if_not_found(boost-asio)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

project(open_loader)
set(CMAKE_CXX_STANDARD 26)


add_executable(open_loader source/main.cpp)

target_include_directories(open_loader PRIVATE source)
target_compile_definitions(open_loader PRIVATE CV_X64_INSERT_VIA_INLINE)
add_subdirectory(source)
add_subdirectory(external)

find_package(OpenSSL REQUIRED)
find_package(boost_asio REQUIRED CONFIG)
find_package(wxWidgets CONFIG REQUIRED)

target_link_libraries(open_loader PRIVATE OpenSSL::SSL Boost::asio cv-sdk satsuma wx::core wx::base)
target_link_options(open_loader PRIVATE -Wl,-Map)