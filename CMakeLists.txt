cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Find Qt6 Widgets
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# Use pkg-config for mbedTLS and libsodium
find_package(PkgConfig REQUIRED)
pkg_search_module(MBEDCRYPTO REQUIRED IMPORTED_TARGET
    mbedcrypto      # Debian/Ubuntu
    mbedtls         # Others
)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_executable(PasswordManager main.cpp)

target_link_libraries(PasswordManager
    Qt6::Core
    Qt6::Widgets
    PkgConfig::MBEDCRYPTO
    PkgConfig::SODIUM
)
