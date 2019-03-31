# https://cmake.org/Wiki/CMake_Cross_Compiling

cmake_minimum_required(VERSION 3.9)
project(untitled C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER   /usr/local/Cellar/mingw-w64/5.0.3_2/bin/i686-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER /usr/local/Cellar/mingw-w64/5.0.3_2/bin/i686-w64-mingw32-g++)

# here is the target environment located
set(CMAKE_FIND_ROOT_PATH /usr/local/Cellar/mingw-w64/5.0.3_2/bin/)

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_C_LINK_FLAGS "")

add_executable(untitled.exe main.c)