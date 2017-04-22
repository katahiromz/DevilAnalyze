# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008" .
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles" .
##############################################################################
# This file is public domain software (PDS).
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 2.4)

# project name and language
project(DevilAnalyze32 CXX)

# 32-bit compiler
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "32-bit compiler required.")
endif()

# Unicode build?
option(USE_UNICODE "Build as Unicode application" OFF)
if (USE_UNICODE)
    add_definitions(-DUNICODE -D_UNICODE)
else()
    add_definitions(-DMBCS -D_MBCS)
endif()

# check build type
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Debug")
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# make uppercase string of build type
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)

# check build type again
if (NOT uppercase_CMAKE_BUILD_TYPE MATCHES "^(DEBUG|RELEASE|RELWITHDEBINFO|MINSIZEREL)$")
    message(FATAL_ERROR "Invalid value for CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# define _DEBUG on Debug version
if (uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG")
endif()

# set output directory (build/)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    # using Clang
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBRARIES OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # using GCC
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBRARIES OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
    # using Intel C++
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # using Visual Studio C++
endif()

# Win32
add_executable(DevilAnalyze32 ../DevilAnalyze.cpp)
target_link_libraries(DevilAnalyze32 version)

# install the program
install(TARGETS DevilAnalyze32 DESTINATION bin)

##############################################################################
