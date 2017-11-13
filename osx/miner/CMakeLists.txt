project(unihivelib)

cmake_minimum_required(VERSION 3.0.1)

# enforce C++11
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}" CACHE PATH "install prefix" FORCE)

################################################################################
# CMake user options
################################################################################

# gcc 5.1 is the first GNU version without CoW strings
# https://github.com/fireice-uk/xmr-stak-nvidia/pull/10#issuecomment-290821792
# If you remove this guard to compile with older gcc versions the miner will produce
# a high rate of wrong shares.
if(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.1)
        message(FATAL_ERROR "g++ version must be at least 5.1!")
    endif()
endif()

set(BUILD_TYPE "Release;Debug")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "${BUILD_TYPE}")

################################################################################
# Find PThreads
################################################################################

find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

################################################################################
# Compile & Link
################################################################################

# activate sse2 and aes-ni
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2 -maes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2 -maes")
endif()

file(GLOB SRCFILES_CPP "*.cpp" "crypto/*.cpp")
file(GLOB SRCFILES_C "crypto/*.c")

add_library(unihive-crypto
    STATIC
    ${SRCFILES_C}
)
set_property(TARGET unihive-crypto PROPERTY C_STANDARD 99)
target_link_libraries(unihive-crypto ${LIBS})

add_library(unihivelib
    MODULE
    ${SRCFILES_CPP}
)

target_link_libraries(unihivelib ${LIBS} unihive-crypto)
set_target_properties(unihivelib PROPERTIES BUNDLE TRUE)
