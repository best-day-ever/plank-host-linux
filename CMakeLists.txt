cmake_minimum_required(VERSION 3.24)
# `CMAKE_CUDA_ARCHITECTURES` requires 3.18
# `set_source_files_properties` requires 3.18
# `cmake_path(CONVERT ... TO_NATIVE_PATH_LIST ...)` requires 3.20
# `third-party/libvirtualhid` requires 3.24
# todo - set this conditionally

project(StationConnectHost VERSION 0.0.0
        DESCRIPTION "StationConnect remote workstation host"
        HOMEPAGE_URL "https://instinctual.la")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT DEFINED CMAKE_CUDA_STANDARD)
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
endif()

set(PROJECT_LICENSE "GPL-3.0-only")

set(PROJECT_FQDN "la.instinctual.StationConnect.Host")

option(STATIONCONNECT_PRODUCT_BUILD
        "Build the StationConnect product without inherited Sunshine packaging metadata." ON)

set(PROJECT_BRIEF_DESCRIPTION "StationConnect workstation host")  # must be <= 35 characters

set(PROJECT_LONG_DESCRIPTION "StationConnect provides low-latency remote workstation capture, encoding, input, \
authentication, and session management for the StationConnect client.")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(FREEBSD ON)
endif()

# set the module path, used for includes
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# CPM
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpm/CPM.cmake)
CPMUsePackageLock(package-lock.cmake)

# export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set version info for this build
include(${CMAKE_MODULE_PATH}/prep/build_version.cmake)

# cmake build flags
include(${CMAKE_MODULE_PATH}/prep/options.cmake)

# initial prep
include(${CMAKE_MODULE_PATH}/prep/init.cmake)

# The StationConnect RPM has its own explicit, audited package manifest. Do not
# generate inherited desktop, Flatpak, AppImage, or user-service metadata for
# that product build. The upstream packaging path remains available for source
# portability work by explicitly disabling STATIONCONNECT_PRODUCT_BUILD.
if(STATIONCONNECT_PRODUCT_BUILD)
    set(END_BUILD OFF)
else()
    include(${CMAKE_MODULE_PATH}/prep/special_package_configuration.cmake)
endif()

# Exit early if END_BUILD is ON, i.e. when only generating package manifests
if(${END_BUILD})
    return()
endif()

# project constants
include(${CMAKE_MODULE_PATH}/prep/constants.cmake)

# load macros
include(${CMAKE_MODULE_PATH}/macros/common.cmake)

# load dependencies
include(${CMAKE_MODULE_PATH}/dependencies/common.cmake)

# setup compile definitions
include(${CMAKE_MODULE_PATH}/compile_definitions/common.cmake)

# target definitions
include(${CMAKE_MODULE_PATH}/targets/common.cmake)

# The product package consumes only runtime assets from this CMake build. Its
# RPM metadata and filesystem manifest live at the StationConnect repository
# root, not in the inherited CPack layer.
if(STATIONCONNECT_PRODUCT_BUILD)
    include(${CMAKE_MODULE_PATH}/packaging/stationconnect.cmake)
else()
    include(${CMAKE_MODULE_PATH}/packaging/common.cmake)
endif()
