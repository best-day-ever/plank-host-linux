# common target definitions
# this file will also load platform specific macros

if(APPLE AND NOT SUNSHINE_BUILD_HOMEBREW)
    add_executable(sunshine MACOSX_BUNDLE ${SUNSHINE_TARGET_FILES})
else()
    add_executable(sunshine ${SUNSHINE_TARGET_FILES})
endif()
foreach(dep ${SUNSHINE_TARGET_DEPENDENCIES})
    add_dependencies(sunshine ${dep})  # compile these before sunshine
endforeach()

# platform specific target definitions
if(WIN32)
    include(${CMAKE_MODULE_PATH}/targets/windows.cmake)
elseif(UNIX)
    include(${CMAKE_MODULE_PATH}/targets/unix.cmake)

    if(APPLE)
        include(${CMAKE_MODULE_PATH}/targets/macos.cmake)
    else()
        include(${CMAKE_MODULE_PATH}/targets/linux.cmake)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_library(STATIONCONNECT_SYSTEMD_LIBRARY NAMES systemd REQUIRED)
    list(APPEND SUNSHINE_EXTERNAL_LIBRARIES ${STATIONCONNECT_SYSTEMD_LIBRARY})
endif()

target_link_libraries(sunshine ${SUNSHINE_EXTERNAL_LIBRARIES} ${EXTRA_LIBS})
target_compile_definitions(sunshine PUBLIC ${SUNSHINE_DEFINITIONS})

# CLion complains about unknown flags after running cmake, and cannot add symbols to the index for cuda files
if(CUDA_INHERIT_COMPILE_OPTIONS)
    foreach(flag IN LISTS SUNSHINE_COMPILE_OPTIONS)
        list(APPEND SUNSHINE_COMPILE_OPTIONS_CUDA "$<$<COMPILE_LANGUAGE:CUDA>:--compiler-options=${flag}>")
    endforeach()
endif()

target_compile_options(sunshine PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${SUNSHINE_COMPILE_OPTIONS}>;$<$<COMPILE_LANGUAGE:CUDA>:${SUNSHINE_COMPILE_OPTIONS_CUDA};-std=c++17>)  # cmake-lint: disable=C0301
target_link_options(sunshine PRIVATE ${SUNSHINE_LINK_OPTIONS})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_library(STATIONCONNECT_PAM_LIBRARY NAMES pam REQUIRED)
    add_executable(stationconnect-pam-broker
            "${CMAKE_SOURCE_DIR}/src/auth/pam_broker.cpp"
            "${CMAKE_SOURCE_DIR}/src/auth/pam_broker_protocol.h")
    target_link_libraries(stationconnect-pam-broker PRIVATE ${STATIONCONNECT_PAM_LIBRARY})
    target_compile_options(stationconnect-pam-broker PRIVATE ${SUNSHINE_COMPILE_OPTIONS})
    target_link_options(stationconnect-pam-broker PRIVATE ${SUNSHINE_LINK_OPTIONS})
    install(TARGETS stationconnect-pam-broker
            RUNTIME DESTINATION bin
            COMPONENT sunshine)

    add_executable(stationconnect-host-supervisor
            "${CMAKE_SOURCE_DIR}/src/session/host_supervisor.cpp"
            "${CMAKE_SOURCE_DIR}/src/session/session_context.cpp"
            "${CMAKE_SOURCE_DIR}/src/session/session_context.h")
    target_link_libraries(stationconnect-host-supervisor PRIVATE ${STATIONCONNECT_SYSTEMD_LIBRARY})
    target_compile_options(stationconnect-host-supervisor PRIVATE ${SUNSHINE_COMPILE_OPTIONS})
    target_link_options(stationconnect-host-supervisor PRIVATE ${SUNSHINE_LINK_OPTIONS})
    install(TARGETS stationconnect-host-supervisor
            RUNTIME DESTINATION bin
            COMPONENT sunshine)
endif()

# docs
if(BUILD_DOCS)
    add_subdirectory(third-party/doxyconfig docs)
endif()

# tests
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# custom compile flags, must be after adding tests

if (NOT BUILD_TESTS)
    set(TEST_DIR "")
else()
    set(TEST_DIR "${CMAKE_SOURCE_DIR}/tests")
endif()

# src/upnp
set_source_files_properties("${CMAKE_SOURCE_DIR}/src/upnp.cpp"
        DIRECTORY "${CMAKE_SOURCE_DIR}" "${TEST_DIR}"
        PROPERTIES COMPILE_FLAGS -Wno-pedantic)

# third-party/ViGEmClient
set(VIGEM_COMPILE_FLAGS "")
string(APPEND VIGEM_COMPILE_FLAGS "-Wno-unknown-pragmas ")
string(APPEND VIGEM_COMPILE_FLAGS "-Wno-misleading-indentation ")
string(APPEND VIGEM_COMPILE_FLAGS "-Wno-class-memaccess ")
string(APPEND VIGEM_COMPILE_FLAGS "-Wno-unused-function ")
string(APPEND VIGEM_COMPILE_FLAGS "-Wno-unused-variable ")
set_source_files_properties("${CMAKE_SOURCE_DIR}/third-party/ViGEmClient/src/ViGEmClient.cpp"
        DIRECTORY "${CMAKE_SOURCE_DIR}" "${TEST_DIR}"
        PROPERTIES
        COMPILE_DEFINITIONS "UNICODE=1;ERROR_INVALID_DEVICE_OBJECT_PARAMETER=650"
        COMPILE_FLAGS ${VIGEM_COMPILE_FLAGS})

# src/nvhttp
string(TOUPPER "x${CMAKE_BUILD_TYPE}" BUILD_TYPE)
if("${BUILD_TYPE}" STREQUAL "XDEBUG")
    if(WIN32)
        if (NOT BUILD_TESTS)
            set_source_files_properties("${CMAKE_SOURCE_DIR}/src/nvhttp.cpp"
                    DIRECTORY "${CMAKE_SOURCE_DIR}"
                    PROPERTIES COMPILE_FLAGS -O2)
        else()
            set_source_files_properties("${CMAKE_SOURCE_DIR}/src/nvhttp.cpp"
                    DIRECTORY "${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/tests"
                    PROPERTIES COMPILE_FLAGS -O2)
        endif()
    endif()
else()
    add_definitions(-DNDEBUG)
endif()
