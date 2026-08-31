# Runtime assets for the explicit StationConnect package manifest.
#
# Do not add install(), CPack, desktop-entry, user-service, or application
# metadata here. The repository-level RPM builder owns those product surfaces.

file(GLOB_RECURSE STATIONCONNECT_COMMON_ASSETS
        RELATIVE "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/"
        "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/*")
foreach(asset ${STATIONCONNECT_COMMON_ASSETS})
    file(COPY "${SUNSHINE_SOURCE_ASSETS_DIR}/common/assets/${asset}"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/assets")
endforeach()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(COPY "${SUNSHINE_SOURCE_ASSETS_DIR}/linux/assets/"
            DESTINATION "${CMAKE_BINARY_DIR}/assets"
            PATTERN "shaders" EXCLUDE)
    file(CREATE_LINK "${SUNSHINE_SOURCE_ASSETS_DIR}/linux/assets/shaders"
            "${CMAKE_BINARY_DIR}/assets/shaders" COPY_ON_ERROR SYMBOLIC)
elseif(WIN32)
    file(COPY "${SUNSHINE_SOURCE_ASSETS_DIR}/windows/assets/"
            DESTINATION "${CMAKE_BINARY_DIR}/assets")
endif()
