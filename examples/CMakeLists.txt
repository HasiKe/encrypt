# Beispiel-Konfiguration
add_executable(simple_example simple_example.cpp)

if(UNIX AND NOT APPLE)
    target_link_libraries(simple_example 
        PRIVATE 
        encrypt_core
        ${PLATFORM_SOURCES_LINUX}
    )
endif()

if(WIN32)
    target_link_libraries(simple_example 
        PRIVATE 
        encrypt_core
        ${PLATFORM_SOURCES_WINDOWS}
    )
endif()