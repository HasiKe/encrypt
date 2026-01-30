#===============================================================================
# MinGW-w64 Cross-Compilation Toolchain
# For building Windows executables on Linux
#===============================================================================

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Toolchain prefix
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# Cross-compilers
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)

# Target environment
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})

# Adjust the default behavior of the FIND_XXX() commands:
# - Search for headers and libraries only in target environment
# - Search for programs only in host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Static linking for standalone executables
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")

# Windows-specific definitions
add_definitions(-DWIN32 -D_WIN32 -D_WINDOWS)
add_definitions(-DUNICODE -D_UNICODE)
