cmake_minimum_required(VERSION 3.10)
project(libmeminterface)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINK_DYNAMIC_CXX_STANDARD_LIBRARIES OFF)

# Detect if we're cross-compiling
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling for Windows")
    set(IS_CROSS_COMPILE TRUE)
else()
    message(STATUS "Native build")
    set(IS_CROSS_COMPILE FALSE)
endif()

# Set paths based on platform
if(WIN32)
    set(LIBMEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMWIN/includeWIN/libmem")
    set(LIBMEM_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMWIN/libWIN/release")
    set(LIBMEM_LIB_NAME "libmem")
    set(LIBMEM_DLL "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMWIN/libWIN/release/libmem.dll")
else()
    set(LIBMEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMLIN/includeLIN/libmem")
    set(LIBMEM_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMLIN/libLIN")
    set(LIBMEM_LIB_NAME "libmem")
endif()

# Add executable
add_executable(test test.cpp)

# Include directories
target_include_directories(test PRIVATE ${LIBMEM_INCLUDE_DIR})

# Link libraries
target_link_directories(test PRIVATE ${LIBMEM_LIB_DIR})

# Set static linking options for all platforms
if(WIN32)
    # For MinGW
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ -static")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -static-libstdc++ -static")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -Wl,--whole-archive -Wl,--no-whole-archive")
    
    # Link libmem statically
    target_link_libraries(test PRIVATE -Wl,--whole-archive ${LIBMEM_LIB_NAME} -Wl,--no-whole-archive)
else()
    # For GCC/MinGW
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
    target_link_libraries(test PRIVATE -Wl,--whole-archive ${LIBMEM_LIB_NAME} -Wl,--no-whole-archive)
endif()

# Cross-compilation specific settings
if(IS_CROSS_COMPILE)
    # Add post-build command to verify static linking
    add_custom_command(TARGET test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Verifying static linking..."
        COMMAND ${CMAKE_COMMAND} -E echo "If you see any .dll dependencies, static linking failed"
        COMMAND ${CMAKE_COMMAND} -E echo "Dependencies:"
        COMMAND x86_64-w64-mingw32-objdump -p $<TARGET_FILE:test> | findstr "DLL"
        COMMENT "Verifying static linking"
    )
endif()

# Copy DLL to build directory on Windows
if(WIN32)
    add_custom_command(TARGET test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LIBMEM_DLL}"
            $<TARGET_FILE_DIR:test>
        COMMENT "Copying libmem.dll to output directory"
    )
endif()

# Installation
install(TARGETS test
    RUNTIME DESTINATION bin
) 