cmake_minimum_required(VERSION 3.14)
project(cheats)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enforce static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINK_DYNAMIC_CXX_STANDARD_LIBRARIES OFF)

# Platform-specific settings
if(WIN32)
    # Windows (MinGW) specific settings
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    
    # MinGW specific libraries
    set(MINGW_LIBS -lws2_32 -lwinmm -lgdi32 -lcomdlg32 -ole32 -loleaut32 -luuid -lcomctl32 -lmsimg32)
    
    # Set libmem paths for Windows
    set(LIBMEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMWIN/includeWIN")
    set(LIBMEM_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMWIN/libWIN/release")
    set(LIBMEM_LIB_NAME "libmem.lib")
    set(LIBMEM_DLL "libmem.dll")
else()
    # Linux specific settings
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    
    # Set libmem paths for Linux
    set(LIBMEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMLIN/includeLIN")
    set(LIBMEM_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/LIBMEMLIN/libLIN")
    set(LIBMEM_LIB_NAME "liblibmem.so")
endif()

# Add FTXUI using FetchContent
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/ftxui
  GIT_TAG v6.0.2
)

FetchContent_MakeAvailable(ftxui)

# Find all source files in utils directory
file(GLOB UTILS_SOURCES "utils/*.cpp")

# Add executable targets
add_executable(cheats 
    test.cpp
    ${UTILS_SOURCES}
)

# Add TUI executable
add_executable(cheats_tui
    test_tui.cpp
)

# Include directories for both executables
target_include_directories(cheats PRIVATE ${LIBMEM_INCLUDE_DIR})
target_include_directories(cheats_tui PRIVATE ${LIBMEM_INCLUDE_DIR})

# Link directories for both executables
target_link_directories(cheats PRIVATE ${LIBMEM_LIB_DIR})
target_link_directories(cheats_tui PRIVATE ${LIBMEM_LIB_DIR})

# Link against FTXUI and other dependencies for both executables
target_link_libraries(cheats PRIVATE ftxui::screen ftxui::dom ftxui::component)
target_link_libraries(cheats_tui PRIVATE ftxui::screen ftxui::dom ftxui::component)

# Platform-specific linking for cheats executable
if(WIN32)
    # Windows linking
    target_link_libraries(cheats PRIVATE "${LIBMEM_LIB_DIR}/${LIBMEM_LIB_NAME}" ${MINGW_LIBS})
    target_link_libraries(cheats_tui PRIVATE "${LIBMEM_LIB_DIR}/${LIBMEM_LIB_NAME}" ${MINGW_LIBS})
    
    # Copy libmem.dll to output directory for both executables
    add_custom_command(TARGET cheats POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${LIBMEM_LIB_DIR}/${LIBMEM_DLL}"
        $<TARGET_FILE_DIR:cheats>)
    
    add_custom_command(TARGET cheats_tui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${LIBMEM_LIB_DIR}/${LIBMEM_DLL}"
        $<TARGET_FILE_DIR:cheats_tui>)
    
else()
    # Linux linking for both executables
    target_link_libraries(cheats PRIVATE "${LIBMEM_LIB_DIR}/${LIBMEM_LIB_NAME}")
    target_link_libraries(cheats_tui PRIVATE "${LIBMEM_LIB_DIR}/${LIBMEM_LIB_NAME}")
endif()