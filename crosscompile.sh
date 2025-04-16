#!/bin/bash
# crosscompile.sh - Script to cross-compile the cheats project for Windows using MinGW

# Exit on error
set -e

# Print commands before executing
set -x

# Configuration variables - adjust these as needed
MINGW_PREFIX="x86_64-w64-mingw32"
BUILD_DIR="build_mingw"
CMAKE_GENERATOR="Ninja"  # Using Ninja for faster builds, but you can use "Unix Makefiles" if preferred

# Create build directory if it doesn't exist
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# Check if mingw is installed
if ! command -v ${MINGW_PREFIX}-g++ &> /dev/null; then
    echo "Error: ${MINGW_PREFIX}-g++ not found. Please install MinGW toolchain."
    echo "On Arch Linux: sudo pacman -S mingw-w64-gcc"
    echo "On Ubuntu: sudo apt-get install g++-mingw-w64"
    exit 1
fi

# Ensure all required MinGW tools are available and get their full paths
CXX_COMPILER=$(which ${MINGW_PREFIX}-g++)
C_COMPILER=$(which ${MINGW_PREFIX}-gcc)
WINDRES=$(which ${MINGW_PREFIX}-windres || echo "")
RANLIB=$(which ${MINGW_PREFIX}-ranlib || echo "")

# Check if we found all required tools
if [ -z "$CXX_COMPILER" ] || [ -z "$C_COMPILER" ] || [ -z "$WINDRES" ] || [ -z "$RANLIB" ]; then
    echo "Error: One or more required MinGW tools not found:"
    [ -z "$CXX_COMPILER" ] && echo "- ${MINGW_PREFIX}-g++ not found"
    [ -z "$C_COMPILER" ] && echo "- ${MINGW_PREFIX}-gcc not found"
    [ -z "$WINDRES" ] && echo "- ${MINGW_PREFIX}-windres not found"
    [ -z "$RANLIB" ] && echo "- ${MINGW_PREFIX}-ranlib not found"
    echo "Please install the complete MinGW toolchain"
    exit 1
fi

echo "Using compilers:"
echo "C compiler: $C_COMPILER"
echo "C++ compiler: $CXX_COMPILER"
echo "Resource compiler: $WINDRES"
echo "Ranlib: $RANLIB"

# Configure with CMake using the MinGW toolchain
cmake .. \
    -G "${CMAKE_GENERATOR}" \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_C_COMPILER="${C_COMPILER}" \
    -DCMAKE_CXX_COMPILER="${CXX_COMPILER}" \
    -DCMAKE_RC_COMPILER="${WINDRES}" \
    -DCMAKE_RANLIB="${RANLIB}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY

# Build the project
cmake --build . --config Release

echo ""
echo "====================================="
echo "Cross-compilation completed successfully!"
echo "The Windows binaries are located in: ${BUILD_DIR}"
echo "cheats.exe and cheats_ui.exe should be available now"
echo "====================================="

# Copy libmem DLL to the build directory if not done by CMake
if [ ! -f "libmem.dll" ] && [ -f "../LIBMEMWIN/libWIN/release/libmem.dll" ]; then
    cp "../LIBMEMWIN/libWIN/release/libmem.dll" ./
    echo "Copied libmem.dll to the build directory"
fi

echo "Done!"