#!/bin/bash

# Check if mingw-w64 is installed
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "mingw-w64 is not installed. Please install it:"
    echo "Ubuntu/Debian: sudo apt-get install mingw-w64"
    echo "Fedora: sudo dnf install mingw64-gcc-c++"
    exit 1
fi

# Check if CMake is installed
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Please install it first."
    exit 1
fi

# Check if Ninja is installed
if ! command -v ninja &> /dev/null; then
    echo "Ninja is not installed. Please install it first."
    echo "Ubuntu/Debian: sudo apt-get install ninja-build"
    echo "Fedora: sudo dnf install ninja-build"
    exit 1
fi

# Create build directory
mkdir -p build
cd build

# Configure for cross-compilation with Ninja
cmake .. \
    -G "Ninja" \
    -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw.cmake \
    -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build .

# Copy required DLLs
cp ../LIBMEMWIN/libWIN/release/libmem.dll .

echo ""
echo "Build complete!"
echo "To run on Windows, you may need:"
echo "1. Visual C++ Redistributable for libmem.dll"
echo "2. Run as Administrator for process memory access" 