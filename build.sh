#!/bin/bash

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This script is intended for Linux systems only."
    exit 1
fi

# Check if CMake is installed
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake is not installed. Please install CMake first."
    echo "On Ubuntu/Debian: sudo apt-get install cmake"
    echo "On Fedora: sudo dnf install cmake"
    echo "On Arch Linux: sudo pacman -S cmake"
    exit 1
fi

# Check if g++ is installed
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ is not installed. Please install g++ first."
    echo "On Ubuntu/Debian: sudo apt-get install g++"
    echo "On Fedora: sudo dnf install gcc-c++"
    echo "On Arch Linux: sudo pacman -S gcc"
    exit 1
fi

# Check if libmem is installed
if [ ! -d "LIBMEMLIN" ]; then
    echo "Error: libmem library not found. Please ensure LIBMEMLIN directory exists with the following structure:"
    echo "LIBMEMLIN/"
    echo "├── includeLIN/"
    echo "└── libLIN/"
    echo "    └── libmem.a"
    exit 1
fi

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi

# Enter build directory
cd build

# Configure the project
echo "Configuring project..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Check if configuration was successful
if [ $? -ne 0 ]; then
    echo "Error: CMake configuration failed."
    exit 1
fi

# Build the project
echo "Building project..."
cmake --build . --config Release

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Build failed."
    exit 1
fi

echo "Build completed successfully!"
echo "Executables are in the build directory."

cd .. 