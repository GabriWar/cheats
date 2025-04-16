#!/bin/bash
# Cross-compile with static linking

MINGW_PREFIX=x86_64-w64-mingw32

# Set compiler flags
CFLAGS="-std=c++20 -O2"
LDFLAGS="-static-libgcc -static-libstdc++ -static"
INCLUDES="-I LIBMEMWIN/includeWIN/libmem/"
LIBS="-L LIBMEMWIN/libWIN/release/ -llibmem"

# Compile the program with static linking of runtime libraries
${MINGW_PREFIX}-g++ ${CFLAGS} ${INCLUDES} -o test.exe test.cpp ${LIBS} ${LDFLAGS}

if [ $? -ne 0 ]; then
    echo "Full static linking failed, trying alternate build method..."
    # Try with just static C++ runtime libraries
    ${MINGW_PREFIX}-g++ ${CFLAGS} ${INCLUDES} -o test.exe test.cpp ${LIBS} -static-libgcc -static-libstdc++
    
    if [ $? -ne 0 ]; then
        echo "Build failed."
        exit 1
    fi
    
    # Find and copy pthread DLL if needed
    MINGW_PATH=$(dirname $(which ${MINGW_PREFIX}-g++))/../${MINGW_PREFIX}/bin
    echo "Copying pthread DLL from: ${MINGW_PATH}"
    cp ${MINGW_PATH}/libwinpthread-1.dll . 2>/dev/null
    
    if [ ! -f dist/libwinpthread-1.dll ]; then
        echo "Warning: Could not find libwinpthread-1.dll in expected location"
        # Try alternate locations
        cp /usr/lib/gcc/${MINGW_PREFIX}/*/libwinpthread-1.dll . 2>/dev/null || \
        cp /usr/${MINGW_PREFIX}/lib/libwinpthread-1.dll . 2>/dev/null
    fi
fi

echo "Creating  package..."
cp LIBMEMWIN/libWIN/release/libmem.dll .

echo ""
echo "IMPORTANT: To run on Windows, you may need:"
echo "1. Visual C++ Redistributable for libmem.dll"
echo "2. Run as Administrator for process memory access"