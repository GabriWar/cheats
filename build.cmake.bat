@echo off
setlocal

:: Check if CMake is installed
where cmake >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo CMake is not installed or not in PATH
    echo Please install CMake from: https://cmake.org/download/
    exit /b 1
)

:: Check if Ninja is installed
where ninja >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Ninja is not installed or not in PATH
    echo Please install Ninja from: https://ninja-build.org/
    exit /b 1
)

:: Set MinGW paths
set MINGW_PATH=C:\mingw64
if not exist "%MINGW_PATH%\bin\g++.exe" (
    echo MinGW not found at %MINGW_PATH%
    echo Please install MinGW-w64 to C:\mingw64 or update the path in this script
    exit /b 1
)

:: Create build directory
if not exist build mkdir build
cd build

:: Configure and build
cmake .. -G "Ninja" ^
    -DCMAKE_C_COMPILER="%MINGW_PATH%\bin\gcc.exe" ^
    -DCMAKE_CXX_COMPILER="%MINGW_PATH%\bin\g++.exe" ^
    -DCMAKE_MAKE_PROGRAM=ninja

if %ERRORLEVEL% neq 0 (
    echo CMake configuration failed
    exit /b 1
)

cmake --build .
if %ERRORLEVEL% neq 0 (
    echo Build failed
    exit /b 1
)

:: Copy the executable to the root directory
copy test.exe ..\test.exe

echo Build successful!
cd .. 