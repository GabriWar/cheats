@echo off
setlocal enabledelayedexpansion

:: Common MinGW installation paths
set "MINGW_PATHS=C:\MinGW\bin;C:\MinGW64\bin;C:\msys64\mingw64\bin;C:\msys64\mingw32\bin"

:: Check if MinGW is in PATH or common locations
set "FOUND_MINGW=0"
for %%p in (%MINGW_PATHS%) do (
    if exist "%%p\gcc.exe" (
        set "PATH=%%p;%PATH%"
        set "FOUND_MINGW=1"
        echo Found MinGW at: %%p
        goto :found_mingw
    )
)

if %FOUND_MINGW%==0 (
    echo MinGW not found in PATH or common locations!
    echo Please install MinGW and add it to your PATH.
    echo You can download it from: https://sourceforge.net/projects/mingw/
    echo Or use MSYS2: https://www.msys2.org/
    exit /b 1
)

:found_mingw
:: Check if CMake is in PATH
where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo CMake not found in PATH!
    echo Please install CMake and add it to your PATH.
    echo You can download it from: https://cmake.org/download/
    exit /b 1
)

echo Creating build directory...
if not exist build mkdir build
cd build

echo Configuring with MinGW...
cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ..

if %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed!
    echo Please check your MinGW installation and try again.
    exit /b %ERRORLEVEL%
)

echo Building project...
mingw32-make

if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    echo Executables are in the build directory.
) else (
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

cd .. 