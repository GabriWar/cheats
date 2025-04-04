@echo off
setlocal

:: Set paths
set INCLUDE_PATH=%~dp0includeWIN\libmem
set LIB_PATH=%~dp0libWIN\release

:: Get MSVC and SDK versions
set /p MSVC_VERSION=<%~dp0MSVC_VERSION.txt
set /p WINSDK_VERSION=<%~dp0WINSDK_VERSION.txt

:: Compile
cl.exe /std:c++20 /I"%INCLUDE_PATH%" /link /LIBPATH:"%LIB_PATH%" libmem.lib /out:test.exe test.cpp

if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

:: Run the program with any passed arguments
test.exe %* 