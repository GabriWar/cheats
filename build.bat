@echo off
setlocal

:: Compile using g++
g++ -std=c++17 -I LIBMEMWIN\includeWIN\libmem -L LIBMEMWIN\libWIN\release -llibmem -o test.exe test.cpp

if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

:: Run the program with any passed arguments
test.exe %*