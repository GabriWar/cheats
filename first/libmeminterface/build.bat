:: filepath: /home/gabriwar/Desktop/gitthings/cheats/first/libmeminterface/build.bat
@echo off
set "LD_LIBRARY_PATH=%cd%\lib"
g++ -std=c++20 -I include\libmem\ -L lib\ -llibmem -o test.exe test.cpp
if errorlevel 1 exit /b %errorlevel%
:: Make the output executable (not needed on Windows, but kept for parity)
:: Invoke passing arguments passed to the script
test.exe %*