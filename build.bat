@echo off
echo Building BlockerChecker...

REM Create build directory
if not exist "build" mkdir build
cd build

REM Configure with CMake
cmake .. -G "Visual Studio 17 2022" -A x64

REM Build the project
cmake --build . --config Release

echo.
echo Build completed! Executable is in build/bin/Release/
echo.
echo To run the application:
echo 1. Right-click on build/bin/Release/BlockerChecker.exe
echo 2. Select "Run as administrator"
echo 3. The context menu item will be added permanently
echo.
