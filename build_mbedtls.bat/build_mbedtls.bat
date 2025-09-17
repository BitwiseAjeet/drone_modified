@echo off
REM Fixed Build MbedTLS for MinGW on Windows
REM Run this script from your project directory

echo Building MbedTLS for MinGW...

REM Create build directory
if not exist "third_party" mkdir third_party
cd third_party

REM Remove existing mbedtls if it exists to start fresh
if exist "mbedtls" (
    echo Removing existing MbedTLS directory...
    rmdir /s /q mbedtls
)

REM Download MbedTLS with submodules
echo Downloading MbedTLS with submodules...
git clone --recursive --depth 1 --branch v3.6.2 https://github.com/Mbed-TLS/mbedtls.git
if %errorlevel% neq 0 (
    echo Failed to download MbedTLS
    pause
    exit /b 1
)

cd mbedtls

REM Make sure all submodules are updated
echo Updating submodules...
git submodule update --init --recursive
if %errorlevel% neq 0 (
    echo Failed to update submodules
    pause
    exit /b 1
)

REM Create build directory
if not exist "build" mkdir build
cd build

REM Configure with CMake for MinGW
echo Configuring MbedTLS...
cmake -G "MinGW Makefiles" ^
    -DCMAKE_C_COMPILER=gcc ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DENABLE_PROGRAMS=OFF ^
    -DENABLE_TESTING=OFF ^
    -DMBEDTLS_FATAL_WARNINGS=OFF ^
    -DCMAKE_INSTALL_PREFIX=../../mbedtls-install ^
    ..

if %errorlevel% neq 0 (
    echo CMake configuration failed
    echo.
    echo Trying alternative configuration...
    cmake -G "MinGW Makefiles" ^
        -DCMAKE_C_COMPILER=gcc ^
        -DCMAKE_BUILD_TYPE=Release ^
        -DENABLE_PROGRAMS=OFF ^
        -DENABLE_TESTING=OFF ^
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF ^
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON ^
        -DCMAKE_INSTALL_PREFIX=../../mbedtls-install ^
        ..
    
    if %errorlevel% neq 0 (
        echo CMake configuration still failed
        pause
        exit /b 1
    )
)

REM Build the library
echo Building MbedTLS...
mingw32-make -j2

if %errorlevel% neq 0 (
    echo Build failed, trying single-threaded build...
    mingw32-make
    if %errorlevel% neq 0 (
        echo Build failed
        pause
        exit /b 1
    )
)

REM Install the library
echo Installing MbedTLS...
mingw32-make install

if %errorlevel% neq 0 (
    echo Installation failed
    pause
    exit /b 1
)

cd ../../../

echo.
echo ========================================
echo MbedTLS built successfully!
echo ========================================
echo Headers: ./third_party/mbedtls-install/include
echo Libraries: ./third_party/mbedtls-install/lib
echo.
echo Files created:
dir /b third_party\mbedtls-install\lib\*.a 2>nul
echo.
echo You can now use the "Build Sender (with local MbedTLS)" task in VS Code
echo ========================================

pause