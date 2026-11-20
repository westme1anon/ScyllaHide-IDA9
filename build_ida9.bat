@echo off
setlocal enableextensions
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Please install Visual Studio with C++ build tools.
    exit /b 1
)

set "MSBUILD="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
    set "MSBUILD=%%i"
)
if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found.
    exit /b 1
)

if "%PLATFORM_TOOLSET%"=="" set "PLATFORM_TOOLSET=v143"

echo [1/4] Building x64 Scylla, HookLibrary, ScyllaHideIDAServer...
"%MSBUILD%" ScyllaHide.sln /t:Scylla,HookLibrary,ScyllaHideIDAServer /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%PLATFORM_TOOLSET% /p:TrackFileAccess=false /v:minimal
if errorlevel 1 exit /b 1

echo [2/4] Building Win32 Scylla, HookLibrary, ScyllaHideIDAServer...
"%MSBUILD%" ScyllaHide.sln /t:Scylla,HookLibrary,ScyllaHideIDAServer /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=%PLATFORM_TOOLSET% /p:TrackFileAccess=false /v:minimal
if errorlevel 1 exit /b 1

echo [3/4] Building ScyllaHideIDAProPlugin for IDA 9.0 SDK...
"%MSBUILD%" ScyllaHide.sln /t:ScyllaHideIDAProPlugin /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%PLATFORM_TOOLSET% /p:TrackFileAccess=false /p:IdaSdkVersion=90 /v:minimal
if errorlevel 1 exit /b 1

echo [4/4] Building ScyllaHideIDAProPlugin for IDA 9.4 SDK...
"%MSBUILD%" ScyllaHide.sln /t:ScyllaHideIDAProPlugin /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%PLATFORM_TOOLSET% /p:TrackFileAccess=false /p:IdaSdkVersion=94 /v:minimal
if errorlevel 1 exit /b 1

echo Packaging Release\IDA9.0\ScyllaHide and Release\IDA9.4\ScyllaHide...
if exist Release\IDA9.0 rmdir /s /q Release\IDA9.0
if exist Release\IDA9.4 rmdir /s /q Release\IDA9.4
mkdir Release\IDA9.0\ScyllaHide
mkdir Release\IDA9.4\ScyllaHide

copy /y /b ScyllaHideIDAProPlugin\ida-plugin.json Release\IDA9.0\ScyllaHide\ >nul
copy /y /b build\Release\x64\ScyllaHideIDAProPlugin_ida90.dll Release\IDA9.0\ScyllaHide\ScyllaHideIDAProPlugin.dll >nul
copy /y /b build\Release\x64\HookLibraryx64.dll Release\IDA9.0\ScyllaHide\ >nul
copy /y /b build\Release\Win32\HookLibraryx86.dll Release\IDA9.0\ScyllaHide\ >nul
copy /y /b build\Release\x64\ScyllaHideIDAServerx64.exe Release\IDA9.0\ScyllaHide\ >nul
copy /y /b build\Release\Win32\ScyllaHideIDAServerx86.exe Release\IDA9.0\ScyllaHide\ >nul
copy /y /b ConfigCollection\scylla_hide.ini Release\IDA9.0\ScyllaHide\ >nul

copy /y /b ScyllaHideIDAProPlugin\ida-plugin.json Release\IDA9.4\ScyllaHide\ >nul
copy /y /b build\Release\x64\ScyllaHideIDAProPlugin_ida94.dll Release\IDA9.4\ScyllaHide\ScyllaHideIDAProPlugin.dll >nul
copy /y /b build\Release\x64\HookLibraryx64.dll Release\IDA9.4\ScyllaHide\ >nul
copy /y /b build\Release\Win32\HookLibraryx86.dll Release\IDA9.4\ScyllaHide\ >nul
copy /y /b build\Release\x64\ScyllaHideIDAServerx64.exe Release\IDA9.4\ScyllaHide\ >nul
copy /y /b build\Release\Win32\ScyllaHideIDAServerx86.exe Release\IDA9.4\ScyllaHide\ >nul
copy /y /b ConfigCollection\scylla_hide.ini Release\IDA9.4\ScyllaHide\ >nul

echo.
echo Build succeeded!
echo   IDA 9.0 plugin folder: %~dp0Release\IDA9.0\ScyllaHide\
echo   IDA 9.4 plugin folder: %~dp0Release\IDA9.4\ScyllaHide\
exit /b 0
