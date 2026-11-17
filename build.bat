@echo off
rem build.bat - build chiselpe.dll: a bare x64 BOF-PE DLL implementing the
rem jpillora/chisel client (v1.12.1 wire, chisel-v3) with no CRT.
rem
rem Requires mingw-w64 x86_64 (tested: 8.1.0). Override with:
rem   set TOOLCHAIN=C:\path\to\mingw64\bin
rem On hosts where gcc's cc1.exe fails to start standalone (D_PAGED quirk on
rem some hardened Windows builds) the tested configuration runs gcc under
rem "gdb --batch -ex run --args". GDBWRAP=1 (default) does that; GDBWRAP=0
rem invokes gcc directly.
setlocal
set ROOT=%~dp0
if "%TOOLCHAIN%"=="" (set GCCC=gcc& set GDBB=gdb) else (set GCCC="%TOOLCHAIN%\gcc.exe"& set GDBB="%TOOLCHAIN%\gdb.exe")
if "%GDBWRAP%"=="" (if "%TOOLCHAIN%"=="" (set GDBWRAP=0) else (set GDBWRAP=1))
if "%GDBWRAP%"=="1" (set RUN=%GDBB% --batch -ex run --args %GCCC%) else (set RUN=%GCCC%)
if "%TOOLCHAIN%"=="" where gcc >nul 2>&1 || (echo gcc not on PATH - set TOOLCHAIN to your mingw-w64 bin directory, e.g. "set TOOLCHAIN=C:\mingw64\bin" ^&^& build.bat& exit /b 9)
if not exist "%ROOT%build" mkdir "%ROOT%build"

rem ---- build everything from scratch: `build.bat clean` first wipes every
rem generated artifact (deps AND outputs) if you want to force a full rebuild. ----
if /i "%~1"=="clean" (
  rmdir /s /q "%ROOT%build" 2>nul
  del /q "%ROOT%deps\MBED.a" "%ROOT%deps\WS2_32nat.a" 2>nul
  for /d %%D in ("%ROOT%deps\mbedtls-*") do rmdir /s /q "%%D"
  del /q "%ROOT%deps\_mbedtls-*.tar.gz" 2>nul
  echo cleaned: deps and build outputs removed
)

rem ---- nothing binary is published, so the crypto static lib and the winsock
rem import lib are built here from source when absent (fetch + verify Mbed TLS,
rem compile with deps\mbedinc, ar, dlltool).  See tools\build-deps.bat. ----
if not exist "%ROOT%deps\MBED.a"       call "%ROOT%tools\build-deps.bat" || exit /b 9
if not exist "%ROOT%deps\WS2_32nat.a"  call "%ROOT%tools\build-deps.bat" || exit /b 9

rem Remove every intermediate and output first: a failed compile leaves the
rem previous .o/.dll in place, and the `if not exist` checks below would then
rem pass and LINK A STALE OBJECT - the DLL is relinked (fresh timestamp, old
rem code) and the only clue is a WARNING line.  Seen twice; never again.
del /q "%ROOT%build\chiselpe.o"     2>nul
del /q "%ROOT%build\obj_crypto.o"   2>nul
del /q "%ROOT%build\obj_x25519.o"   2>nul
del /q "%ROOT%build\chiselpe.dll"   2>nul
del /q "%ROOT%build\pebdrv.exe"     2>nul

%RUN% -O2 -std=c11 -w -DPE_MAIN -I "%ROOT%src" -I "%ROOT%deps\mbedinc" -I "%ROOT%deps\mbedtls-3.6.7\include" -c "%ROOT%src\stock.c" -o "%ROOT%build\chiselpe.o" > "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\chiselpe.o" echo COMPILE FAILED - see build\build.log & exit /b 9

%RUN% -O2 -std=c11 -w -I "%ROOT%src" -c "%ROOT%src\crypto.c"  -o "%ROOT%build\obj_crypto.o"  >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\obj_crypto.o" echo CRYPTO COMPILE FAILED - see build\build.log & exit /b 9
%RUN% -O2 -std=c11 -w -I "%ROOT%src" -c "%ROOT%src\x25519.c"  -o "%ROOT%build\obj_x25519.o"  >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\obj_x25519.o" echo X25519 COMPILE FAILED - see build\build.log & exit /b 9

%RUN% -nostdlib -shared -Wl,--dynamicbase "-Wl,--exclude-libs,MBED.a" "-Wl,--strip-all" "%ROOT%build\chiselpe.o" "%ROOT%build\obj_crypto.o" "%ROOT%build\obj_x25519.o" "%ROOT%deps\MBED.a" "%ROOT%deps\chiselpe.def" -lgcc "%ROOT%deps\WS2_32nat.a" -lkernel32 -o "%ROOT%build\chiselpe.dll" >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\chiselpe.dll" echo LINK FAILED - see build\build.log & exit /b 9

rem test driver (normal CRT build, not part of the payload)
%RUN% -O2 -w "%ROOT%tools\pebdrv.c" -o "%ROOT%build\pebdrv.exe" >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\pebdrv.exe" echo DRIVER COMPILE FAILED - see build\build.log & exit /b 9

findstr /i /c:"error" /c:"undefined" /c:"cannot open" "%ROOT%build\build.log" >nul 2>&1
if not errorlevel 1 echo WARNING: build.log contains error-like lines & exit /b 8
echo BUILD OK: build\chiselpe.dll + build\pebdrv.exe
exit /b 0
