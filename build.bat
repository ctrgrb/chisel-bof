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
rem The `del` above is best-effort: if a running process still has the DLL mapped
rem (a test client, an explorer thumbnail, an AV scan) the delete FAILS quietly, the
rem `if not exist` guards below then PASS on the stale file, and ld cannot overwrite
rem it either ("cannot open output file ... Permission denied") - which is how a
rem stale-but-fresh-timestamped DLL got shipped twice.  Fail loudly instead.
if exist "%ROOT%build\chiselpe.dll" echo OUTPUT LOCKED: build\chiselpe.dll is still loaded by a running process - stop the test client first & exit /b 9
if exist "%ROOT%build\pebdrv.exe"   echo OUTPUT LOCKED: build\pebdrv.exe is still running - stop it first & exit /b 9

rem See tools\build-deps.bat: these five diagnostics are errors by default on
rem gcc >= 14, warnings on older toolchains.  Pin them as errors so the payload
rem sources stay buildable on a current mingw-w64 without surprises.  PORT pins
rem the codegen defaults a no-CRT payload depends on (no stack protector, no
rem _FORTIFY_SOURCE, no PIC/PIE - see the same block there).  And note there is no
rem `-w` on any compile line here: `-w` would suppress the warnings before
rem -Werror= promotes them, hiding exactly the two bugs that a modern gcc then
rem refused to build (an undeclared winsock select() and mbedtls_ssl_session_free()
rem called on an mbedtls_ssl_context).
rem   -fno-tree-loop-distribute-patterns: src/crypto.c *defines* memcpy, memset,
rem   memmove, memcmp, strlen, strcmp and strchr.  At -O2 GCC 12 and newer rewrite
rem   those byte-loop bodies into calls to the same functions, which on a modern
rem   toolchain is infinite self-recursion - the client hangs before the first
rem   connect(), prints nothing, and the server never sees a connection.  8.1.0
rem   only ran that pass at -O3, so this never showed on the reference box.
set PORT=-fno-stack-protector -fno-pic -fno-pie -U_FORTIFY_SOURCE -fno-tree-loop-distribute-patterns
set STRICT=-Werror=implicit-function-declaration -Werror=implicit-int -Werror=int-conversion -Werror=incompatible-pointer-types -Werror=discarded-qualifiers
rem Escape hatch for toolchains whose gcc *specs* inject extra options after the
rem command line (some MSYS2 builds re-add -D_FORTIFY_SOURCE / a stack protector,
rem which a -nostdlib link rejects).  Append your own flags without editing the
rem script:  set EXTRA_CFLAGS=-D_FORTIFY_SOURCE=0 && build.bat
set EXTRA=%EXTRA_CFLAGS%

%RUN% -O2 -std=c11 %PORT% %STRICT% %EXTRA% -DPE_MAIN -I "%ROOT%src" -I "%ROOT%deps\mbedinc" -I "%ROOT%deps\mbedtls-3.6.7\include" -c "%ROOT%src\stock.c" -o "%ROOT%build\chiselpe.o" > "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\chiselpe.o" echo COMPILE FAILED - see build\build.log & exit /b 9

%RUN% -O2 -std=c11 %PORT% %STRICT% %EXTRA% -I "%ROOT%src" -c "%ROOT%src\crypto.c"  -o "%ROOT%build\obj_crypto.o"  >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\obj_crypto.o" echo CRYPTO COMPILE FAILED - see build\build.log & exit /b 9
%RUN% -O2 -std=c11 %PORT% %STRICT% %EXTRA% -I "%ROOT%src" -c "%ROOT%src\x25519.c"  -o "%ROOT%build\obj_x25519.o"  >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\obj_x25519.o" echo X25519 COMPILE FAILED - see build\build.log & exit /b 9

rem -Wl,--no-undefined is load-bearing for a payload that must import nothing but
rem ws2_32 + kernel32: with -nostdlib, an accidental libc reference (a stray
rem memcpy/printf the compiler decided to call out-of-line, a library file that
rem suddenly matters) would otherwise link into a DLL whose calls jump into
rem garbage at runtime.  It must be a build failure instead.
rem -Wl,--no-undefined is load-bearing for a payload that must import nothing but
rem ws2_32 + kernel32: with -nostdlib, an accidental libc reference (a stray
rem memcpy/printf the compiler decided to call out-of-line, a library file that
rem suddenly matters) would otherwise link into a DLL whose calls jump into
rem garbage at runtime.  It must be a build failure instead.
rem
rem Do NOT add `-no-pie` here: the PIE pin is a COMPILE-side thing (%PORT% below).
rem Passed to the link of a -shared -nostdlib image it produces a DLL that the
rem Windows loader refuses to initialise - LoadLibrary fails with 1114
rem (ERROR_DLL_INIT_FAILED), with no other clue.  Verified both ways on this
rem tree: same objects, link with -no-pie -> 1114, without -> loads and runs.
%RUN% -nostdlib -shared -Wl,--dynamicbase -Wl,--no-undefined "-Wl,--exclude-libs,MBED.a" "-Wl,--strip-all" "%ROOT%build\chiselpe.o" "%ROOT%build\obj_crypto.o" "%ROOT%build\obj_x25519.o" "%ROOT%deps\MBED.a" "%ROOT%deps\chiselpe.def" -lgcc "%ROOT%deps\WS2_32nat.a" -lkernel32 -o "%ROOT%build\chiselpe.dll" >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\chiselpe.dll" echo LINK FAILED - see build\build.log & exit /b 9

rem test driver (normal CRT build, not part of the payload)
%RUN% -O2 -w "%ROOT%tools\pebdrv.c" -o "%ROOT%build\pebdrv.exe" >> "%ROOT%build\build.log" 2>&1
if not exist "%ROOT%build\pebdrv.exe" echo DRIVER COMPILE FAILED - see build\build.log & exit /b 9

findstr /i /c:"error" /c:"undefined" /c:"cannot open" "%ROOT%build\build.log" >nul 2>&1
if not errorlevel 1 echo WARNING: build.log contains error-like lines & exit /b 8
echo BUILD OK: build\chiselpe.dll + build\pebdrv.exe
exit /b 0
