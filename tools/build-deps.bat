@echo off
rem build-deps.bat - produce the two .a files build.bat links against, from text
rem sources only.  Nothing binary is published in this repository:
rem
rem   deps\MBED.a        static Mbed TLS built from the pinned upstream sources
rem                      (fetched + hash-verified below), with OUR trimmed config
rem                      (deps\mbedinc) first on the include path, plus our own
rem                      src\mbedfmt.c snprintf shim.
rem   deps\WS2_32nat.a   winsock import library generated from the published text
rem                      deps\WS2_32nat.def with dlltool.
rem
rem build.bat calls this automatically whenever either file is missing, so a
rem clean checkout builds with a single command.
rem
rem Toolchain: same rules as build.bat (mingw-w64 x86_64; set TOOLCHAIN to point
rem at it; GDBWRAP=1 default runs gcc/ar/dlltool under "gdb --batch -ex run
rem --args", required on hosts where cc1.exe cannot start standalone).
setlocal enabledelayedexpansion
rem Canonical absolute folder root.  `%~dp0..\` + `%ROOT%deps` would concatenate
rem into a literal `tools\..deps` directory, so resolve the path properly.
for %%I in ("%~dp0..") do set ROOT=%%~fI\
set VER=3.6.7
rem GitHub source archive for the v3.6.7 tag.  Pinned by sha256: the build refuses
rem to link against a crypto tree that is not exactly this one.  `library/`,
rem `include/` and `3rdparty/` of this archive were verified identical to the
rem tree this client was developed and tested against.
set SHA256=7312b70b067b6a271961c8d36c3b8f9ba3e86fe6b26f18af13cd70430ee52ed1
set URL=https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v%VER%.tar.gz

if "%TOOLCHAIN%"=="" (set GCCC=gcc& set GDBB=gdb& set ARB=ar& set DLLT=dlltool) else (set GCCC="%TOOLCHAIN%\gcc.exe"& set GDBB="%TOOLCHAIN%\gdb.exe"& set ARB="%TOOLCHAIN%\ar.exe"& set DLLT="%TOOLCHAIN%\dlltool.exe")
if "%GDBWRAP%"=="" (if "%TOOLCHAIN%"=="" (set GDBWRAP=0) else (set GDBWRAP=1))
if "%GDBWRAP%"=="1" (set RUN=%GDBB% --batch -ex run --args %GCCC%& set RUNAR=%GDBB% --batch -ex run --args %ARB%& set RUNDT=%GDBB% --batch -ex run --args %DLLT%) else (set RUN=%GCCC%& set RUNAR=%ARB%& set RUNDT=%DLLT%)

if not exist "%ROOT%deps" mkdir "%ROOT%deps"
if not exist "%ROOT%build\mbedobj" mkdir "%ROOT%build\mbedobj"

rem ---- 1. fetch + verify + unpack Mbed TLS (skipped if already unpacked) ----
if not exist "%ROOT%deps\mbedtls-%VER%\library" (
  echo fetching Mbed TLS v%VER% ...
  if not exist "%ROOT%deps\_mbedtls-v%VER%.tar.gz" curl -fL --retry 3 -o "%ROOT%deps\_mbedtls-v%VER%.tar.gz" "%URL%" || (echo FETCH FAILED - download %URL% by hand and unpack into deps\, then re-run & exit /b 9)
  set GOT=
  for /f %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%ROOT%deps\_mbedtls-v%VER%.tar.gz').Hash"') do set GOT=%%H
  if /i not "!GOT!"=="%SHA256%" (echo SHA256 MISMATCH: got !GOT! expected %SHA256% & exit /b 9)
  tar -xzf "%ROOT%deps\_mbedtls-v%VER%.tar.gz" -C "%ROOT%deps" || (echo EXTRACT FAILED & exit /b 9)
  echo verified sha256 of Mbed TLS v%VER%
)

rem ---- 2. compile the whole library with our config FIRST on the include path,
rem         so deps\mbedinc\mbedtls\mbedtls_config.h wins over upstream's.  The
rem         config decides which .c files contribute code, so it is
rem         load-bearing: a different config means a different MBED.a (and a
rem         client that cannot parse public CA chains). ----
del /q "%ROOT%build\mbedobj\*.o" 2>nul
del /q "%ROOT%build\mbedlog.txt" 2>nul
rem These five diagnostics became ERRORS by default in gcc 14 (i.e. every current
rem mingw-w64 / MSYS2 toolchain) while older toolchains only warned.  Pinning them
rem as errors here is what makes "it compiled on my box" mean something: on a
rem modern box the same source now fails the same way, rather than stopping the
rem build with a wall of `implicit declaration of ...`.
rem Toolchain defaults that must be pinned for a -nostdlib payload: MSYS2 /
rem current mingw-w64 gcc specs add -fstack-protector-strong and
rem -D_FORTIFY_SOURCE (references to __stack_chk_fail/__stack_chk_guard/
rem __chk_fail that only exist in the C runtime -> with -Wl,--no-undefined they
rem stop the link, and without it they would silently become bogus imports), and
rem PIE-by-default codegen (this payload relies on the non-PIE/absolute-slot
rem shape that tools/pehl2dir.py audits, 587/587 in-image).
rem
rem There is deliberately NO `-w` here or in build.bat: `-w` suppresses warnings
rem BEFORE -Werror= promotes them, so with `-w` the pin above is decorative on
rem toolchains older than gcc 14 (it did hide exactly that: an undeclared winsock
rem select() and a wrong-pointer call in our own sources, both invisible here and
rem hard errors there).  Upstream Mbed TLS and our sources compile warning-free
rem with these flags; preprocessor noise is fixed at the source (see the
rem PSA_WANT_* note in deps\mbedinc\mbedtls\mbedtls_config.h), not silenced.
rem (-Wno-cpp does NOT suppress macro-redefinition warnings on older gcc; only
rem -Wp,-w does, and it would also hide genuine config mistakes.)
set PORT=-fno-stack-protector -fno-pic -fno-pie -U_FORTIFY_SOURCE -fno-tree-loop-distribute-patterns
set STRICT=-Werror=implicit-function-declaration -Werror=implicit-int -Werror=int-conversion -Werror=incompatible-pointer-types -Werror=discarded-qualifiers
rem See build.bat: EXTRA_CFLAGS appends your own flags (e.g. a spec re-injected
rem -D_FORTIFY_SOURCE) without editing this script.
set EXTRA=%EXTRA_CFLAGS%
rem `library\platform.c` is deliberately skipped.  It contributes only
rem mbedtls_platform_setup/teardown plus the win32 snprintf shims that platform.h
rem force-enables for EVERY __MINGW32__ build; nothing here references any of those
rem symbols (checked with nm over the whole object set), because calloc/free/
rem printf/snprintf are all overridden by macros in the config.  The shims call
rem UCRT `vsnprintf_s`, i.e. exactly the libc reference this no-CRT payload must
rem never carry - so the file is left out rather than declaring a prototype for a
rem function we do not implement.  build.bat links with -Wl,--no-undefined, which
rem turns any future accidental dependency into a hard error.
for %%F in ("%ROOT%deps\mbedtls-%VER%\library\*.c") do (
  if /i not "%%~nxF"=="platform.c" %RUN% -c -O2 -std=c11 %PORT% %STRICT% %EXTRA% -I "%ROOT%deps\mbedinc" -I "%ROOT%deps\mbedtls-%VER%\include" -o "%ROOT%build\mbedobj\%%~nxF.o" "%%F" >> "%ROOT%build\mbedlog.txt" 2>&1
)
%RUN% -c -O2 -std=c11 %PORT% %STRICT% %EXTRA% -o "%ROOT%build\mbedobj\mbedfmt.o" "%ROOT%src\mbedfmt.c" >> "%ROOT%build\mbedlog.txt" 2>&1

rem ---- 3. archive, in batches: ~110 quoted absolute object paths exceed cmd's
rem 8191-character command-line limit, which fails inside `ar` with no useful
rem message.  `rcs` inserts/updates, so repeated calls build one archive. ----
del /q "%ROOT%deps\MBED.a" 2>nul
set L=
set N=0
for %%F in ("%ROOT%build\mbedobj\*.o") do (
  set L=!L! "%%F"
  set /a N+=1
  if !N! geq 24 (
    %RUNAR% rcs "%ROOT%deps\MBED.a" !L! >> "%ROOT%build\mbedlog.txt" 2>&1
    set L=
    set N=0
  )
)
if not "!L!"=="" %RUNAR% rcs "%ROOT%deps\MBED.a" !L! >> "%ROOT%build\mbedlog.txt" 2>&1
if not exist "%ROOT%deps\MBED.a" echo MBED.a ARCHIVE FAILED - see build\mbedlog.txt & exit /b 9

rem ---- 4. winsock import library from the published .def ----
del /q "%ROOT%deps\WS2_32nat.a" 2>nul
%RUNDT% --no-leading-underscore --input-def "%ROOT%deps\WS2_32nat.def" --output-lib "%ROOT%deps\WS2_32nat.a" >> "%ROOT%build\mbedlog.txt" 2>&1
if not exist "%ROOT%deps\WS2_32nat.a" echo WS2_32nat.a GENERATION FAILED - see build\mbedlog.txt & exit /b 9

findstr /i /c:"error" /c:"undefined" /c:"No such file" "%ROOT%build\mbedlog.txt" >nul 2>&1
if not errorlevel 1 (echo WARNING: build\mbedlog.txt contains error-like lines & exit /b 8)
echo DEPS OK: deps\MBED.a + deps\WS2_32nat.a
exit /b 0
