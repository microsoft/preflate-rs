@echo off
:: profile_container.cmd
::
:: Non-kernel user-space profiler for preflate container compression.
:: Runs inside WSL so that valgrind (Linux) is available.
::
:: Usage from a Windows terminal:
::   profile_container.cmd [options]
::   profile_container.cmd --input samples --top 30
::   profile_container.cmd --no-build --keep --filter preflate
::
:: All arguments are forwarded verbatim to profile_container.py.
::
:: Requirements inside WSL:
::   valgrind   (sudo apt install valgrind)
::   uv         (manages the project Python environment)
::   Rust/cargo (curl https://sh.rustup.rs | sh)

setlocal

for %%I in ("%~dp0..") do set "REPO_WIN=%%~fI"

:: Verify WSL is available
where wsl >nul 2>&1
if errorlevel 1 (
    echo ERROR: WSL not found. This script requires Windows Subsystem for Linux.
    exit /b 1
)

set "REPO_WSL="
for /f "delims=" %%I in ('wsl --exec wslpath -a "%REPO_WIN%"') do set "REPO_WSL=%%I"
if not defined REPO_WSL (
    echo ERROR: Could not resolve the repository path inside WSL.
    exit /b 1
)

echo Running profiler inside WSL...
echo Repo : %REPO_WSL%
echo.

wsl --exec bash -lc "cd '%REPO_WSL%' && UV_PROJECT_ENVIRONMENT=.venv-wsl UV_LINK_MODE=copy uv run --locked corpus/profile_container.py %*"
set "RESULT=%ERRORLEVEL%"

endlocal & exit /b %RESULT%
