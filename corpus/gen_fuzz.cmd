@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
uv run --locked --project "%SCRIPT_DIR%.." python "%SCRIPT_DIR%gen_fuzz.py" %*
set "RESULT=%ERRORLEVEL%"
endlocal & exit /b %RESULT%
