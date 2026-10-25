@echo off
rem underhood CLI launcher for Windows cmd and PowerShell (bin/uh is the bash one).
rem Put this bin folder on PATH, then run uh as usual: uh scan --list, uh kb search Terraria, ...
rem Uses uv when available (set UH_NO_UV=1 to skip it); otherwise python on PATH,
rem which then needs: pip install pillow numpy pyyaml
setlocal
rem The repo root, resolved without a trailing backslash: in "C:\path\" the \" escapes the closing
rem quote for uv and python, which mangles every argument after it. No cd: relative paths stay the caller's.
for %%I in ("%~dp0..") do set "UH_ROOT=%%~fI"
if defined UH_NO_UV goto python
where uv >nul 2>&1 || goto python
uv run --quiet --project "%UH_ROOT%" python -m uh %*
exit /b %ERRORLEVEL%

:python
if defined PYTHONPATH (set "PYTHONPATH=%UH_ROOT%;%PYTHONPATH%") else set "PYTHONPATH=%UH_ROOT%"
where python >nul 2>&1 || goto nopython
python -m uh %*
exit /b %ERRORLEVEL%

:nopython
echo uh: neither uv nor python is on PATH. Install uv: https://docs.astral.sh/uv/ 1>&2
exit /b 1
