@echo off
REM Build CytadelExposure.exe as a single windowed Windows executable.
setlocal

echo === Installing dependencies ===
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo === Running tests ===
python -m pytest -q
if errorlevel 1 goto :error

echo === Building executable with PyInstaller ===
pyinstaller --noconfirm --onefile --windowed ^
  --icon assets\app.ico ^
  --add-data "assets;assets" ^
  --name CytadelExposure ^
  --collect-submodules reportlab ^
  main.py
if errorlevel 1 goto :error

echo.
echo === Build complete: dist\CytadelExposure.exe ===
echo Branding (icon + cover/UI logos) is bundled from the assets\ folder.
goto :eof

:error
echo.
echo *** BUILD FAILED ***
exit /b 1
