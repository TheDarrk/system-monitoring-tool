@echo off
echo [1/3] Installing dependencies...
pip install cx_Freeze pywin32
if errorlevel 1 (
    echo Error installing dependencies!
    pause
    exit /b 1
)

echo [2/3] Building executable...
python setup.py build
if errorlevel 1 (
    echo Error building executable!
    pause
    exit /b 1
)

echo [3/3] Build complete! Check the /build folder
pause