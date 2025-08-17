@echo off
REM Ruby2FA Quickstart Script
echo Ruby2FA Quickstart Script
echo This script will set up Ruby2FA and its dependencies automatically.
echo Make sure to review the script before running it! ^>^:3
echo.
echo Press any key to continue...
pause >nul
echo.

REM Check for python
where python >nul 2>nul
if errorlevel 1 (
    echo Python not found! Please install Python 3.8+ and rerun this script.
    echo Download Python from https://www.python.org/downloads/
    echo Or use winget to install Python 3.8+ by typing in Powershell: winget install python
    goto :pauseAndExit
)

REM Check for pip
python -m pip --version >nul 2>nul
if errorlevel 1 (
    echo pip not found! Installing pip...
    python -m ensurepip --upgrade
    if errorlevel 1 (
        echo Failed to install pip. Please install pip manually.
        goto :pauseAndExit
    )
)

REM Install requirements
echo Installing Python dependencies...
echo This will install the Python modules via pip that are required to run Ruby2FA, such as: PyQt5, opencv-python, numpy, pyzbar, pillow, and pyotp.
python -m pip install --user -r requirements.txt
if errorlevel 1 (
    echo Dependency install failed!
    goto :pauseAndExit
)

REM Check for protobuf
python -c "import google.protobuf" >nul 2>nul
if errorlevel 1 (
    echo Installing protobuf...
    echo protobuf and grpcio-tools are also used to import Google Authenticator import QR text files.
    python -m pip install --user protobuf
)

REM Compile OtpMigration_pb2 if not present
if not exist addtl\OtpMigration_pb2.py (
    if exist addtl\OtpMigration.proto (
        echo Compiling OtpMigration.proto...
        echo OtpMigration.proto and grpcio-tools are also used to import Google Authenticator import QR text files.
        python -m pip install --user grpcio-tools
        python -m grpc_tools.protoc -Iaddtl --python_out=addtl addtl\OtpMigration.proto
        if errorlevel 1 (
            echo Failed to compile proto!
            goto :pauseAndExit
        )
    ) else (
        echo Warning: addtl\OtpMigration.proto not found. Google Auth import may not work. The script is fully functional, but you will not be able to import Google Authenticator import QR text files, and will have to manually re-add all accounts.
        echo The script is fully functional, but you will not be able to import Google Authenticator import QR text files, and will have to manually re-add all accounts.
    )
)

REM Create rubykeys dir if missing
if not exist rubykeys (
    mkdir rubykeys
    echo Created rubykeys directory.
    echo This directory is used to store your encrypted secrets. If you lose it, you will not be able to access your accounts.
    echo Make sure to back it up somewhere safe once you've added all your accounts and the files are generated!
    echo.
)

REM Create Ruby2FA shortcut in current folder
set "shortcutName=Ruby2FA.lnk"
set "targetPath=%~dp0ruby2fa.py"
set "pythonPath="
for /f "delims=" %%i in ('where python') do (
    set "pythonPath=%%i"
    goto :foundPython
)
:foundPython
if not defined pythonPath (
    set "pythonPath=python"
)
echo Creating shortcut in this folder for Ruby2FA...
    powershell -Command ^
 "$s=(New-Object -COM WScript.Shell).CreateShortcut('%~dp0%shortcutName%');" ^
 "$s.TargetPath='%pythonPath%';" ^
 "$s.Arguments='\"%targetPath%\"';" ^
 "$s.WorkingDirectory='%~dp0';" ^
 "$s.Save()"
echo Shortcut created as Ruby2FA.lnk in this folder!
echo You can double-click it to launch Ruby2FA.

echo Setup complete! To start Ruby2FA from the command line in the folder you ran this script in, run: python ruby2fa.py
echo.
echo Meowdy! Ruby2FA is ready to go! ^>^.^<
echo If you have any questions, feel free to email rubyaftermidnight@gmail.com! ^:3

goto :pauseAndExit

:pauseAndExit
echo.
echo Press any key to close this window...
pause >nul
exit /b 1
