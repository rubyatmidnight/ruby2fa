#!/bin/bash

echo "Ruby2FA Quickstart Script"
echo "This script will set up Ruby2FA and its dependencies automatically."
echo "Make sure to review the script before running it! >:3"
echo

# Check for python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python3 not found! Please install Python 3.8+ and rerun this script."
    echo "On macOS, you can install Python 3.8+ using Homebrew: brew install python@3.8"
    echo "On Windows 11, you can install Python 3.8+ via winget by opening an admin PowerShell window and running: `winget install python`"
    echo "On Linux, you can install Python 3.8+ using your package manager. For example, on Ubuntu: sudo apt install python3.8"
    exit 1
fi

# Check for pip
if ! command -v pip3 >/dev/null 2>&1; then
    echo "pip3 not found! Installing pip..."
    echo "pip3 is a package manager for Python. It is used to install Python modules that have extra features for development."
    python3 -m ensurepip --upgrade || { echo "Failed to install pip. Please install pip manually."; exit 1; }
fi

# Install requirements
echo "Installing Python dependencies..."
echo "This will install the Python modules via pip3 that are required to run Ruby2FA, such as: PyQt5, opencv-python, numpy, pyzbar, pillow, and pyotp."
pip3 install --user -r requirements.txt || { echo "Dependency install failed!"; exit 1; }

# Check for protobuf
if ! python3 -c "import google.protobuf" 2>/dev/null; then
    echo "Installing protobuf..."
    echo "protobuf and grpcio-tools are also used to import Google Authenticator import QR text files."
    pip3 install --user protobuf
fi

# Compile OtpMigration_pb2 if not present
if [ ! -f addtl/OtpMigration_pb2.py ]; then
    if [ -f addtl/OtpMigration.proto ]; then
        echo "Compiling OtpMigration.proto..."
        echo "OtpMigration.proto and grpcio-tools are also used to import Google Authenticator import QR text files."
        python3 -m pip install --user grpcio-tools
        python3 -m grpc_tools.protoc -Iaddtl --python_out=addtl addtl/OtpMigration.proto || { echo "Failed to compile proto!"; exit 1; }
    else
        echo "Warning: addtl/OtpMigration.proto not found. Google Auth import may not work. The script is fully functional, but you will not be able to import Google Authenticator import QR text files, and will have to manually re-add all accounts."
    fi
fi

# Create rubykeys dir if missing
if [ ! -d rubykeys ]; then
    mkdir rubykeys
    echo "Created rubykeys directory."
    echo "This directory is used to store your encrypted secrets. If you lose it, you will not be able to access your accounts."
    echo "Make sure to back it up somewhere safe once you've added all your accounts and the files are generated!"
fi

echo "Setup complete! To start Ruby2FA from the command line in the folder you ran this script in, run: `python3 ruby2fa.py`"
echo "If you are on Windows 11, you can create a PowerShell alias to run Ruby2FA by running: `New-Alias -Name ruby2fa -Value 'python3 C:\path\to\ruby2fa.py'`"
echo "Then, you can run Ruby2FA by simply typing: `ruby2fa` into your PowerShell window. :3"
echo
echo "Meowdy! Ruby2FA is ready to go! 🐾"
echo "If you have any questions, feel free to email rubyaftermidnight@gmail.com! :3"
