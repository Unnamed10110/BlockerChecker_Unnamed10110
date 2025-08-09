# Blocker Checker

A C++ GUI application that adds a permanent "Blocker Checker" option to the Windows right-click context menu for detecting and managing processes that block files, folders, and drives.

**Developer:** Unnamed10110  
**Contact:** trojan.v6@gmail.com / sergiobritos10110@gmail.com

## Features

- **Context Menu Integration**: Adds a permanent "BlockerChecker" option to the Windows right-click context menu
- **Custom Icon**: Uses the application's own `blocker.ico` icon in both the executable and context menu
- **Strategic Positioning**: Menu item appears at the bottom of context menu, above "Properties", with separator lines
- **Selective Targeting**: Appears when right-clicking on files, drives, and folders
- **GUI Window**: Opens a responsive window sized at 40% screen width and 70% screen height
- **File Path Display**: Shows the path of the right-clicked file in an editable text box
- **Interactive Buttons**: 
  - **Copy**: Copies the file path to clipboard
  - **Browse**: Opens a file selection dialog to choose a different file
- **Advanced Blocking Detection**: Comprehensive analysis of processes blocking files, drives, or programs
- **Detailed Process Information**: Shows process names, PIDs, access rights, and blocking reasons
- **Process Grouping**: Groups multiple instances of the same process together for easier management
- **Bulk Process Termination**: Kill all instances of a process type with a single "KILL ALL" button
- **File/Folder Actions**: Delete files, force delete, or schedule deletion at restart
- **Responsive Design**: Fully responsive window that adapts to any screen size
- **Smooth Scrolling**: Container-based scrolling with smooth performance and no flickering
- **Permanent Installation**: Context menu entry persists across system restarts

## Requirements

- Windows 10/11
- Visual Studio 2019 or later (with C++ development tools)
- CMake 3.10 or later
- Administrator privileges (for first run)

## Building the Application

### Using the provided batch file
1. Open Command Prompt as Administrator
2. Navigate to the project directory
3. Run: `build.bat`

### Manual build with CMake
```bash
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Installation and Usage

1. **Build the application** using one of the methods above
2. **Run as Administrator**: Right-click on `build/bin/Release/BlockerChecker.exe` and select "Run as administrator"
3. **Confirm installation**: The application will show a success message and add the context menu item
4. **Use the context menu**: Right-click on files, drives, or folders to see the "BlockerChecker" option
5. **Automatic Elevation**: When you click the "BlockerChecker" context menu item, the application will automatically request administrator privileges if needed

## Context Menu Features

### Visual Design
- **Custom Icon**: Uses the `blocker.ico` icon in both the executable and context menu
- **Strategic Positioning**: Appears at the bottom of the context menu, above "Properties"
- **Separator Lines**: Visual separator lines above and below the menu item for clear distinction
- **Professional Appearance**: Clean, modern look that integrates seamlessly with Windows

### Registry Integration
The application modifies the Windows registry to add a context menu item to:
- All files (`*`)
- Drives (`Drive`)
- Directories (`Directory`)
- Folders (`Folder`)

Registry pattern: `HKEY_CURRENT_USER\Software\Classes\[type]\shell\BlockerChecker`

## Window Features

### Responsive Design
- **Default Size**: 40% width and 70% height of the screen
- **Resizable**: Window can be resized by dragging the edges
- **Minimum Size**: Enforced minimum size of 400x300 pixels
- **Responsive Elements**: All UI elements adapt dynamically to window size changes

### Process Management
- **Process Detection**: Comprehensive scanning for file locks and sharing violations
- **Grouped Display**: Multiple instances of the same process are grouped together
- **Bulk Actions**: Single "KILL ALL" button to terminate all instances of a process type
- **Detailed Information**: Shows process names, PIDs, access rights, and blocking reasons

### File Operations
- **Delete File**: Permanently removes the selected file
- **Kill All Processes**: Terminates all processes blocking the file
- **Force Delete Now**: Ignores locks and forces immediate deletion
- **Delete at Restart**: Schedules file deletion for the next system restart

### Scrolling System
- **Container-Based**: Only the process list container has scrolling functionality
- **Smooth Performance**: Enhanced scrolling with proper refresh/redraw
- **Mouse Wheel Support**: Smooth scrolling with mouse wheel
- **Keyboard Navigation**: Arrow keys, Page Up/Down, Home/End for navigation

## Uninstallation

To remove the context menu item:
1. Run the application as administrator
2. The context menu entries will be automatically removed

## File Structure

```
BlockerChecker/
├── main.cpp                    # Main application source code (4685 lines)
├── resource.rc                 # Resource file with icon definition
├── resource.h                  # Resource header file
├── blocker.ico                 # Application icon (264KB)
├── CMakeLists.txt             # CMake build configuration
├── build.bat                  # Automated build script
├── .gitignore                 # Git ignore file
└── README.md                  # This documentation
```

## Technical Details

### Dependencies
- Windows API (Win32)
- Shell32.lib
- Advapi32.lib
- Comctl32.lib
- Psapi.lib (for process information)
- Tlhelp32.lib (for process enumeration)

### Compilation
- C++17 standard
- Windows subsystem (no console window)
- Unicode support

## Troubleshooting

### "Administrator Required" Error
- Make sure you're running the executable as administrator
- Right-click the .exe file and select "Run as administrator"

### Build Errors
- Ensure Visual Studio is installed with C++ development tools
- Verify CMake is installed and in your PATH
- Check that you're using a compatible Visual Studio version

### Context Menu Not Appearing
- Restart Windows Explorer: `taskkill /f /im explorer.exe && start explorer.exe`
- Check if the registry keys were created successfully
- Ensure the executable path in the registry is correct

## License

This project is provided as-is for educational and development purposes.

---

**Developer:** Unnamed10110  
**Email:** trojan.v6@gmail.com / sergiobritos10110@gmail.com  
**Project:** BlockerChecker - Windows Context Menu Process Blocker Detection Tool 