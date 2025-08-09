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

## Usage Demostration (GUI and CLI)
- GUI
  <br><br>
  <img width="447" height="221" alt="image" src="https://github.com/user-attachments/assets/76737b0b-1117-41eb-8546-e9a1b1b40ea0" />
  <br><br>
  <img width="300" height="743" alt="image" src="https://github.com/user-attachments/assets/f3d93c53-3888-4af8-b3d3-0e8c816b479e" />
  <br><br>
  <img width="754" height="749" alt="image" src="https://github.com/user-attachments/assets/fbae9fec-3f12-4aae-9193-430e8a8df27f" />
  <br><br>
- CLI mode
  <img width="1557" height="311" alt="image" src="https://github.com/user-attachments/assets/d6f38dcd-ee1f-4d04-9a94-d2664f3b5ae9" />
  <br><br>
  <img width="1088" height="211" alt="image" src="https://github.com/user-attachments/assets/079f9dcb-22cc-4b1f-876f-5a59757777ee" />
  <br><br>
  <img width="1044" height="200" alt="image" src="https://github.com/user-attachments/assets/7eb6b8be-e0ae-4aef-b5c2-375a2fc0469a" />
  <br><br>
  <img width="1063" height="255" alt="image" src="https://github.com/user-attachments/assets/a03629a7-83de-4979-89a1-07d02062c522" />
  <br><br>
  <img width="1133" height="367" alt="image" src="https://github.com/user-attachments/assets/ccc6762a-321f-4fc8-ae86-8d7802dfc05f" />

  
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

## Technical Detection Methods

### File Blocking Detection

BlockerChecker uses multiple sophisticated detection methods to identify processes blocking files:

#### 1. **Windows Restart Manager (Primary Method)**
- **API Used**: `RmStartSession`, `RmRegisterResources`, `RmGetList`
- **How it works**: 
  - Registers the target file as a resource to monitor
  - Gets a comprehensive list of all processes using that specific file
  - Returns process IDs that have file handles open
- **Advantage**: Very accurate, low false positives, Windows-native approach
- **When used**: Primary detection method for all file types

#### 2. **NtQuerySystemInformation (Kernel-Level)**
- **API Used**: `NtQuerySystemInformation` with `SystemHandleInformation`
- **How it works**:
  - Directly queries the Windows kernel for all system handles
  - Enumerates file handles across all processes
  - Duplicates handles from other processes to get file paths
  - Compares file paths with the target file
- **Advantage**: Can find handles that other methods miss, kernel-level access
- **When used**: Secondary method for comprehensive detection

#### 3. **File Access Testing**
- **API Used**: `CreateFile` with exclusive access
- **How it works**: Attempts to open the file with `GENERIC_READ | GENERIC_WRITE | DELETE` and no sharing
- **Error Detection**:
  - `ERROR_SHARING_VIOLATION`: File is being used by another process
  - `ERROR_LOCK_VIOLATION`: File is locked
  - `ERROR_ACCESS_DENIED`: Access denied
- **When used**: Confirms file is actually blocked before detailed scanning

#### 4. **Process Command Line Analysis**
- **API Used**: `NtQueryInformationProcess` for command line retrieval
- **How it works**: Checks each process's command line arguments for file path references
- **When used**: For processes that might be using the file indirectly

### Folder Blocking Detection

For folder detection, BlockerChecker uses enhanced methods to identify processes using folders:

#### 1. **Working Directory Check**
- **API Used**: `GetCurrentDirectoryW`
- **How it works**: Checks if any process has the target folder as its current working directory
- **Detection**: Processes with CWD set to the target folder

#### 2. **Command Line Analysis**
- **How it works**: Analyzes process command lines for folder path references
- **Detection**: Processes that were started with parameters pointing to the folder

#### 3. **Process Path Check**
- **API Used**: `QueryFullProcessImageName`
- **How it works**: Checks if the process executable is located within the target folder
- **Detection**: Processes running from within the folder

#### 4. **Loaded Modules Check**
- **API Used**: `CreateToolhelp32Snapshot` with `TH32CS_SNAPMODULE`
- **How it works**: Scans all DLLs loaded by each process
- **Detection**: Processes that have loaded modules (DLLs) from the target folder

#### 5. **Kernel-Level Handle Detection**
- **API Used**: `NtQuerySystemInformation` with path normalization
- **How it works**:
  - Enumerates all file handles in the system
  - Checks if any handle points to files within the target folder
  - Normalizes paths (long names, short names, volume GUID paths)
  - Handles both DOS paths and volume GUID paths
- **Advantage**: Most comprehensive folder detection method

### Path Normalization and Matching

BlockerChecker uses sophisticated path normalization to ensure accurate detection:

```cpp
// Normalize target path
std::wstring norm(fullBuf);
std::wstring normLower = norm;
std::transform(normLower.begin(), normLower.end(), normLower.begin(), ::towlower);

// Handle different path formats
std::wstring shortPath = GetShortPathName(norm);
std::wstring normGuid = BuildVolumeGuidPath(norm);

// Check for matches in handle paths
if (handlePathLower.find(normLowerWithSlash) == 0 || 
    handlePathLower == normLower ||
    handlePathLower.find(shortPathLower) == 0) {
    // Found a process with handle in this folder
}
```

### False Positive Prevention

To minimize false positives, BlockerChecker implements several filtering mechanisms:

#### 1. **System Service Filtering**
```cpp
bool IsSystemService(const std::wstring& processName) {
    // Filter out svchost.exe and other system services
    if (processName == L"svchost.exe" || 
        processName.find(L"svchost") != std::wstring::npos) {
        return true;
    }
    return false;
}
```

#### 2. **Temporary File Detection**
```cpp
bool IsInTempDirectory(const std::wstring& filePath) {
    // Be more strict with temp files to reduce false positives
    return filePath.find(L"\\temp\\") != std::wstring::npos ||
           filePath.find(L"\\tmp\\") != std::wstring::npos;
}
```

#### 3. **Process Priority Calculation**
```cpp
int CalculateBlockingPriority(DWORD processId, const std::wstring& processName, const std::wstring& filePath) {
    // Calculate priority based on process type and file location
    // Higher priority for user applications, lower for system processes
}
```

### Detection Process Flow

#### For Files:
1. **Try Restart Manager** (most accurate, Windows-native)
2. **Test file access** (confirm it's actually blocked)
3. **Use NtQuerySystemInformation** (find all handles)
4. **Check process command lines** (find indirect usage)
5. **Filter out system services** (reduce false positives)
6. **Apply priority scoring** (rank results by relevance)

#### For Folders:
1. **Check working directories** (processes using folder as CWD)
2. **Analyze command lines** (processes referencing folder)
3. **Check process paths** (executables in folder)
4. **Scan loaded modules** (DLLs loaded from folder)
5. **Use kernel handle enumeration** (find file handles in folder)
6. **Apply heuristics** (common processes that use folders)
7. **Normalize and match paths** (handle different path formats)

### Why This Multi-Layered Approach Works

1. **Comprehensive Coverage**: Multiple detection methods ensure nothing is missed
2. **Kernel-Level Access**: Direct system handle enumeration catches everything
3. **Path Normalization**: Handles different path formats (long, short, GUID)
4. **False Positive Reduction**: Filters out system services and applies heuristics
5. **Windows-Native APIs**: Uses official Windows APIs for reliability
6. **Fallback Mechanisms**: If one method fails, others can still find blocking processes

This sophisticated detection system ensures that BlockerChecker can identify virtually any process that's blocking a file or folder, while maintaining high accuracy and low false positive rates.

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
