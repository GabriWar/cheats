# Cheats Memory Tool

This repository contains two memory cheat tools:

1. **cheats.exe** - A command-line based memory scanner and editor
2. **cheats_tui.exe** - An advanced Text-based User Interface (TUI) memory viewer and editor

Both tools allow you to:
- Select processes
- Browse modules
- Scan memory for patterns/signatures
- View and edit memory at specific addresses
- Watch memory regions for changes

## Building

### On Windows:

1. Make sure you have MinGW and CMake installed
2. Run the build script:
   ```
   build.bat
   ```

### On Linux:

1. Make sure you have GCC/G++ and CMake installed
2. Run the build script:
   ```
   ./build.sh
   ```

The compiled executables will be in the `build` directory.

## Usage

### cheats.exe

Command-line based memory tool that walks you through process and module selection.

```
./build/cheats
```

### cheats_tui.exe

Advanced TUI-based memory tool with a rich interface for memory manipulation.

```
./build/cheats_tui
```

#### TUI Controls:

- **F**: Filter processes/modules
- **ESC**: Exit current view or cancel operation
- **Arrow keys**: Navigate through menus
- **Enter**: Select item
- **E**: Edit memory value
- **P**: Pause memory watch
- **F**: Freeze memory value
- **G**: Go to address

## Requirements

- libmem library (included in the repository)
- FTXUI library (automatically downloaded during build)

## Note

These tools require administrator privileges on Windows or root on Linux to access process memory. 