# Encrypt - Secure File and Folder Encryption

A modern, cross-platform encryption tool for secure file and folder protection.

## Features

- **File and Folder Encryption**: Securely encrypt individual files or entire folders
- **Multiple Security Levels**: Choose from 5 different security levels (1=fast to 5=maximum)
- **Easy to Use**: Drag-and-drop interface on Windows and command-line interface
- **Cross-Platform**: Works on Windows and Linux
- **No Dependencies**: The Windows version is completely standalone
- **Password Strength Analysis**: Evaluates password quality before encryption

## Security Levels

1. **Level 1**: Fast but secure (AES-128-GCM, PBKDF2 with 10,000 iterations)
2. **Level 2**: Balanced (AES-256-GCM, PBKDF2 with 100,000 iterations)
3. **Level 3**: Enhanced security (AES-256-GCM, PBKDF2 with 250,000 iterations)
4. **Level 4**: High security (AES-256-GCM, Argon2id with 64MB RAM)
5. **Level 5**: Maximum security (AES-256-GCM + ChaCha20, Argon2id with 256MB RAM)

## Installation

### Windows

1. Download the latest release ZIP file
2. Extract to any location
3. Double-click `encrypt.exe` to start the drag-and-drop interface, or
4. Run `install.bat` to install for the current user

### Linux

Build from source:

```bash
# Install dependencies
sudo apt install build-essential cmake libssl-dev

# Build
git clone https://github.com/HasiKe/encrypt.git
cd encrypt
mkdir build && cd build
cmake ..
make

# Run
./bin/encrypt
```

## Usage

### Windows Drag-and-Drop Mode

1. Start `encrypt.exe`
2. Drag files or folders into the window
3. The app will automatically detect if you're encrypting or decrypting based on file extension
4. Enter your password and select security level (for encryption)
5. The processed file will be created in the same directory

### Command Line Mode

```
Usage: encrypt [options] <file>

Options:
  -h, --help              Show this help
  -d, --decrypt           Decrypt file (default: encrypt)
  -o, --output <file>     Specify output file
  -p, --password <pass>   Specify password (INSECURE)
  -l, --level <1-5>       Specify security level
  -c, --check-password    Check password strength
```

Examples:

```bash
# Encrypt a file
encrypt document.docx

# Encrypt with high security
encrypt -l 4 document.docx

# Decrypt a file
encrypt -d document.docx.cryp

# Check password strength
encrypt -c
```

## Building from Source

### For Linux

```bash
mkdir -p build && cd build
cmake ..
make
```

### For Windows (Cross-Compile)

```bash
# Install MinGW cross-compiler
sudo apt install mingw-w64

# Build
./build_windows.sh
```

The Windows executable will be in `build_windows/install/encrypt.exe`.

## License

This software is provided as-is. Please use responsibly.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.