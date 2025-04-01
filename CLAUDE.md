# Command Reference & Style Guide

## Build Commands
```bash
# Install dependencies
sudo apt install build-essential cmake mingw-w64

# Build for Linux
mkdir -p build && cd build
cmake ..
make

# Build for Windows (cross-compile)
mkdir -p build_windows && cd build_windows
cmake .. -DBUILD_WINDOWS=ON
make

# Run tests
cmake .. -DBUILD_TESTS=ON
make
ctest
```

## Code Style Guidelines
- **Namespaces**: Use `encrypt::` namespace for all code
- **Headers**: Include guards with proper namespaces (e.g., `ENCRYPT_CRYPTO_H`)
- **Indentation**: 4 spaces (no tabs)
- **Naming**: 
  - Classes: PascalCase (e.g., `Crypto`, `Platform`)
  - Functions: camelCase (e.g., `encryptFile`, `getPassword`)
  - Variables: camelCase
  - Constants: ALL_CAPS
- **Error Handling**: Return boolean success/failure values, use `getLastError()` for details
- **Cross-Platform**: Use platform namespace for platform-specific implementations
- **Documentation**: Use Doxygen-style comments for classes and functions
- **C++ Standard**: C++17 or higher
- **Memory Management**: Use smart pointers and RAII, avoid raw `new`/`delete`

## Project Structure
- **include/encrypt/**: Public header files
- **src/core/**: Core implementation files
- **src/platform/**: Platform-specific code
- **src/ui/**: User interface code
- **test/**: Unit tests
- **examples/**: Example applications
- **resources/**: Icons and resource files