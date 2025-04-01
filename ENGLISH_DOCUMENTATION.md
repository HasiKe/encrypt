# English Documentation for Encrypt

This directory contains English-language versions of documentation and code comments for the Encrypt application.

## Documentation Files

- `README_EN.md` - Main English README with overview and quickstart
- `DOCUMENTATION_EN.md` - Comprehensive documentation with full details
- `include/encrypt/crypto_en.h` - English version of the crypto header file with translated comments
- `include/encrypt/platform_en.h` - English version of the platform interface header
- `resources/resources_en.rc` - English version of Windows resource files
- `src/platform/windows_en_messages.h` - English messages for Windows UI
- `install_windows_en.bat` - English version of the Windows installation script

## Building English Version

To build the application with English messages, you would need to:

1. Rename the English resource file: `cp resources/resources_en.rc resources/resources.rc`
2. Include the English messages header in your Windows platform code
3. Build as normal:
   ```bash
   ./build_windows.sh
   ```

## Usage

See `README_EN.md` for basic usage instructions or `DOCUMENTATION_EN.md` for comprehensive documentation.

## Converting Between Languages

The application is designed to be easily translatable. The core functionality is language-independent, with UI strings and messages separated into language-specific files.

To add a new language:
1. Copy the English message files and translate the strings
2. Update the build process to use your language files
3. Create documentation in your language

## Supported Languages

- German (Default)
- English (This documentation)

## Contributing Translations

If you would like to contribute translations to other languages, please:
1. Fork the repository
2. Create translated versions of the documentation and message files
3. Submit a pull request with your changes