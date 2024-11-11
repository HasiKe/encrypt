## deps
sudo apt install mingw-w64

## Windows:
mkdir build-win/
cd build-win/
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw-w64.cmake
make

## Linux
mkdir build
cd build
cmake ..
make