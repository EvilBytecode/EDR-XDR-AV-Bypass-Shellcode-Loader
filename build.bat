@echo off
nasm -f win64 -o codepulzeispapa.obj codepulzeispapa.asm
x86_64-w64-mingw32-g++ -O2 remote.cpp -o hack.exe -I/usr/share/mingw-w64/include/ codepulzeispapa.obj -s -ffunction-sections -fdata-sections -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive -lwininet -w
strip --strip-all hack.exe
