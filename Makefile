CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc
CFLAGS = -c -masm=intel

all: ms16032_inject.x64.o ms16032_inject.x86.o

ms16032_inject.x64.o: ms16032_inject.c beacon.h
	$(CC_x64) $(CFLAGS) ms16032_inject.c -o ms16032_inject.x64.o

ms16032_inject.x86.o: ms16032_inject.c beacon.h
	$(CC_x86) $(CFLAGS) ms16032_inject.c -o ms16032_inject.x86.o

x64: ms16032_inject.x64.o

x86: ms16032_inject.x86.o

clean:
	rm -f ms16032_inject.x64.o ms16032_inject.x86.o

.PHONY: all x64 x86 clean
