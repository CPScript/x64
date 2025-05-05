CC = gcc
ASM = nasm
CFLAGS = -Wall -Wextra -Werror -O2 -fno-stack-protector -z execstack
LDFLAGS = -no-pie

.PHONY: all clean

all: reverse_shell shellcode_extractor shellcode_injector shellcode_loader

reverse_shell: reverse_shell.o
	ld -o $@ $<

reverse_shell.o: reverse_shell.asm
	$(ASM) -f elf64 -o $@ $<

shellcode_extractor: shellcode_extractor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

shellcode_injector: shellcode_injector.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

shellcode_loader: shellcode_loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

shellcode.bin: reverse_shell
	objcopy -O binary -j .text $< $@

shellcode.h: shellcode.bin shellcode_extractor
	./shellcode_extractor reverse_shell $@

shellcode_loader_embedded: shellcode_loader.c shellcode.h
	$(CC) $(CFLAGS) -DSHELLCODE_EMBEDDED -include shellcode.h -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o reverse_shell shellcode_extractor shellcode_injector shellcode_loader shellcode_loader_embedded shellcode.bin shellcode.h