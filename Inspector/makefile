# Makefile for x64 Hardware Inspector

# Tool definitions
NASM = nasm
LD = ld

# Target definitions based on execution environment
.PHONY: all clean efi bios

all: efi bios

# UEFI application (x64)
efi: bin/HWINFO.EFI

bin/HWINFO.EFI: obj/hwinfo_efi.o
	@mkdir -p bin
	$(LD) -o $@ $< -nostdlib -znocombreloc -T efi.lds -shared -Bsymbolic

obj/hwinfo_efi.o: src/hwinfo.asm
	@mkdir -p obj
	$(NASM) -f elf64 -o $@ $< -D EFI_BUILD

# Legacy BIOS bootloader (multiboot)
bios: bin/hwinfo.bin

bin/hwinfo.bin: obj/hwinfo_bios.o
	@mkdir -p bin
	$(LD) -o $@ $< -nostdlib -Ttext 0x100000

obj/hwinfo_bios.o: src/hwinfo.asm
	@mkdir -p obj
	$(NASM) -f elf64 -o $@ $< -D BIOS_BUILD

# Create bootable USB image (requires root privileges)
usb: bin/hwinfo.bin
	@echo "Creating bootable USB image (requires sudo)"
	@echo "WARNING: This will DESTROY ALL DATA on the target device!"
	@echo "Enter the target device (e.g., /dev/sdb): "
	@read device; \
	sudo dd if=bin/hwinfo.bin of=$$device bs=512 conv=sync

# Clean build artifacts
clean:
	rm -rf obj bin

# Build kernel module driver for Windows
windows_driver: src/hwinfo_win_driver.asm
	@echo "Building Windows kernel-mode driver (requires Windows DDK)"
	@echo "This requires manual compilation with the Windows DDK tools"
	@echo "See README-WINDOWS.md for instructions"

# Build Linux kernel module
linux_module: src/hwinfo_linux_module.c
	@echo "Building Linux kernel module (requires kernel headers)"
	@echo "This requires manual compilation with kernel build system"
	@echo "See README-LINUX.md for instructions"