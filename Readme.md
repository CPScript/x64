> This repository contains various tools and frameworks designed for in-depth binary analysis, code obfuscation, shellcode development, and system security research. These components are intended for educational purposes, legitimate security research, and authorized penetration testing activities. **I HAVE NOT TESTED THEM NOR WILL BOTHER TO MAKE CHANGES. THESE ARE FOR EDUCATIONAL PURPOSES AND FOR PEOPLE TO LEARN FROM. PLEASE ENJOY**

## Components

### Binary Obfuscator (`BianaryObfu/`)
A professional-grade framework for obfuscating binaries through techniques such as junk code insertion, control flow flattening, and opaque predicates.

### Bootloader Security Research (`BootLoaderPOC/`)
A proof-of-concept implementation demonstrating 16-bit to 32-bit transition techniques and low-level system manipulation for bootloader security analysis.

### COFF Loader (`COFFLoader/`)
A utility for loading and executing Common Object File Format (COFF) files, enabling in-memory loading and execution capabilities.

### Heap Exploitation Framework (`HEAPEF/`)
Advanced toolkit for analyzing and exploiting heap vulnerabilities with support for multiple exploitation techniques like tcache poisoning and fastbin attacks.

### Intel Driver Research (`IntDriver/`)
Security research tools focused on Intel graphics driver vulnerabilities, including proof-of-concept implementations.

### Process Injection Framework (`PInjection/`)
Assembly-based implementation for Windows process injection using direct syscalls and dynamic PEB walking techniques.

### Polymorphic Shellcode Tools (`Polymorphic/`)
Framework for creating, analyzing, and manipulating polymorphic shellcode with multi-layered encoding to evade signature-based detection.

### Input Monitoring Research (`Reader/`)
Research implementations for Linux input monitoring including device input and ptrace-based approaches.

### Shellcode Utilities (`ShellFX/`)
Comprehensive toolkit for creating, testing, and deploying shellcode, including a reverse shell implementation and testing harness.

### Executable Packer (`packer/`)
Multi-platform (Windows/Linux) executable packing frameworks for PE and ELF binaries, providing compression, encryption, and obfuscation capabilities.

## Requirements

Different components have different dependencies. Generally, the following are required:

- Python 3.6+
- NASM (Netwide Assembler)
- GCC/Clang compiler
- Windows systems require Visual Studio or MinGW for Windows-specific components
- Linux components require standard development tools (`build-essential`)

See individual component documentation for specific requirements.

## Usage

### Binary Obfuscator
```
cd BianaryObfu
python3 binary_obfuscator.py <input_binary> -o <output_binary> -t junk,flow,opaque
```

### Shellcode Framework
```
cd ShellFX
make
./shellcode_loader --file <shellcode.bin> --analyze
```

### Process Injection
```
cd PInjection
nasm -f elf64 x64_injection.asm -o x64_injection.o
ld -o x64_injector x64_injection.o
```

See individual component documentation for detailed usage instructions.

## Security and Legal Notice

**IMPORTANT:** This toolkit is provided for educational and research purposes only. The tools and code in this repository should only be used:

1. In controlled environments
2. On systems you own or have explicit permission to test
3. For legitimate security research and education

Unauthorized use of these tools against systems without proper authorization may violate local, state, and federal laws. The authors assume no liability and are not responsible for any misuse or damage caused by this software.

---

*Note: Some components may have additional documentation in their respective directories with more detailed usage instructions and examples.*# Binary Analysis and Security Research Toolkit
