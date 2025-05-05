#!/usr/bin/env python3
import os
import sys
import argparse
import struct
import zlib
import hashlib
import random
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

try:
    import pefile
    PE_SUPPORT = True
except ImportError:
    PE_SUPPORT = False

try:
    from elftools.elf.elffile import ELFFile
    ELF_SUPPORT = True
except ImportError:
    ELF_SUPPORT = False


class TargetFormat(Enum):
    PE = 0
    ELF = 1
    UNKNOWN = 2


class CompressionType(Enum):
    NONE = 0
    ZLIB = 1
    LZMA = 2


class EncryptionType(Enum):
    NONE = 0
    XOR = 1
    AES = 2


class Packer:
    """Main packer class handling both PE and ELF formats."""
    
    # Constants for the packed file format
    MAGIC = b'UPEF'  # Universal Packer for Executables Format
    VERSION = 1
    HEADER_SIZE = 64
    
    def __init__(self, 
                 input_file,
                 output_file=None,
                 stub_file="stub.bin",
                 compression=CompressionType.ZLIB,
                 encryption=EncryptionType.XOR,
                 encryption_key=None,
                 entropy_layers=1):
        """
        Initialize the packer with configuration settings.
        
        Args:
            input_file: Path to the executable to pack
            output_file: Path for the packed output (default: input + .packed)
            stub_file: Path to the unpacking stub (compiled assembly)
            compression: Compression algorithm to use
            encryption: Encryption algorithm to use
            encryption_key: Key for encryption (generated if None)
            entropy_layers: Number of additional entropy layers
        """
        self.input_file = input_file
        self.output_file = output_file or f"{input_file}.packed"
        self.stub_file = stub_file
        self.compression = compression
        self.encryption = encryption
        self.encryption_key = encryption_key or self._generate_key()
        self.entropy_layers = entropy_layers
        self.target_format = self._detect_format()
        
        # Ensure required libraries are available
        if self.target_format == TargetFormat.PE and not PE_SUPPORT:
            raise ImportError("PE format detected but pefile module is not installed")
        if self.target_format == TargetFormat.ELF and not ELF_SUPPORT:
            raise ImportError("ELF format detected but pyelftools module is not installed")
        
        # Get image details based on format
        self._load_binary()
    
    def _generate_key(self, length=16):
        """Generate a random encryption key."""
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    def _detect_format(self):
        """Detect if the input file is PE or ELF."""
        with open(self.input_file, 'rb') as f:
            magic = f.read(4)
            
        if magic.startswith(b'MZ'):
            return TargetFormat.PE
        elif magic == b'\x7fELF':
            return TargetFormat.ELF
        else:
            return TargetFormat.UNKNOWN
    
    def _load_binary(self):
        """Load and parse the binary file."""
        if self.target_format == TargetFormat.PE:
            self._load_pe()
        elif self.target_format == TargetFormat.ELF:
            self._load_elf()
        else:
            raise ValueError(f"Unsupported file format: {self.input_file}")
    
    def _load_pe(self):
        """Load and parse a PE file."""
        self.pe = pefile.PE(self.input_file)
        self.original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = [(s.Name.decode().strip('\x00'), s.PointerToRawData, s.SizeOfRawData)
                         for s in self.pe.sections]
    
    def _load_elf(self):
        """Load and parse an ELF file."""
        with open(self.input_file, 'rb') as f:
            self.elf = ELFFile(f)
            self.original_entry_point = self.elf.header.e_entry
            
            # Find the program headers for segments
            self.segments = []
            for segment in self.elf.iter_segments():
                self.segments.append((
                    segment.header.p_type,
                    segment.header.p_offset,
                    segment.header.p_filesz
                ))
    
    def _compress_data(self, data):
        """Compress data using the selected algorithm."""
        if self.compression == CompressionType.NONE:
            return data
        elif self.compression == CompressionType.ZLIB:
            return zlib.compress(data, level=9)
        elif self.compression == CompressionType.LZMA:
            import lzma
            return lzma.compress(data)
        else:
            raise ValueError(f"Unsupported compression type: {self.compression}")
    
    def _encrypt_data(self, data):
        """Encrypt data using the selected algorithm."""
        if self.encryption == EncryptionType.NONE:
            return data
        elif self.encryption == EncryptionType.XOR:
            # Simple XOR encryption
            key_len = len(self.encryption_key)
            return bytes([data[i] ^ self.encryption_key[i % key_len] for i in range(len(data))])
        elif self.encryption == EncryptionType.AES:
            # AES encryption
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend the IV to the encrypted data
            return iv + encrypted_data
        else:
            raise ValueError(f"Unsupported encryption type: {self.encryption}")
    
    def _add_entropy(self, data):
        """Add entropy layers to obfuscate the binary."""
        result = data
        for _ in range(self.entropy_layers):
            # Add random data blocks at random positions
            pos = random.randint(0, len(result) - 1)
            entropy_block = os.urandom(random.randint(16, 256))
            result = result[:pos] + entropy_block + result[pos:]
        
        return result
    
    def _create_packed_header(self, original_size, packed_size):
        """Create the header for the packed file."""
        # Create a structured header with metadata
        header = bytearray(self.HEADER_SIZE)
        
        # Magic identifier
        header[0:4] = self.MAGIC
        
        # Format type (PE=0, ELF=1)
        header[4] = self.target_format.value
        
        # Version
        header[5] = self.VERSION
        
        # Compression and encryption flags
        header[6] = self.compression.value
        header[7] = self.encryption.value
        
        # Original entry point (8-byte value)
        struct.pack_into("<Q", header, 8, self.original_entry_point)
        
        # Image base for PE (8-byte value)
        if self.target_format == TargetFormat.PE:
            struct.pack_into("<Q", header, 16, self.image_base)
        
        # Key length and entropy layers
        header[24] = len(self.encryption_key)
        header[25] = self.entropy_layers
        
        # Original and packed sizes
        struct.pack_into("<I", header, 26, original_size)
        struct.pack_into("<I", header, 30, packed_size)
        
        # Append encryption key
        key_offset = 34
        for i, b in enumerate(self.encryption_key):
            if key_offset + i < self.HEADER_SIZE:
                header[key_offset + i] = b
        
        # Checksum
        checksum = hashlib.sha256(header[0:key_offset + len(self.encryption_key)]).digest()
        checksum_offset = self.HEADER_SIZE - 32
        for i, b in enumerate(checksum[:32]):
            header[checksum_offset + i] = b
        
        return header
    
    def pack(self):
        """Pack the executable with the selected methods."""
        print(f"[+] Packing {self.input_file} ({self.target_format.name})...")
        
        # Read the original file
        with open(self.input_file, 'rb') as f:
            original_data = f.read()
        
        original_size = len(original_data)
        print(f"[+] Original size: {original_size} bytes")
        
        # Apply compression
        compressed_data = self._compress_data(original_data)
        print(f"[+] After compression: {len(compressed_data)} bytes")
        
        # Apply encryption
        encrypted_data = self._encrypt_data(compressed_data)
        print(f"[+] After encryption: {len(encrypted_data)} bytes")
        
        # Add entropy layers if specified
        if self.entropy_layers > 0:
            obfuscated_data = self._add_entropy(encrypted_data)
            print(f"[+] After entropy layers: {len(obfuscated_data)} bytes")
        else:
            obfuscated_data = encrypted_data
        
        # Create the packed file header
        packed_size = len(obfuscated_data)
        header = self._create_packed_header(original_size, packed_size)
        
        # Read the stub file
        try:
            with open(self.stub_file, 'rb') as f:
                stub_data = f.read()
        except FileNotFoundError:
            print(f"[!] Stub file {self.stub_file} not found!")
            # If we can't find the compiled stub, try to assemble it on the fly
            if os.path.exists("stub.asm"):
                print("[+] Attempting to assemble stub.asm...")
                self._assemble_stub()
                with open(self.stub_file, 'rb') as f:
                    stub_data = f.read()
            else:
                raise FileNotFoundError(f"Neither {self.stub_file} nor stub.asm found")
        
        # Write the packed file: stub + header + packed data
        with open(self.output_file, 'wb') as f:
            f.write(stub_data)
            f.write(header)
            f.write(obfuscated_data)
        
        # Make the output file executable on Unix-like systems
        if os.name == 'posix':
            os.chmod(self.output_file, 0o755)
        
        print(f"[+] Packed executable written to {self.output_file}")
        print(f"[+] Final size: {os.path.getsize(self.output_file)} bytes")
    
    def _assemble_stub(self):
        """Attempt to assemble the stub.asm file."""
        if not os.path.exists("stub.asm"):
            raise FileNotFoundError("stub.asm not found")
        
        # Try with nasm first
        try:
            os.system("nasm -f bin stub.asm -o stub.bin")
            print("[+] Assembled stub using nasm")
            return
        except:
            pass
        
        # Try with yasm if nasm fails
        try:
            os.system("yasm -f bin stub.asm -o stub.bin")
            print("[+] Assembled stub using yasm")
            return
        except:
            pass
        
        raise RuntimeError("Failed to assemble stub.asm. Ensure nasm or yasm is installed.")


def main():
    """Main entry point for the packer."""
    parser = argparse.ArgumentParser(description="Universal PE/ELF Packer")
    
    parser.add_argument("input", help="Input executable file to pack")
    parser.add_argument("-o", "--output", help="Output packed file")
    parser.add_argument("-s", "--stub", default="stub.bin", help="Stub binary file")
    parser.add_argument("-c", "--compression", choices=["none", "zlib", "lzma"], 
                        default="zlib", help="Compression algorithm")
    parser.add_argument("-e", "--encryption", choices=["none", "xor", "aes"], 
                        default="xor", help="Encryption algorithm")
    parser.add_argument("-k", "--key", help="Encryption key (hex string)")
    parser.add_argument("--entropy", type=int, default=1, 
                        help="Number of entropy layers to add")

    args = parser.parse_args()
    
    # Convert string choices to enum values
    compression_map = {"none": CompressionType.NONE, 
                      "zlib": CompressionType.ZLIB, 
                      "lzma": CompressionType.LZMA}
    
    encryption_map = {"none": EncryptionType.NONE, 
                     "xor": EncryptionType.XOR, 
                     "aes": EncryptionType.AES}
    
    # Convert hex key string to bytes if provided
    key = None
    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            print("[!] Error: Encryption key must be a valid hex string")
            return 1
    
    # Create and run the packer
    try:
        packer = Packer(
            input_file=args.input,
            output_file=args.output,
            stub_file=args.stub,
            compression=compression_map[args.compression],
            encryption=encryption_map[args.encryption],
            encryption_key=key,
            entropy_layers=args.entropy
        )
        
        packer.pack()
        return 0
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())