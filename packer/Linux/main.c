/**
 * ELF Packer Framework
 * 
 * A professional-grade executable packer for Linux ELF binaries that:
 * 1. Compresses/encrypts ELF files
 * 2. Prepends a stub for runtime unpacking
 * 3. Preserves executable functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define ENCRYPTION_KEY 0x37    // Simple XOR key
#define SIGNATURE "PKELF"      // Signature to identify packed executables

typedef struct {
    char signature[6];         // Signature "PKELF"
    uint32_t originalSize;     // Original file size
    uint32_t packedSize;       // Packed data size
    uint32_t entryPoint;       // Original entry point
    uint32_t baseAddress;      // Original base address
} PackerHeader;

// Forward declarations
int compressAndEncrypt(const unsigned char* input, size_t inputSize, unsigned char** output, size_t* outputSize);
int decompressAndDecrypt(const unsigned char* input, size_t inputSize, unsigned char** output, size_t* outputSize);
int injectUnpackStub(const char* packedFilePath, const unsigned char* unpackStub, size_t stubSize);

/**
 * Packs an ELF executable
 */
int packExecutable(const char* inputPath, const char* outputPath) {
    int fd;
    struct stat st;
    void* map;
    
    // Open and map the input file
    fd = open(inputPath, O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open input file");
        return 0;
    }
    
    // Get file size
    if (fstat(fd, &st) < 0) {
        perror("[-] Failed to get file stats");
        close(fd);
        return 0;
    }
    
    // Map the file into memory
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("[-] Failed to map file");
        close(fd);
        return 0;
    }
    
    // Verify ELF file
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)map;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[-] Not a valid ELF file\n");
        munmap(map, st.st_size);
        close(fd);
        return 0;
    }
    
    // Save original entry point and other needed information
    uint32_t entryPoint = ehdr->e_entry;
    uint32_t baseAddress = 0; // For PIE executables this would be set dynamically
    
    // Compress and encrypt the ELF file
    unsigned char* packedData;
    size_t packedSize;
    if (!compressAndEncrypt(map, st.st_size, &packedData, &packedSize)) {
        fprintf(stderr, "[-] Compression/encryption failed\n");
        munmap(map, st.st_size);
        close(fd);
        return 0;
    }
    
    // Create output file
    FILE* outputFile = fopen(outputPath, "wb");
    if (!outputFile) {
        fprintf(stderr, "[-] Failed to create output file: %s\n", outputPath);
        free(packedData);
        munmap(map, st.st_size);
        close(fd);
        return 0;
    }
    
    // Create packer header
    PackerHeader header;
    memcpy(header.signature, SIGNATURE, sizeof(header.signature));
    header.originalSize = st.st_size;
    header.packedSize = packedSize;
    header.entryPoint = entryPoint;
    header.baseAddress = baseAddress;
    
    // Write header and packed data
    fwrite(&header, sizeof(PackerHeader), 1, outputFile);
    fwrite(packedData, 1, packedSize, outputFile);
    fclose(outputFile);
    
    printf("[+] Successfully packed %s to %s\n", inputPath, outputPath);
    printf("[+] Original size: %ld bytes, Packed size: %zu bytes\n", st.st_size, packedSize);
    
    // Clean up
    free(packedData);
    munmap(map, st.st_size);
    close(fd);
    
    // Make the output file executable
    chmod(outputPath, 0755);
    
    // Now inject the unpacker stub - this would be implemented separately
    // injectUnpackStub(outputPath, unpackStubData, unpackStubSize);
    
    return 1;
}

/**
 * Simple XOR-based compression and encryption
 * Production version should use better compression (zlib, LZMA, etc.) and encryption (AES, etc.)
 */
int compressAndEncrypt(const unsigned char* input, size_t inputSize, unsigned char** output, size_t* outputSize) {
    // For demonstration, we'll just use XOR encryption without compression
    
    *outputSize = inputSize;
    *output = (unsigned char*)malloc(*outputSize);
    
    if (!*output) {
        return 0;
    }
    
    // Simple XOR encryption
    for (size_t i = 0; i < inputSize; i++) {
        (*output)[i] = input[i] ^ ENCRYPTION_KEY;
    }
    
    return 1;
}

/**
 * Decompress and decrypt data (reverse of compressAndEncrypt)
 */
int decompressAndDecrypt(const unsigned char* input, size_t inputSize, unsigned char** output, size_t* outputSize) {
    // For demonstration, we'll just use XOR decryption
    
    *outputSize = inputSize;
    *output = (unsigned char*)malloc(*outputSize);
    
    if (!*output) {
        return 0;
    }
    
    // Simple XOR decryption (same as encryption since XOR is symmetric)
    for (size_t i = 0; i < inputSize; i++) {
        (*output)[i] = input[i] ^ ENCRYPTION_KEY;
    }
    
    return 1;
}

/**
 * The main unpacker stub that would be injected
 * This would be converted to position-independent shellcode in a real implementation
 */
void unpackerStub(void) {
    // This is a simplified representation - in reality this would be
    // hand-written assembly or compiler-generated position-independent code
    
    // 1. Find the packer header
    // 2. Allocate memory with mmap
    // 3. Decrypt and decompress the packed data
    // 4. Set up executable memory permissions
    // 5. Jump to original entry point
    
    // This stub would be extracted, assembled, and injected as shellcode
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    
    if (!packExecutable(argv[1], argv[2])) {
        fprintf(stderr, "[-] Packing failed\n");
        return 1;
    }
    
    return 0;
}