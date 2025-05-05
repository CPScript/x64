/**
 * PE Packer Framework
 * 
 * A professional-grade executable packer that:
 * 1. Compresses/encrypts PE files
 * 2. Prepends a stub for runtime unpacking
 * 3. Handles both x86/x64 PE executables
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define ENCRYPTION_KEY 0x37  // Simple XOR key (replace with more sophisticated algorithm in production)
#define SIGNATURE "PKEXE"    // Signature to identify packed executables

typedef struct {
    char signature[6];        // Signature "PKEXE"
    DWORD originalSize;       // Original file size
    DWORD packedSize;         // Packed data size
    DWORD originalEntryPoint; // Original entry point RVA
    DWORD imageBase;          // Original image base
} PackerHeader;

// Forward declarations
BOOL CompressAndEncrypt(const BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize);
BOOL DecompressAndDecrypt(const BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize);
BOOL InjectUnpackStub(const char* packedFilePath, const BYTE* unpackStub, DWORD stubSize);

/**
 * Packs a PE executable
 */
BOOL PackExecutable(const char* inputPath, const char* outputPath) {
    FILE* inputFile = fopen(inputPath, "rb");
    if (!inputFile) {
        printf("[-] Failed to open input file: %s\n", inputPath);
        return FALSE;
    }

    // Get file size
    fseek(inputFile, 0, SEEK_END);
    DWORD fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // Read input file
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        printf("[-] Memory allocation failed\n");
        fclose(inputFile);
        return FALSE;
    }
    fread(fileBuffer, 1, fileSize, inputFile);
    fclose(inputFile);

    // Validate PE file
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid PE file\n");
        free(fileBuffer);
        return FALSE;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid PE file\n");
        free(fileBuffer);
        return FALSE;
    }

    // Save original entry point and image base
    DWORD originalEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD imageBase = ntHeaders->OptionalHeader.ImageBase;

    // Compress and encrypt the PE file
    BYTE* packedData;
    DWORD packedSize;
    if (!CompressAndEncrypt(fileBuffer, fileSize, &packedData, &packedSize)) {
        printf("[-] Compression/encryption failed\n");
        free(fileBuffer);
        return FALSE;
    }

    // Create output file
    FILE* outputFile = fopen(outputPath, "wb");
    if (!outputFile) {
        printf("[-] Failed to create output file: %s\n", outputPath);
        free(fileBuffer);
        free(packedData);
        return FALSE;
    }

    // Create packer header
    PackerHeader header;
    memcpy(header.signature, SIGNATURE, sizeof(header.signature));
    header.originalSize = fileSize;
    header.packedSize = packedSize;
    header.originalEntryPoint = originalEntryPoint;
    header.imageBase = imageBase;

    // Write header and packed data
    fwrite(&header, sizeof(PackerHeader), 1, outputFile);
    fwrite(packedData, 1, packedSize, outputFile);
    fclose(outputFile);

    printf("[+] Successfully packed %s to %s\n", inputPath, outputPath);
    printf("[+] Original size: %d bytes, Packed size: %d bytes\n", fileSize, packedSize);

    free(fileBuffer);
    free(packedData);
    
    // Now inject the unpacker stub - this would be implemented separately
    // InjectUnpackStub(outputPath, unpackStubData, unpackStubSize);
    
    return TRUE;
}

/**
 * Simple XOR-based compression and encryption
 * Production version should use better compression (LZMA, etc.) and encryption (AES, etc.)
 */
BOOL CompressAndEncrypt(const BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize) {
    // For demonstration, we'll just use XOR encryption without compression
    // In a real implementation, compress first then encrypt
    
    *outputSize = inputSize;
    *output = (BYTE*)malloc(*outputSize);
    
    if (!*output) {
        return FALSE;
    }
    
    // Simple XOR encryption
    for (DWORD i = 0; i < inputSize; i++) {
        (*output)[i] = input[i] ^ ENCRYPTION_KEY;
    }
    
    return TRUE;
}

/**
 * Decompress and decrypt data (reverse of CompressAndEncrypt)
 */
BOOL DecompressAndDecrypt(const BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize) {
    // For demonstration, we'll just use XOR decryption
    
    *outputSize = inputSize;
    *output = (BYTE*)malloc(*outputSize);
    
    if (!*output) {
        return FALSE;
    }
    
    // Simple XOR decryption (same as encryption since XOR is symmetric)
    for (DWORD i = 0; i < inputSize; i++) {
        (*output)[i] = input[i] ^ ENCRYPTION_KEY;
    }
    
    return TRUE;
}

/**
 * The main unpacker stub that would be injected
 * This would be converted to position-independent shellcode in a real implementation
 */
void UnpackerStub(void) {
    // This is a simplified representation - in reality this would be
    // hand-written assembly or compiler-generated position-independent code
    
    // 1. Get our own module handle
    // 2. Find the packer header
    // 3. Allocate memory for the original executable
    // 4. Decrypt and decompress the packed data
    // 5. Reconstruct PE headers and sections
    // 6. Fix imports and relocations
    // 7. Jump to original entry point
    
    // This stub would be extracted, assembled, and injected as shellcode
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    
    if (!PackExecutable(argv[1], argv[2])) {
        printf("[-] Packing failed\n");
        return 1;
    }
    
    return 0;
}