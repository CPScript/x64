#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Define colors for output
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define RESET "\033[0m"

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
    
    printf(YELLOW "[-] Executing shellcode at %p\n" RESET, executable_memory);
    
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
        printf("%s [%zu bytes]:\n", desc, len);
    
    for (size_t i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\n", buff);
            printf("  %04zx ", i);
        }
        
        printf(" %02x", pc[i]);
        
        if (pc[i] < 0x20 || pc[i] > 0x7e)
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        
        buff[(i % 16) + 1] = '\0';
    }
    
    // Pad out last line if necessary
    while ((len % 16) != 0) {
        printf("   ");
        len++;
    }
    
    printf("  %s\n", buff);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <encoded_shellcode_file>\n", argv[0]);
        return 1;
    }
    
    printf(YELLOW "[*] Polymorphic Shellcode Tester\n" RESET);
    
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
        fprintf(stderr, "Error reading file (read %zu of %zu bytes)\n", 
                bytes_read, size);
        free(buffer);
        return 1;
    }
    
    hexdump("Encoded shellcode (with decoder stub)", buffer, size);
    
    printf(YELLOW "[*] Executing polymorphic shellcode...\n" RESET);
    
    // Execute the shellcode
    int result = execute_shellcode(buffer, size);
    
    // This line will only be reached if the shellcode didn't terminate the process
    printf(RED "[!] Shellcode execution failed or did not terminate\n" RESET);
    
    free(buffer);
    return 0;
}