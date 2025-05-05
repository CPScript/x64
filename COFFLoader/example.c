#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Include the COFF loader header (assuming it's in coff_loader.h)
#include "coff_loader.h"

// Advanced usage example with memory-only execution
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <coff_file> [args...]\n", argv[0]);
        return 1;
    }
    
    // Read the COFF file into memory
    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", argv[1]);
        return 1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate buffer and read file
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (!buffer) {
        printf("Error: Memory allocation failed\n");
        fclose(file);
        return 1;
    }
    
    if (fread(buffer, 1, fileSize, file) != fileSize) {
        printf("Error: Failed to read file content\n");
        free(buffer);
        fclose(file);
        return 1;
    }
    
    fclose(file);
    
    // Custom symbol resolver that logs resolved symbols
    void* CustomResolver(const char* symbolName) {
        void* address = DefaultSymbolResolver(symbolName);
        printf("Resolving symbol: %s -> %p\n", symbolName, address);
        return address;
    }
    
    // Load the COFF module
    PCOFF_MODULE module = CoffLoadModule(buffer, fileSize);
    if (!module) {
        printf("Error: Failed to load COFF module\n");
        free(buffer);
        return 1;
    }
    
    // Relocate the module using our custom resolver
    if (!CoffRelocateModule(module, CustomResolver)) {
        printf("Error: Failed to relocate COFF module\n");
        CoffUnloadModule(module);
        free(buffer);
        return 1;
    }
    
    // Free the buffer as it's no longer needed
    free(buffer);
    
    // Get a specific exported function (optional)
    typedef int (*CustomFunction)(const char*, int);
    CustomFunction customFunc = (CustomFunction)CoffGetExportedFunction(module, "specific_function");
    if (customFunc) {
        printf("Calling specific_function directly: %d\n", customFunc("test", 123));
    }
    
    // Execute the COFF module's main function
    printf("Executing COFF module main function...\n");
    int result = CoffExecuteModule(module, argc - 1, &argv[1]);
    printf("Execution completed with result: %d\n", result);
    
    // Unload the module
    CoffUnloadModule(module);
    
    return 0;
}