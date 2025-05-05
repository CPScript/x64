#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

// COFF File Header structure
typedef struct _COFF_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;

// COFF Section Header
typedef struct _COFF_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SECTION_HEADER, *PCOFF_SECTION_HEADER;

// COFF Relocation Entry
typedef struct _COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;

// COFF Symbol Table Entry
typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } Name;
    } N;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;

// COFF String Table
typedef struct _COFF_STRING_TABLE {
    uint32_t Size;
    char Strings[1];  // Variable size array
} COFF_STRING_TABLE, *PCOFF_STRING_TABLE;

// In-memory COFF module
typedef struct _COFF_MODULE {
    uint8_t* rawData;           // Original file data
    size_t rawSize;             // Size of the raw data
    PCOFF_FILE_HEADER header;   // Pointer to file header
    PCOFF_SECTION_HEADER sections; // Array of section headers
    PCOFF_SYMBOL symbols;       // Symbol table
    char* stringTable;          // String table
    void** sectionData;         // Array of pointers to loaded sections
    void* entryPoint;           // Entry point function
} COFF_MODULE, *PCOFF_MODULE;

// External symbol resolution function type
typedef void* (*SYMBOL_RESOLVER)(const char* symbolName);

// Machine types
#define IMAGE_FILE_MACHINE_I386  0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664

// Section flags
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ    0x40000000
#define IMAGE_SCN_MEM_WRITE   0x80000000
#define IMAGE_SCN_CNT_CODE    0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080

// Relocation types
#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_REL32  0x0004

// Symbol types
#define IMAGE_SYM_TYPE_NULL   0x0000
#define IMAGE_SYM_TYPE_FUNC   0x0020

// Symbol storage classes
#define IMAGE_SYM_CLASS_EXTERNAL 0x0002
#define IMAGE_SYM_CLASS_STATIC   0x0003

// Function prototypes
PCOFF_MODULE CoffLoadModule(const uint8_t* data, size_t size);
BOOL CoffRelocateModule(PCOFF_MODULE module, SYMBOL_RESOLVER resolver);
void* CoffGetExportedFunction(PCOFF_MODULE module, const char* functionName);
void CoffUnloadModule(PCOFF_MODULE module);
char* CoffGetSymbolName(PCOFF_MODULE module, PCOFF_SYMBOL symbol);

// Default resolver for Windows API functions
void* DefaultSymbolResolver(const char* symbolName) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE user32 = GetModuleHandleA("user32.dll");
    
    void* address = NULL;
    
    if (!address && kernel32) address = GetProcAddress(kernel32, symbolName);
    if (!address && ntdll) address = GetProcAddress(ntdll, symbolName);
    if (!address && user32) address = GetProcAddress(user32, symbolName);
    
    if (!address) {
        // Try to load additional libraries if needed
        HMODULE module = LoadLibraryA(symbolName);
        if (module) return module;
    }
    
    return address;
}

/**
 * Load a COFF module from memory
 * 
 * @param data Pointer to the raw COFF data
 * @param size Size of the COFF data
 * @return Pointer to the loaded COFF module or NULL on failure
 */
PCOFF_MODULE CoffLoadModule(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(COFF_FILE_HEADER)) {
        return NULL;
    }
    
    // Allocate module structure
    PCOFF_MODULE module = (PCOFF_MODULE)malloc(sizeof(COFF_MODULE));
    if (!module) {
        return NULL;
    }
    memset(module, 0, sizeof(COFF_MODULE));
    
    // Copy the raw data
    module->rawData = (uint8_t*)malloc(size);
    if (!module->rawData) {
        free(module);
        return NULL;
    }
    memcpy(module->rawData, data, size);
    module->rawSize = size;
    
    // Initialize pointers
    module->header = (PCOFF_FILE_HEADER)module->rawData;
    
    // Validate COFF header
    if (module->header->Machine != IMAGE_FILE_MACHINE_I386 && 
        module->header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        CoffUnloadModule(module);
        return NULL;
    }
    
    // Get section headers
    module->sections = (PCOFF_SECTION_HEADER)(module->rawData + sizeof(COFF_FILE_HEADER) + 
                                            module->header->SizeOfOptionalHeader);
    
    // Get symbol table
    if (module->header->PointerToSymbolTable && module->header->NumberOfSymbols) {
        module->symbols = (PCOFF_SYMBOL)(module->rawData + module->header->PointerToSymbolTable);
        
        // Get string table (located right after the symbol table)
        uint32_t stringTableOffset = module->header->PointerToSymbolTable + 
                                    (module->header->NumberOfSymbols * sizeof(COFF_SYMBOL));
        if (stringTableOffset < module->rawSize) {
            module->stringTable = (char*)(module->rawData + stringTableOffset);
        }
    }
    
    // Allocate section data array
    module->sectionData = (void**)malloc(module->header->NumberOfSections * sizeof(void*));
    if (!module->sectionData) {
        CoffUnloadModule(module);
        return NULL;
    }
    memset(module->sectionData, 0, module->header->NumberOfSections * sizeof(void*));
    
    // Load sections
    for (int i = 0; i < module->header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &module->sections[i];
        DWORD protectFlags = 0;
        
        // Determine section protection
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) protectFlags |= PAGE_EXECUTE_READWRITE;
        else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protectFlags |= PAGE_READWRITE;
        else if (section->Characteristics & IMAGE_SCN_MEM_READ) protectFlags |= PAGE_READONLY;
        else protectFlags = PAGE_READWRITE; // Default
        
        // Allocate memory for section
        DWORD sectionSize = max(section->VirtualSize, section->SizeOfRawData);
        if (sectionSize == 0) continue;
        
        module->sectionData[i] = VirtualAlloc(NULL, sectionSize, MEM_COMMIT | MEM_RESERVE, protectFlags);
        if (!module->sectionData[i]) {
            CoffUnloadModule(module);
            return NULL;
        }
        
        // Initialize section data
        if (section->SizeOfRawData > 0 && section->PointerToRawData > 0) {
            memcpy(module->sectionData[i], 
                   module->rawData + section->PointerToRawData, 
                   min(section->SizeOfRawData, sectionSize));
        } else {
            // BSS section or similar - just zero it out
            memset(module->sectionData[i], 0, sectionSize);
        }
    }
    
    return module;
}

/**
 * Get the name of a symbol from the COFF symbol table
 * 
 * @param module Pointer to the COFF module
 * @param symbol Pointer to the symbol table entry
 * @return Pointer to the symbol name
 */
char* CoffGetSymbolName(PCOFF_MODULE module, PCOFF_SYMBOL symbol) {
    static char shortName[9]; // 8 chars + null terminator
    
    if (!module || !symbol) {
        return NULL;
    }
    
    // Check if the name is in the symbol table or string table
    if (symbol->N.Name.Zeros == 0 && module->stringTable) {
        // Name is in the string table
        return module->stringTable + symbol->N.Name.Offset;
    } else {
        // Name is in the symbol structure
        memset(shortName, 0, sizeof(shortName));
        memcpy(shortName, symbol->N.ShortName, 8);
        return shortName;
    }
}

/**
 * Apply relocations to the COFF module
 * 
 * @param module Pointer to the COFF module
 * @param resolver Function to resolve external symbols
 * @return TRUE on success, FALSE on failure
 */
BOOL CoffRelocateModule(PCOFF_MODULE module, SYMBOL_RESOLVER resolver) {
    if (!module || !resolver) {
        return FALSE;
    }
    
    // Process each section
    for (int i = 0; i < module->header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &module->sections[i];
        
        // Skip sections without relocations
        if (section->NumberOfRelocations == 0 || section->PointerToRelocations == 0) {
            continue;
        }
        
        // Get relocation table for this section
        PCOFF_RELOCATION relocations = (PCOFF_RELOCATION)(module->rawData + section->PointerToRelocations);
        
        // Process each relocation
        for (int r = 0; r < section->NumberOfRelocations; r++) {
            PCOFF_RELOCATION reloc = &relocations[r];
            PCOFF_SYMBOL symbol = &module->symbols[reloc->SymbolTableIndex];
            void* symbolAddress = NULL;
            
            // Check if it's an internal or external symbol
            if (symbol->SectionNumber > 0) {
                // Internal symbol
                int targetSection = symbol->SectionNumber - 1;
                symbolAddress = (uint8_t*)module->sectionData[targetSection] + symbol->Value;
            } else if (symbol->SectionNumber == 0) {
                // External symbol - resolve it
                char* symbolName = CoffGetSymbolName(module, symbol);
                if (symbolName) {
                    symbolAddress = resolver(symbolName);
                }
                
                if (!symbolAddress) {
                    // Failed to resolve external symbol
                    return FALSE;
                }
            } else {
                // Special section number or undefined
                continue;
            }
            
            // Apply relocation
            uint8_t* relocTarget = (uint8_t*)module->sectionData[i] + reloc->VirtualAddress;
            
            switch (reloc->Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(uint64_t*)relocTarget = (uint64_t)symbolAddress;
                    break;
                
                case IMAGE_REL_AMD64_ADDR32:
                    *(uint32_t*)relocTarget = (uint32_t)((uint64_t)symbolAddress & 0xFFFFFFFF);
                    break;
                
                case IMAGE_REL_AMD64_REL32: {
                    // Relative address - 32-bit offset from the next instruction
                    uint64_t nextInstructionAddr = (uint64_t)relocTarget + 4;
                    int32_t offset = (int32_t)((uint64_t)symbolAddress - nextInstructionAddr);
                    *(int32_t*)relocTarget = offset;
                    break;
                }
                
                default:
                    // Unsupported relocation type
                    return FALSE;
            }
        }
    }
    
    // Find entry point (typically "main" symbol)
    module->entryPoint = CoffGetExportedFunction(module, "main");
    if (!module->entryPoint) {
        module->entryPoint = CoffGetExportedFunction(module, "_main");
    }
    
    return TRUE;
}

/**
 * Get an exported function from the COFF module
 * 
 * @param module Pointer to the COFF module
 * @param functionName Name of the function to find
 * @return Pointer to the function or NULL if not found
 */
void* CoffGetExportedFunction(PCOFF_MODULE module, const char* functionName) {
    if (!module || !functionName || !module->symbols || module->header->NumberOfSymbols == 0) {
        return NULL;
    }
    
    // Search symbol table for the function
    for (uint32_t i = 0; i < module->header->NumberOfSymbols; i++) {
        PCOFF_SYMBOL symbol = &module->symbols[i];
        
        // Skip auxiliary symbols
        i += symbol->NumberOfAuxSymbols;
        
        // Check if it's a function and has the right name
        if ((symbol->Type & IMAGE_SYM_TYPE_FUNC) && symbol->SectionNumber > 0) {
            char* symbolName = CoffGetSymbolName(module, symbol);
            if (symbolName && strcmp(symbolName, functionName) == 0) {
                int sectionIndex = symbol->SectionNumber - 1;
                return (uint8_t*)module->sectionData[sectionIndex] + symbol->Value;
            }
        }
    }
    
    return NULL;
}

/**
 * Unload a COFF module and free all associated resources
 * 
 * @param module Pointer to the COFF module
 */
void CoffUnloadModule(PCOFF_MODULE module) {
    if (!module) {
        return;
    }
    
    // Free section data
    if (module->sectionData) {
        for (int i = 0; i < module->header->NumberOfSections; i++) {
            if (module->sectionData[i]) {
                VirtualFree(module->sectionData[i], 0, MEM_RELEASE);
            }
        }
        free(module->sectionData);
    }
    
    // Free raw data
    if (module->rawData) {
        free(module->rawData);
    }
    
    // Free module structure
    free(module);
}

/**
 * Execute a loaded COFF module
 * 
 * @param module Pointer to the COFF module
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return The return value of the executed function
 */
int CoffExecuteModule(PCOFF_MODULE module, int argc, char** argv) {
    if (!module || !module->entryPoint) {
        return -1;
    }
    
    // Cast the entry point to the appropriate function type
    int (*mainFunc)(int, char**) = (int (*)(int, char**))module->entryPoint;
    
    // Call the entry point
    return mainFunc(argc, argv);
}

/**
 * Load a COFF file from disk and execute it
 * 
 * @param filename Path to the COFF file
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return The return value of the executed function or -1 on failure
 */
int CoffLoadAndExecuteFile(const char* filename, int argc, char** argv) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate buffer and read file
    uint8_t* buffer = (uint8_t*)malloc(fileSize);
    if (!buffer) {
        fclose(file);
        return -1;
    }
    
    if (fread(buffer, 1, fileSize, file) != fileSize) {
        free(buffer);
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    // Load and execute the COFF module
    PCOFF_MODULE module = CoffLoadModule(buffer, fileSize);
    if (!module) {
        free(buffer);
        return -1;
    }
    
    if (!CoffRelocateModule(module, DefaultSymbolResolver)) {
        CoffUnloadModule(module);
        free(buffer);
        return -1;
    }
    
    int result = CoffExecuteModule(module, argc, argv);
    
    // Cleanup
    CoffUnloadModule(module);
    free(buffer);
    
    return result;
}

// Example usage
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <coff_file> [args...]\n", argv[0]);
        return 1;
    }
    
    return CoffLoadAndExecuteFile(argv[1], argc - 1, &argv[1]);
}