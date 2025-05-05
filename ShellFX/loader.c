#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>

// Optional shellcode - embedded here when extracted using shellcode_extractor
#ifndef SHELLCODE_EMBEDDED
unsigned char shellcode[] = {
    // replace with your actual shellcode  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    0x90, 0x90, 0x90, 0x90, 0x90  // NOP sled
};
unsigned int shellcode_len = 5;
#endif

void sighandler(int sig) {
    printf("\n[!] Signal %d received. Exiting...\n", sig);
    exit(1);
}

/**
 * execute_shellcode - Executes shellcode in memory
 * @shellcode: Pointer to shellcode buffer
 * @size: Size of shellcode
 * @verbose: Enable verbose output
 * 
 * Returns: Does not return on success, -1 on failure
 */
int execute_shellcode(unsigned char *shellcode, size_t size, int verbose) {
    void *mem;
    int (*sc)();
    int ret;
    
    if (verbose) {
        printf("[*] Allocating %zu bytes of memory with RWX permissions\n", size);
    }
    
    // Allocate memory with RWX permissions
    mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("[-] mmap failed");
        return -1;
    }
    
    if (verbose) {
        printf("[+] Memory allocated at %p\n", mem);
        printf("[*] Copying shellcode to memory\n");
    }
    
    // Copy shellcode to memory
    memcpy(mem, shellcode, size);
    
    // Flush instruction cache (relevant on some architectures)
    __builtin___clear_cache(mem, (char *)mem + size);
    
    if (verbose) {
        printf("[+] Shellcode copied to memory\n");
        printf("[*] Executing shellcode\n");
        printf("[!] Control will be transferred to shellcode. Press Ctrl+C to abort.\n");
        printf("-------- Shellcode Output --------\n");
        fflush(stdout);
    }
    
    // Cast memory to function pointer and execute
    sc = (int (*)())mem;
    ret = sc();
    
    // Should not reach here if shellcode doesn't return
    if (verbose) {
        printf("\n-------- Shellcode Returned --------\n");
        printf("[+] Shellcode execution completed with return value: %d\n", ret);
    }
    
    // Free memory
    munmap(mem, size);
    
    return ret;
}

/**
 * load_shellcode_from_file - Loads shellcode from file
 * @filename: Path to shellcode file
 * @shellcode: Pointer to shellcode buffer pointer
 * @size: Pointer to size variable
 * 
 * Returns: 0 on success, -1 on failure
 */
int load_shellcode_from_file(const char *filename, unsigned char **shellcode, size_t *size) {
    FILE *fp;
    long file_size;
    
    fp = fopen(filename, "rb");
    if (!fp) {
        perror("[-] Failed to open shellcode file");
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);
    
    if (file_size <= 0) {
        fprintf(stderr, "[-] Empty shellcode file\n");
        fclose(fp);
        return -1;
    }
    
    // Allocate memory
    *shellcode = (unsigned char *)malloc(file_size);
    if (!*shellcode) {
        perror("[-] Failed to allocate memory for shellcode");
        fclose(fp);
        return -1;
    }
    
    // Read shellcode
    if (fread(*shellcode, 1, file_size, fp) != (size_t)file_size) {
        perror("[-] Failed to read shellcode");
        fclose(fp);
        free(*shellcode);
        *shellcode = NULL;
        return -1;
    }
    
    fclose(fp);
    *size = file_size;
    
    return 0;
}

/**
 * analyze_shellcode - Checks shellcode for potential issues
 * @shellcode: Pointer to shellcode buffer
 * @size: Size of shellcode
 * 
 * Returns: Number of bad characters found (0 means clean)
 */
int analyze_shellcode(unsigned char *shellcode, size_t size) {
    int null_bytes = 0;
    int bad_chars = 0;
    const unsigned char common_bad[] = {0x0a, 0x0d, 0x20, 0x09, 0x0b, 0x0c, 0xff};
    const char *bad_names[] = {"\\n", "\\r", "space", "\\t", "\\v", "\\f", "0xff"};
    int i, j;
    
    printf("[*] Analyzing shellcode (%zu bytes):\n", size);
    
    // Check for NULL bytes
    for (i = 0; i < size; i++) {
        if (shellcode[i] == 0x00) {
            null_bytes++;
        }
    }
    
    printf("[*] NULL bytes: %d\n", null_bytes);
    
    if (null_bytes > 0) {
        printf("[!] Warning: NULL bytes found at offsets: ");
        for (i = 0, j = 0; i < size; i++) {
            if (shellcode[i] == 0x00) {
                printf("%d%s", i, (++j < null_bytes) ? ", " : "");
            }
        }
        printf("\n");
    }
    
    // Check for other common bad characters
    printf("[*] Checking for common bad characters:\n");
    
    for (j = 0; j < sizeof(common_bad); j++) {
        int count = 0;
        
        for (i = 0; i < size; i++) {
            if (shellcode[i] == common_bad[j]) {
                count++;
            }
        }
        
        if (count > 0) {
            printf("[!] 0x%02x (%s): %d occurrences\n", common_bad[j], bad_names[j], count);
            bad_chars += count;
        }
    }
    
    if (null_bytes == 0 && bad_chars == 0) {
        printf("[+] Shellcode is clean! No NULL bytes or common bad characters found.\n");
    }
    
    return null_bytes + bad_chars;
}

/**
 * hex_dump - Prints shellcode in hex format
 * @data: Pointer to data buffer
 * @size: Size of data
 */
void hex_dump(unsigned char *data, size_t size) {
    size_t i, j;
    
    for (i = 0; i < size; i += 16) {
        printf("%04zx: ", i);
        
        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" | ");
        
        // Print ASCII representation
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                unsigned char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            } else {
                printf(" ");
            }
        }
        
        printf(" |\n");
    }
}

void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -f, --file FILE       Load shellcode from FILE\n");
    printf("  -d, --dump            Dump shellcode in hex format\n");
    printf("  -a, --analyze         Analyze shellcode for bad characters\n");
    printf("  -e, --execute         Execute shellcode (default if no other options)\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Display this help\n");
}

int main(int argc, char *argv[]) {
    unsigned char *sc = NULL;
    size_t sc_size = 0;
    int dump = 0;
    int analyze = 0;
    int execute = 0;
    int verbose = 0;
    char *filename = NULL;
    int i;
    int ret = 0;
    
    // Register signal handlers
    signal(SIGSEGV, sighandler);
    signal(SIGILL, sighandler);
    
    // Parse arguments
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] Missing file argument\n");
                print_usage(argv[0]);
                return 1;
            }
            filename = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dump") == 0) {
            dump = 1;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--analyze") == 0) {
            analyze = 1;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--execute") == 0) {
            execute = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[-] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // If no action specified, default to execute
    if (!dump && !analyze && !execute) {
        execute = 1;
    }
    
    // Load shellcode from file if specified
    if (filename) {
        printf("[*] Loading shellcode from %s\n", filename);
        if (load_shellcode_from_file(filename, &sc, &sc_size) < 0) {
            return 1;
        }
        printf("[+] Loaded %zu bytes of shellcode\n", sc_size);
    } else {
        // Use embedded shellcode
        printf("[*] Using embedded shellcode (%u bytes)\n", shellcode_len);
        sc = shellcode;
        sc_size = shellcode_len;
    }
    
    // Dump shellcode
    if (dump) {
        printf("[*] Shellcode hex dump:\n");
        hex_dump(sc, sc_size);
        printf("\n");
    }
    
    // Analyze shellcode
    if (analyze) {
        int bad = analyze_shellcode(sc, sc_size);
        if (bad > 0) {
            printf("[!] Found %d potential issues in shellcode\n", bad);
        }
        printf("\n");
    }
    
    // Execute shellcode
    if (execute) {
        printf("[*] Executing shellcode...\n");
        ret = execute_shellcode(sc, sc_size, verbose);
        
        // If we get here, the shellcode returned instead of taking over
        printf("[+] Shellcode execution completed with return value: %d\n", ret);
    }
    
    // Cleanup
    if (filename && sc) {
        free(sc);
    }
    
    return ret;
}