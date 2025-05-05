; ELF Unpacker Stub - x64 version
; Position-independent code that unpacks and executes the original ELF binary
; To be prepended to the packed executable

BITS 64

section .text

global _start

_start:
    ; Save registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    ; Get current RIP to establish position-independent addressing
    call get_rip
get_rip:
    pop rbx                    ; RBX = current RIP
    sub rbx, get_rip           ; Adjust to get the actual start of our code
    
    ; Find the packed data (header is right after our stub)
    lea rsi, [rbx + stub_end]  ; RSI = pointer to packer header
    
    ; Verify signature
    mov eax, [rsi]             ; First 4 bytes of signature
    cmp eax, 'PKEL'            ; Check first part of signature
    jne unpacking_failed
    cmp byte [rsi+4], 'F'      ; Check last byte of signature
    jne unpacking_failed
    
    ; Extract header information
    mov ecx, [rsi + 8]         ; Original size
    mov edx, [rsi + 12]        ; Packed size
    mov eax, [rsi + 16]        ; Original entry point
    ; mov ebp, [rsi + 20]      ; Original base address (not used in this example)
    
    ; Point to packed data
    add rsi, 24                ; Skip the header (size = 24 bytes)
    
    ; Allocate memory for the unpacked executable using mmap
    ; void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    mov rdi, 0                 ; addr = NULL (let kernel choose)
    mov rsi, rcx               ; length = original size
    mov rdx, 0x7               ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
    mov r10, 0x22              ; flags = MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                 ; fd = -1
    mov r9, 0                  ; offset = 0
    mov rax, 9                 ; syscall number for mmap
    syscall
    
    ; Check if mmap succeeded
    cmp rax, -1
    je unpacking_failed
    
    ; RAX = Base address of allocated memory
    mov rdi, rax               ; RDI = destination for unpacked data
    lea rsi, [rbx + stub_end + 24] ; RSI = source (packed data)
    
    ; Decrypt/decompress the data (simplified XOR decryption)
    mov r8, 0x37               ; XOR key (same as in C code)
    mov rcx, rdx               ; RCX = packed size
    
decrypt_loop:
    mov al, [rsi]              ; Load byte from source
    xor al, r8b                ; XOR with key
    mov [rdi], al              ; Store at destination
    inc rsi
    inc rdi
    dec rcx
    jnz decrypt_loop
    
    ; Get unpacked executable base
    sub rdi, rdx               ; RDI = start of unpacked data
    
    ; Parse ELF headers to find the entry point
    mov rsi, rdi               ; RSI = ELF base
    
    ; Check ELF magic
    cmp dword [rsi], 0x464C457F ; ELF magic number
    jne unpacking_failed
    
    ; Get entry point address
    mov rax, [rsi + 0x18]      ; e_entry offset in 64-bit ELF header
    
    ; Jump to original entry point
    ; Note: In a real implementation, we would need to set up the stack properly
    ; and handle dynamic linking if needed
    
    ; Restore registers (in reverse order)
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Jump to entry point
    jmp rax
    
unpacking_failed:
    ; Exit with error status
    mov rdi, 1                 ; exit status = 1
    mov rax, 60                ; syscall number for exit
    syscall
    
stub_end:
    ; Our packed data and header starts here