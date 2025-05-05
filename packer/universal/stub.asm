;-----------------------------------------------------------------------------
; Universal PE/ELF Unpacker Stub - x86-64 Assembly
;
; Handles runtime unpacking of compressed/encrypted executables for both
; PE (Windows) and ELF (Linux) formats.
;
; Assembler: NASM (nasm -f bin stub.asm -o stub.bin)
;-----------------------------------------------------------------------------

BITS 64

%define MAGIC                   'UPEF'  ; Magic identifier
%define HEADER_SIZE             64      ; Size of the packed header
%define FORMAT_TYPE_OFFSET      4       ; Format type offset in header
%define VERSION_OFFSET          5       ; Version offset in header
%define COMPRESSION_OFFSET      6       ; Compression type offset in header
%define ENCRYPTION_OFFSET       7       ; Encryption type offset in header
%define OEP_OFFSET              8       ; Original entry point offset in header
%define IMAGE_BASE_OFFSET       16      ; Image base offset in header (PE only)
%define KEY_LENGTH_OFFSET       24      ; Key length offset in header
%define ENTROPY_LAYERS_OFFSET   25      ; Entropy layers offset in header
%define ORIGINAL_SIZE_OFFSET    26      ; Original file size offset in header
%define PACKED_SIZE_OFFSET      30      ; Packed data size offset in header
%define KEY_DATA_OFFSET         34      ; Encryption key data offset in header

%define FORMAT_PE               0       ; PE format identifier
%define FORMAT_ELF              1       ; ELF format identifier

%define COMP_NONE               0       ; No compression
%define COMP_ZLIB               1       ; ZLIB compression
%define COMP_LZMA               2       ; LZMA compression

%define ENCRYPT_NONE            0       ; No encryption
%define ENCRYPT_XOR             1       ; XOR encryption
%define ENCRYPT_AES             2       ; AES encryption

; For Windows syscalls
%define PAGE_EXECUTE_READWRITE  0x40    ; Memory protection constant

; For Linux syscalls
%define PROT_READ               0x1     ; Page can be read
%define PROT_WRITE              0x2     ; Page can be written
%define PROT_EXEC               0x4     ; Page can be executed
%define MAP_PRIVATE             0x2     ; Changes are private
%define MAP_ANONYMOUS           0x20    ; Don't use a file
%define SYS_MMAP                9       ; mmap syscall number
%define SYS_MPROTECT            10      ; mprotect syscall number

;-----------------------------------------------------------------------------
; Stub Entry Point
;-----------------------------------------------------------------------------
section .text
global _start

_start:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Get current position (delta offset technique)
    call get_delta
get_delta:
    pop rbp
    sub rbp, get_delta

    ; First, detect the platform (Windows vs Linux)
    ; We'll do this by attempting a Linux-specific syscall
    ; If we're on Linux, this succeeds; on Windows, it will likely cause an exception
    ; that is caught by the OS and execution continues at the Windows handler
    
    ; Linux Platform Detection: Try to get PID using getpid syscall (39)
    mov rax, 39              ; getpid syscall
    syscall
    
    ; If we get here and rax is not a huge value, we're likely on Linux
    cmp rax, 0x8000000000000000
    jae detect_windows       ; Likely Windows if rax has a very large value
    
    ; We're on Linux, continue with Linux unpacker
    jmp detect_linux

detect_windows:
    ; We're on Windows - continue with PE unpacking path
    mov dword [rbp + platform], FORMAT_PE
    jmp load_header

detect_linux:
    ; We're on Linux - continue with ELF unpacking path
    mov dword [rbp + platform], FORMAT_ELF
    
load_header:
    ; Find the packed header which follows this stub
    ; We calculate this by adding _end - _start to our current location
    lea rsi, [rbp + _end]    ; Start of the header
    
    ; Verify the magic number
    lodsd
    cmp eax, MAGIC
    jne exit_stub            ; Invalid magic, abort
    
    ; Get the format type (PE/ELF)
    xor eax, eax
    lodsb                    ; AL = format type
    cmp al, byte [rbp + platform]
    jne exit_stub            ; Wrong platform, abort
    
    ; Skip version
    lodsb
    
    ; Get compression and encryption types
    xor ecx, ecx
    lodsb                    ; compression type
    mov [rbp + compression_type], al
    
    lodsb                    ; encryption type
    mov [rbp + encryption_type], al
    
    ; Get original entry point
    mov rax, qword [rsi]
    mov [rbp + original_entry_point], rax
    add rsi, 8
    
    ; Get image base (PE only)
    mov rax, qword [rsi]
    mov [rbp + image_base], rax
    add rsi, 8
    
    ; Get key length and entropy layers
    xor eax, eax
    lodsb                    ; key length
    mov [rbp + key_length], al
    
    lodsb                    ; entropy layers
    mov [rbp + entropy_layers], al
    
    ; Get original and packed sizes
    lodsd                    ; original size
    mov [rbp + original_size], eax
    
    lodsd                    ; packed size
    mov [rbp + packed_size], eax
    
    ; Get the key data
    mov ecx, [rbp + key_length]
    test ecx, ecx
    jz no_key
    
    ; Copy the key
    lea rdi, [rbp + key_data]
    rep movsb
    
no_key:
    ; Calculate where the packed data begins
    lea rsi, [rbp + _end]    ; Start of the header
    add rsi, HEADER_SIZE     ; Skip the header

    ; Allocate memory for the unpacked executable
    call allocate_memory
    test rax, rax
    jz exit_stub             ; Memory allocation failed
    
    ; Save the allocated memory address
    mov [rbp + unpacked_buffer], rax
    
    ; Decrypt and decompress the packed data
    call process_packed_data
    
    ; Now we have the unpacked executable in memory, prepare to run it
    call prepare_execution
    
    ; Jump to the original entry point
    call execute_unpacked
    
    ; We should never reach here as the unpacked code takes over
    
exit_stub:
    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Return to the OS - this should never actually be reached
    ; as we jump to the unpacked program before this
    ret

;-----------------------------------------------------------------------------
; Memory Allocation Function - Platform specific
;-----------------------------------------------------------------------------
allocate_memory:
    ; Determine which platform allocation to use
    cmp dword [rbp + platform], FORMAT_PE
    je allocate_memory_windows
    jmp allocate_memory_linux

allocate_memory_windows:
    ; Windows memory allocation using VirtualAlloc
    ; Get the VirtualAlloc function address (would normally use GetProcAddress)
    ; This is a simplified version - in a real implementation, you'd need to
    ; properly get the function address from kernel32.dll
    
    ; For this stub, we'll assume we already have it for brevity
    ; This would need to be implemented properly with PEB/LDR traversal
    
    ; Parameters for VirtualAlloc:
    ; rcx = lpAddress (NULL for system choice)
    ; rdx = dwSize (size to allocate)
    ; r8 = flAllocationType (MEM_COMMIT | MEM_RESERVE = 0x3000)
    ; r9 = flProtect (PAGE_EXECUTE_READWRITE = 0x40)
    
    sub rsp, 40              ; Shadow space for Win64 calling convention
    
    xor rcx, rcx             ; NULL - let system choose address
    mov rdx, [rbp + original_size]  ; Size to allocate
    mov r8, 0x3000           ; MEM_COMMIT | MEM_RESERVE
    mov r9, PAGE_EXECUTE_READWRITE
    
    ; Call VirtualAlloc - here, we'd use the actual function address
    ; For demonstration, we'll just use a placeholder
    ; call [VirtualAlloc]
    
    ; Placeholder for actual implementation:
    mov rax, rcx             ; Just return the requested address for demo
    
    add rsp, 40              ; Clean up shadow space
    ret

allocate_memory_linux:
    ; Linux memory allocation using mmap
    ; Parameters for mmap:
    ; rax = syscall number (9 for mmap)
    ; rdi = addr (NULL for system choice)
    ; rsi = length
    ; rdx = prot (PROT_READ | PROT_WRITE | PROT_EXEC)
    ; r10 = flags (MAP_PRIVATE | MAP_ANONYMOUS)
    ; r8 = fd (-1 for anonymous mapping)
    ; r9 = offset (0)
    
    mov rax, SYS_MMAP       ; mmap syscall
    xor rdi, rdi            ; NULL - let system choose address
    mov rsi, [rbp + original_size]  ; Size to allocate
    mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC  ; Protection flags
    mov r10, MAP_PRIVATE | MAP_ANONYMOUS  ; Mapping flags
    mov r8, -1              ; No file descriptor (anonymous)
    xor r9, r9              ; Offset of 0
    
    syscall
    
    ; rax now contains the allocated memory address or error code
    cmp rax, 0xfffffffffffff000
    jae allocation_failed    ; If rax >= -4096, it's an error
    
    ret

allocation_failed:
    xor rax, rax             ; Return NULL to indicate failure
    ret

;-----------------------------------------------------------------------------
; Process Packed Data - Decrypt and decompress
;-----------------------------------------------------------------------------
process_packed_data:
    ; Determine which processing steps are needed
    mov al, [rbp + encryption_type]
    
    ; Check for encryption
    test al, al
    jz check_compression     ; No encryption
    
    ; Decrypt the data based on encryption type
    cmp al, ENCRYPT_XOR
    je decrypt_xor
    
    ; AES decryption would be here (not implemented in this basic stub)
    ; In a real implementation, you would call into a crypto library or
    ; implement the AES algorithm in assembly
    
decrypt_xor:
    ; Simple XOR decryption
    mov rsi, [rbp + packed_data]    ; Source (packed data)
    mov rdi, [rbp + temp_buffer]    ; Destination (temp buffer)
    mov ecx, [rbp + packed_size]    ; Size to process
    
    xor edx, edx                    ; Key index
    
xor_loop:
    movzx eax, byte [rsi]           ; Get a byte of packed data
    movzx ebx, byte [rbp + key_data + rdx]  ; Get a byte of the key
    
    xor al, bl                      ; XOR with key
    
    stosb                           ; Store to destination
    inc rsi                         ; Next source byte
    
    inc rdx                         ; Next key byte
    cmp dl, [rbp + key_length]      ; End of key?
    jb xor_continue                 ; No, continue
    xor edx, edx                    ; Yes, wrap around to start of key
    
xor_continue:
    dec ecx                         ; Decrement counter
    jnz xor_loop                    ; Continue until done
    
    ; Update source to point to decrypted data for decompression
    mov rsi, [rbp + temp_buffer]
    jmp check_compression

check_compression:
    ; Check compression type
    mov al, [rbp + compression_type]
    test al, al
    jz no_compression       ; No compression, just copy
    
    ; Decompress based on compression type
    cmp al, COMP_ZLIB
    je decompress_zlib
    
    ; LZMA decompression would be here (not implemented in this basic stub)
    ; In a real implementation, you would call into a compression library
    ; or implement the decompression algorithm in assembly
    
    ; For now, just fail if compression is not supported
    jmp exit_stub

decompress_zlib:
    ; Zlib decompression would be implemented here
    ; Again, in a real implementation, this would call into a decompression
    ; library or implement the algorithm in assembly
    
    ; For this stub, we'll just pretend to decompress by copying
    ; to the destination buffer
    
no_compression:
    ; Just copy the data to the unpacked buffer
    mov rsi, [rbp + packed_data]    ; Source
    mov rdi, [rbp + unpacked_buffer]  ; Destination
    mov ecx, [rbp + original_size]   ; Size to copy
    
    ; Copy in 8-byte chunks when possible
    shr ecx, 3              ; Divide by 8 to get qword count
    rep movsq
    
    ; Copy any remaining bytes
    mov ecx, [rbp + original_size]
    and ecx, 7              ; Remainder bytes
    rep movsb
    
    ret

;-----------------------------------------------------------------------------
; Prepare Execution - Format-specific setup before jumping to unpacked code
;-----------------------------------------------------------------------------
prepare_execution:
    ; Determine which format-specific preparation to use
    cmp dword [rbp + platform], FORMAT_PE
    je prepare_pe
    jmp prepare_elf

prepare_pe:
    ; PE-specific preparation
    ; In a real implementation, this would handle sections, imports, relocations, etc.
    ; For this stub, we'll just do basic preparation
    
    ; For PE, we need to calculate the actual entry point in memory
    mov rax, [rbp + original_entry_point]
    add rax, [rbp + image_base]
    mov [rbp + jump_address], rax
    
    ret

prepare_elf:
    ; ELF-specific preparation
    ; For ELF, the entry point is usually an absolute virtual address
    
    ; Set the jump address to the original entry point
    mov rax, [rbp + original_entry_point]
    mov [rbp + jump_address], rax
    
    ret

;-----------------------------------------------------------------------------
; Execute Unpacked - Jump to the unpacked executable's entry point
;-----------------------------------------------------------------------------
execute_unpacked:
    ; Restore registers before jumping
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    
    ; Jump to the original entry point
    jmp [rbp + jump_address]

;-----------------------------------------------------------------------------
; Data Section
;-----------------------------------------------------------------------------
section .data
    platform:               dd 0            ; 0 = PE, 1 = ELF
    compression_type:       db 0            ; Compression type from header
    encryption_type:        db 0            ; Encryption type from header
    original_entry_point:   dq 0            ; Original entry point
    image_base:             dq 0            ; Image base for PE
    key_length:             db 0            ; Length of encryption key
    entropy_layers:         db 0            ; Number of entropy layers
    original_size:          dd 0            ; Original unpacked size
    packed_size:            dd 0            ; Size of packed data
    unpacked_buffer:        dq 0            ; Address of unpacked memory
    jump_address:           dq 0            ; Calculated jump address
    packed_data:            dq 0            ; Pointer to packed data
    temp_buffer:            dq 0            ; Temporary buffer for processing
    
    ; The following buffer is a placeholder for the key - in a real implementation
    ; this would need to be properly allocated based on the actual key size
    key_data:               times 32 db 0   ; Buffer for encryption key

;-----------------------------------------------------------------------------
; End Marker - Used to find the boundary between stub and packed data
;-----------------------------------------------------------------------------
_end:
    ; Packed header and data follow this marker