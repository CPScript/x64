; Unpacker Stub for PE files - x86 version
; Position-independent code to be prepended to the packed executable
; This handles unpacking, loading and transferring execution to the original entry point

BITS 32

section .text

global _start

_start:
    ; Save registers
    pushad
    
    ; Get current EIP to establish position-independent addressing
    call get_eip
get_eip:
    pop ebx                     ; EBX = current EIP
    sub ebx, get_eip            ; Adjust to get the actual start of our code
    
    ; Find the packed data (header is right after our stub)
    lea esi, [ebx + stub_end]   ; ESI = pointer to packer header
    
    ; Verify signature
    mov edi, [esi]              ; First 4 bytes of signature
    cmp edi, 'PKEX'             ; Check first part of signature
    jne unpacking_failed
    cmp byte [esi+4], 'E'       ; Check last byte of signature
    jne unpacking_failed
    
    ; Extract header information
    mov ecx, [esi + 8]          ; Original size
    mov edx, [esi + 12]         ; Packed size
    mov eax, [esi + 16]         ; Original entry point RVA
    mov ebp, [esi + 20]         ; Original image base
    
    ; Point to packed data
    add esi, 24                 ; Skip the header (size = 24 bytes)
    
    ; Allocate memory for the unpacked executable
    push ecx                    ; Save original size
    push 0x40                   ; PAGE_EXECUTE_READWRITE
    push ecx                    ; Size to allocate
    push 0                      ; Let the system decide the address
    push 0xFFFFFFFF             ; Current process
    call [ebx + offset_VirtualAlloc]
    test eax, eax
    jz unpacking_failed
    
    ; EAX = Base address of allocated memory
    mov edi, eax                ; EDI = destination for unpacked data
    pop ecx                     ; Restore original size
    
    ; Decrypt/decompress the data (simplified XOR decryption)
    mov ebp, 0x37               ; XOR key (same as in C code)
    
decrypt_loop:
    lodsb                       ; Load byte from ESI into AL
    xor al, bpl                 ; XOR with key
    stosb                       ; Store decrypted byte to EDI
    loop decrypt_loop           ; Continue until ECX = 0
    
    ; Get unpacked executable base
    sub edi, ecx                ; EDI = start of unpacked data
    
    ; Parse PE headers to find the entry point
    mov esi, edi                ; ESI = PE base
    
    ; Check DOS signature
    cmp word [esi], 'MZ'
    jne unpacking_failed
    
    ; Get PE header offset
    mov ebx, [esi + 0x3C]       ; e_lfanew
    add ebx, esi                ; EBX = PE header
    
    ; Check PE signature
    cmp dword [ebx], 'PE'
    jne unpacking_failed
    
    ; Get entry point RVA
    mov eax, [ebx + 0x28]       ; AddressOfEntryPoint
    add eax, edi                ; Add base address
    
    ; Jump to original entry point
    popad                       ; Restore registers
    jmp eax                     ; Jump to OEP
    
unpacking_failed:
    ; Handle error (in production code, this would be more graceful)
    push 0
    call [ebx + offset_ExitProcess]
    
stub_end:
    ; Our packed data and header starts here
    
; Offsets to Windows API functions (would be resolved dynamically in a real implementation)
offset_VirtualAlloc dd 0x12345678    ; Placeholder
offset_ExitProcess  dd 0x87654321    ; Placeholder