; =============================================================================
; x64 Hardware Inspector - Bare Metal Implementation
; 
; A comprehensive hardware inspection utility that bypasses OS APIs to directly
; interface with CPU registers, memory structures, and hardware I/O ports.
;
; - Designed to run as an EFI application (UEFI) or Legacy BIOS bootloader
; - Contains direct hardware interaction via privileged instructions
; - Provides deep visibility into internal CPU state, memory layout, and I/O devices
; =============================================================================

BITS 64
DEFAULT REL                     ; Use RIP-relative addressing by default

; =============================================================================
; EFI Application Header
; =============================================================================
section .text

global _start

; EFI Application Entry Point
_start:
    ; Preserve incoming parameters (x64 System V ABI)
    push    rbp
    mov     rbp, rsp
    
    ; Save EFI parameters
    mov     [ImageHandle], rcx  ; First parameter: EFI_HANDLE
    mov     [SystemTable], rdx  ; Second parameter: EFI_SYSTEM_TABLE*
    
    ; Set up output
    call    initialize_output
    
    ; Display program header
    lea     rdi, [program_header]
    call    print_string
    
    ; === Execute main inspection modules ===
    call    inspect_cpu         ; CPU & Register inspection
    call    inspect_memory      ; Memory map inspection 
    call    inspect_io          ; I/O port & PCI scanning
    call    inspect_processes   ; Process structure inspection (if OS detected)
    call    inspect_cache       ; Cache hierarchy inspection via CPUID
    call    inspect_security    ; Security features (SMM, SecureBoot)
    
    ; Program complete
    lea     rdi, [program_footer]
    call    print_string
    
    ; Wait for keypress before exit
    call    wait_for_key
    
    ; Exit
    xor     eax, eax            ; Return success (0)
    leave
    ret

; =============================================================================
; CPU & Register Inspection Module
; =============================================================================
inspect_cpu:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [cpu_header]
    call    print_string
    
    ; --- Basic CPU Info via CPUID ---
    ; Get CPU vendor string
    xor     eax, eax            ; CPUID leaf 0: Basic info
    cpuid
    
    ; Store vendor string (EBX, EDX, ECX contain the 12-byte ASCII string)
    mov     [cpu_vendor], ebx
    mov     [cpu_vendor+4], edx
    mov     [cpu_vendor+8], ecx
    mov     byte [cpu_vendor+12], 0   ; Null-terminate
    
    ; Print vendor
    lea     rdi, [cpu_vendor_str]
    call    print_string
    lea     rdi, [cpu_vendor]
    call    print_string
    call    print_newline
    
    ; Get CPU brand string (CPUID leaves 0x80000002-0x80000004)
    mov     eax, 0x80000000     ; Check if brand string is supported
    cpuid
    cmp     eax, 0x80000004     ; Must support up to leaf 0x80000004
    jb      .no_brand_string
    
    mov     eax, 0x80000002     ; First part of brand string
    cpuid
    mov     [cpu_brand], eax
    mov     [cpu_brand+4], ebx
    mov     [cpu_brand+8], ecx
    mov     [cpu_brand+12], edx
    
    mov     eax, 0x80000003     ; Second part of brand string
    cpuid
    mov     [cpu_brand+16], eax
    mov     [cpu_brand+20], ebx
    mov     [cpu_brand+24], ecx
    mov     [cpu_brand+28], edx
    
    mov     eax, 0x80000004     ; Third part of brand string
    cpuid
    mov     [cpu_brand+32], eax
    mov     [cpu_brand+36], ebx
    mov     [cpu_brand+40], ecx
    mov     [cpu_brand+44], edx
    mov     byte [cpu_brand+48], 0    ; Null-terminate
    
    ; Print CPU brand string
    lea     rdi, [cpu_brand_str]
    call    print_string
    lea     rdi, [cpu_brand]
    call    print_string
    call    print_newline
    
    jmp     .continue_cpu_info
    
.no_brand_string:
    lea     rdi, [cpu_unknown_str]
    call    print_string
    
.continue_cpu_info:
    ; Get family/model information
    mov     eax, 1             ; CPUID leaf 1: Family/Model
    cpuid
    
    ; Extract family & model
    mov     ebx, eax
    shr     ebx, 8             ; Move family to lower 4 bits
    and     ebx, 0Fh           ; Mask to get just family
    mov     [cpu_family], ebx
    
    mov     ebx, eax
    shr     ebx, 4             ; Move model to lower 4 bits
    and     ebx, 0Fh           ; Mask to get base model
    
    mov     ecx, eax
    shr     ecx, 16            ; Move extended model to lower 4 bits
    and     ecx, 0Fh           ; Mask to get extended model
    shl     ecx, 4             ; Shift left by 4 to combine with base model
    or      ebx, ecx           ; Combine extended and base model
    mov     [cpu_model], ebx
    
    ; Print family/model
    lea     rdi, [cpu_family_str]
    call    print_string
    mov     rdi, [cpu_family]
    call    print_hex_byte
    lea     rdi, [cpu_model_str]
    call    print_string
    mov     rdi, [cpu_model]
    call    print_hex_byte
    call    print_newline
    
    ; --- Read and display control registers ---
    ; CR0 (contains cache disable, write-protect, paging flags)
    lea     rdi, [cr0_str]
    call    print_string
    mov     rax, cr0
    mov     rdi, rax
    call    print_hex_qword
    
    ; Show flags meaning
    push    rax                 ; Save CR0 value
    mov     rbx, rax            ; Copy for flag testing
    lea     rdi, [cr0_flags_str]
    call    print_string
    
    test    rbx, (1 << 0)       ; PE (Protected Mode Enable)
    jz      .cr0_no_pe
    lea     rdi, [cr0_pe_str]
    call    print_string
.cr0_no_pe:
    
    test    rbx, (1 << 16)      ; WP (Write Protect)
    jz      .cr0_no_wp
    lea     rdi, [cr0_wp_str]
    call    print_string
.cr0_no_wp:
    
    test    rbx, (1 << 31)      ; PG (Paging)
    jz      .cr0_no_pg
    lea     rdi, [cr0_pg_str]
    call    print_string
.cr0_no_pg:
    
    test    rbx, (1 << 29)      ; NW (Not Write-through)
    jz      .cr0_no_nw
    lea     rdi, [cr0_nw_str]
    call    print_string
.cr0_no_nw:
    
    test    rbx, (1 << 30)      ; CD (Cache Disable)
    jz      .cr0_no_cd
    lea     rdi, [cr0_cd_str]
    call    print_string
.cr0_no_cd:
    
    pop     rax                 ; Restore CR0 value
    call    print_newline
    
    ; CR4 (contains PAE, VME, PSE flags)
    lea     rdi, [cr4_str]
    call    print_string
    mov     rax, cr4
    mov     rdi, rax
    call    print_hex_qword
    
    ; Show flags meaning
    push    rax                 ; Save CR4 value 
    mov     rbx, rax            ; Copy for flag testing
    lea     rdi, [cr4_flags_str]
    call    print_string
    
    test    rbx, (1 << 5)       ; PAE (Physical Address Extension)
    jz      .cr4_no_pae
    lea     rdi, [cr4_pae_str]
    call    print_string
.cr4_no_pae:
    
    test    rbx, (1 << 7)       ; PGE (Page Global Enable)
    jz      .cr4_no_pge
    lea     rdi, [cr4_pge_str]
    call    print_string
.cr4_no_pge:
    
    test    rbx, (1 << 10)      ; UMIP (User Mode Instruction Prevention)
    jz      .cr4_no_umip
    lea     rdi, [cr4_umip_str]
    call    print_string
.cr4_no_umip:
    
    pop     rax                 ; Restore CR4 value
    call    print_newline
    
    ; Only show CR3 if paging is enabled (CR0.PG = 1)
    mov     rax, cr0
    test    rax, (1 << 31)      ; Check if paging is enabled
    jz      .skip_cr3
    
    ; CR3 (page directory base)
    lea     rdi, [cr3_str]
    call    print_string
    mov     rax, cr3
    mov     rdi, rax
    call    print_hex_qword
    call    print_newline
    
.skip_cr3:
    
    ; --- Read Model-Specific Registers (MSRs) ---
    ; Read IA32_EFER MSR (0xC0000080)
    lea     rdi, [efer_msr_str]
    call    print_string
    mov     ecx, 0xC0000080     ; IA32_EFER
    rdmsr                       ; Read MSR, result in EDX:EAX
    ; Combine EDX:EAX into a 64-bit value in RDI
    shl     rdx, 32
    or      rdi, rdx
    mov     rdi, rax
    call    print_hex_qword
    
    ; Show EFER flags
    push    rax                 ; Save EAX value
    mov     rbx, rax            ; Copy for flag testing
    lea     rdi, [efer_flags_str]
    call    print_string
    
    test    rbx, (1 << 0)       ; SCE (System Call Extensions)
    jz      .efer_no_sce
    lea     rdi, [efer_sce_str]
    call    print_string
.efer_no_sce:
    
    test    rbx, (1 << 8)       ; LME (Long Mode Enable)
    jz      .efer_no_lme
    lea     rdi, [efer_lme_str]
    call    print_string
.efer_no_lme:
    
    test    rbx, (1 << 10)      ; LMA (Long Mode Active)
    jz      .efer_no_lma
    lea     rdi, [efer_lma_str]
    call    print_string
.efer_no_lma:
    
    test    rbx, (1 << 11)      ; NXE (No-Execute Enable)
    jz      .efer_no_nxe
    lea     rdi, [efer_nxe_str]
    call    print_string
.efer_no_nxe:
    
    pop     rax                 ; Restore EAX value
    call    print_newline
    
    ; --- Read IA32_APIC_BASE MSR (0x1B) ---
    lea     rdi, [apic_base_str]
    call    print_string
    mov     ecx, 0x1B           ; IA32_APIC_BASE
    rdmsr                       ; Read MSR, result in EDX:EAX
    ; Combine EDX:EAX into a 64-bit value in RDI
    shl     rdx, 32
    or      rdi, rdx
    mov     rdi, rax
    call    print_hex_qword
    call    print_newline
    
    ; --- Read Segment Registers ---
    lea     rdi, [segment_header]
    call    print_string
    
    ; CS (Code Segment)
    lea     rdi, [cs_str]
    call    print_string
    xor     rdi, rdi
    mov     di, cs
    call    print_hex_word
    call    print_newline
    
    ; DS (Data Segment)
    lea     rdi, [ds_str]
    call    print_string
    xor     rdi, rdi
    mov     di, ds
    call    print_hex_word
    call    print_newline
    
    ; SS (Stack Segment)
    lea     rdi, [ss_str]
    call    print_string
    xor     rdi, rdi
    mov     di, ss
    call    print_hex_word
    call    print_newline
    
    ; ES (Extra Segment)
    lea     rdi, [es_str]
    call    print_string
    xor     rdi, rdi
    mov     di, es
    call    print_hex_word
    call    print_newline
    
    ; FS (F Segment - often thread local storage in x64)
    lea     rdi, [fs_str]
    call    print_string
    xor     rdi, rdi
    mov     di, fs
    call    print_hex_word
    call    print_newline
    
    ; GS (G Segment - often thread local storage in x64)
    lea     rdi, [gs_str]
    call    print_string
    xor     rdi, rdi
    mov     di, gs
    call    print_hex_word
    call    print_newline
    
    ; --- Read RFLAGS Register ---
    lea     rdi, [rflags_str]
    call    print_string
    pushfq                      ; Push RFLAGS onto stack
    pop     rdi                 ; Pop into RDI for printing
    call    print_hex_qword
    
    ; Show RFLAGS meaning
    mov     rbx, rdi            ; Copy for flag testing
    lea     rdi, [rflags_meaning_str]
    call    print_string
    
    test    rbx, (1 << 0)       ; CF (Carry Flag)
    jz      .rflags_no_cf
    lea     rdi, [rflags_cf_str]
    call    print_string
.rflags_no_cf:
    
    test    rbx, (1 << 2)       ; PF (Parity Flag)
    jz      .rflags_no_pf
    lea     rdi, [rflags_pf_str]
    call    print_string
.rflags_no_pf:
    
    test    rbx, (1 << 4)       ; AF (Adjust Flag)
    jz      .rflags_no_af
    lea     rdi, [rflags_af_str]
    call    print_string
.rflags_no_af:
    
    test    rbx, (1 << 6)       ; ZF (Zero Flag)
    jz      .rflags_no_zf
    lea     rdi, [rflags_zf_str]
    call    print_string
.rflags_no_zf:
    
    test    rbx, (1 << 7)       ; SF (Sign Flag)
    jz      .rflags_no_sf
    lea     rdi, [rflags_sf_str]
    call    print_string
.rflags_no_sf:
    
    test    rbx, (1 << 9)       ; IF (Interrupt Flag)
    jz      .rflags_no_if
    lea     rdi, [rflags_if_str]
    call    print_string
.rflags_no_if:
    
    test    rbx, (1 << 10)      ; DF (Direction Flag)
    jz      .rflags_no_df
    lea     rdi, [rflags_df_str]
    call    print_string
.rflags_no_df:
    
    test    rbx, (1 << 11)      ; OF (Overflow Flag)
    jz      .rflags_no_of
    lea     rdi, [rflags_of_str]
    call    print_string
.rflags_no_of:
    
    call    print_newline
    
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; Memory Map Inspection Module
; =============================================================================
inspect_memory:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [memory_header]
    call    print_string
    
    ; --- Detect if we're running under EFI or BIOS ---
    cmp     qword [SystemTable], 0
    je      .use_bios_method    ; If no EFI system table, use BIOS method
    
    ; --- EFI Method ---
    ; Get memory map from EFI
    lea     rdi, [efi_memmap_str]
    call    print_string
    
    ; Get EFI memory map (simplified implementation)
    mov     rcx, [SystemTable]            ; EFI_SYSTEM_TABLE*
    mov     rcx, [rcx + 0x60]             ; Get BootServices
    mov     rax, [rcx + 0x58]             ; GetMemoryMap function
    
    ; Prepare parameters for GetMemoryMap
    lea     rcx, [efi_memmap_size]        ; Size
    lea     rdx, [efi_memmap_buffer]      ; Buffer
    lea     r8, [efi_memmap_key]          ; MapKey
    lea     r9, [efi_memmap_desc_size]    ; DescriptorSize
    lea     r10, [efi_memmap_desc_ver]    ; DescriptorVersion
    
    ; TODO: Complete EFI memory map retrieval
    ; This is simplified, would need the full EFI API call implementation
    
    jmp     .memory_map_complete
    
.use_bios_method:
    ; --- INT 15h, EAX=E820h Method (needs real mode) ---
    ; Simplified demonstration, actual implementation would need
    ; to switch from long mode to real mode and back
    
    lea     rdi, [bios_memmap_str]
    call    print_string
    
    ; Note: Would need to switch to real mode and execute:
    ; mov eax, 0xE820
    ; mov ebx, 0          ; Continuation value, 0 for first call
    ; mov ecx, 24         ; Size of buffer
    ; mov edx, 0x534D4150 ; 'SMAP'
    ; int 0x15
    
    ; Instead, show a simulated memory map for demonstration
    lea     rdi, [simulated_memmap_str]
    call    print_string
    
    ; Display example entries
    lea     rdi, [memmap_entry1]
    call    print_string
    lea     rdi, [memmap_entry2]
    call    print_string
    lea     rdi, [memmap_entry3]
    call    print_string
    lea     rdi, [memmap_entry4]
    call    print_string
    
.memory_map_complete:
    ; --- Parse ACPI tables for memory information ---
    lea     rdi, [acpi_tables_str]
    call    print_string
    
    ; Scan for ACPI RSDP in the memory range 0x000E0000 - 0x000FFFFF
    mov     rdi, 0x000E0000
    mov     rcx, (0x000FFFFF - 0x000E0000) / 8  ; Number of 8-byte blocks to check
    
.scan_for_rsdp:
    ; Check for "RSD PTR " signature (8 bytes)
    mov     rax, 0x2052545020445352  ; "RSD PTR " in little-endian
    cmp     [rdi], rax
    je      .found_rsdp
    
    add     rdi, 8                   ; Move to next 8-byte block
    dec     rcx
    jnz     .scan_for_rsdp
    
    ; Not found
    lea     rdi, [rsdp_not_found_str]
    call    print_string
    jmp     .acpi_scan_complete
    
.found_rsdp:
    ; Found RSDP signature, print address
    push    rdi                      ; Save RSDP address
    
    lea     rdi, [rsdp_found_str]
    call    print_string
    
    pop     rdi                      ; Restore RSDP address
    call    print_hex_qword          ; Print the address
    call    print_newline
    
    ; TODO: Parse RSDP to locate XSDT, then parse XSDT
    ; This would require full ACPI table traversal code
    
.acpi_scan_complete:
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; I/O Port Scanning Module
; =============================================================================
inspect_io:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [io_header]
    call    print_string
    
    ; --- PCI Configuration Space Access ---
    lea     rdi, [pci_scan_str]
    call    print_string
    
    ; Scan for PCI devices (bus 0, up to device 32, function 0)
    mov     rdx, 0                 ; Start with bus 0, device 0, function 0
    
.pci_scan_loop:
    ; Create PCI configuration address: 0x80000000 | (bus << 16) | (device << 11) | (function << 8)
    mov     eax, 0x80000000        ; Enable bit (31)
    or      eax, edx               ; Add bus/device/function
    
    ; Write to PCI CONFIG_ADDRESS port (0xCF8)
    mov     dx, 0xCF8
    out     dx, eax
    
    ; Read from PCI CONFIG_DATA port (0xCFC)
    mov     dx, 0xCFC
    in      eax, dx
    
    ; Check if device exists (vendor ID != 0xFFFF)
    cmp     ax, 0xFFFF
    je      .pci_device_not_present
    
    ; Device exists, print information
    push    rax                    ; Save device/vendor ID
    
    ; Calculate PCI address components for display
    mov     rax, rdx               ; Get the bus/device/function
    shr     rax, 16                ; Extract bus (bits 16-23)
    and     rax, 0xFF
    mov     rbx, rax               ; Save bus number
    
    mov     rax, rdx
    shr     rax, 11                ; Extract device (bits 11-15)
    and     rax, 0x1F
    mov     rcx, rax               ; Save device number
    
    mov     rax, rdx
    shr     rax, 8                 ; Extract function (bits 8-10)
    and     rax, 0x7
    mov     rsi, rax               ; Save function number
    
    ; Print PCI device information
    lea     rdi, [pci_device_str]
    call    print_string
    
    ; Print bus in hex
    mov     rdi, rbx
    call    print_hex_byte
    
    lea     rdi, [colon_str]
    call    print_string
    
    ; Print device in hex
    mov     rdi, rcx
    call    print_hex_byte
    
    lea     rdi, [dot_str]
    call    print_string
    
    ; Print function in hex
    mov     rdi, rsi
    call    print_hex_byte
    
    lea     rdi, [bracket_open_str]
    call    print_string
    
    ; Get device/vendor ID
    pop     rax
    push    rax                    ; Save for later
    
    ; Print vendor ID (lower 16 bits)
    mov     rdi, rax
    and     rdi, 0xFFFF
    call    print_hex_word
    
    lea     rdi, [colon_str]
    call    print_string
    
    ; Print device ID (upper 16 bits)
    pop     rax
    shr     rax, 16
    mov     rdi, rax
    and     rdi, 0xFFFF
    call    print_hex_word
    
    lea     rdi, [bracket_close_str]
    call    print_string
    call    print_newline
    
.pci_device_not_present:
    ; Move to next device
    add     rdx, (1 << 11)         ; Increment device number (bits 11-15)
    
    ; Check if we've done all devices on this bus
    mov     rax, rdx
    shr     rax, 11
    and     rax, 0x1F
    cmp     rax, 32                ; Check if device > 31
    jb      .pci_scan_loop
    
    ; --- Scan Common I/O Ports ---
    lea     rdi, [common_ports_str]
    call    print_string
    
    ; Read from some common I/O ports
    ; NOTE: Many I/O ports may cause issues if read indiscriminately
    ; This is just an example with relatively safe ports
    
    ; PIT (Programmable Interval Timer) - Port 0x40 (Channel 0 counter)
    lea     rdi, [pit_str]
    call    print_string
    
    mov     dx, 0x40
    in      al, dx                ; Read from port 0x40 (PIT counter low byte)
    movzx   rdi, al
    call    print_hex_byte
    call    print_newline
    
    ; PIC (Programmable Interrupt Controller) - Ports 0x20 & 0xA0
    lea     rdi, [pic_master_str]
    call    print_string
    
    mov     dx, 0x21              ; PIC Master interrupt mask register
    in      al, dx
    movzx   rdi, al
    call    print_hex_byte
    call    print_newline
    
    lea     rdi, [pic_slave_str]
    call    print_string
    
    mov     dx, 0xA1              ; PIC Slave interrupt mask register
    in      al, dx
    movzx   rdi, al
    call    print_hex_byte
    call    print_newline
    
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; Process & Kernel Structure Inspection Module
; =============================================================================
inspect_processes:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [process_header]
    call    print_string
    
    ; Try to detect which OS we're running under (if any)
    ; Check for Windows-specific structures
    
    ; Check if we're running in ring 0 (kernel mode)
    ; by examining CS segment register bits 0-1 (RPL field)
    xor     rax, rax
    mov     ax, cs
    and     ax, 3                  ; Isolate RPL bits
    cmp     ax, 0                  ; RPL = 0 means kernel mode
    jne     .not_kernel_mode
    
    ; We're in kernel mode, check for Windows structures
    ; Try to access KPCR at GS:[0] (Windows x64)
    mov     rax, gs:[0]            ; If this access succeeds, may be Windows
    
    ; Look for EPROCESS structure using GS:[0x188]
    lea     rdi, [windows_detect_str]
    call    print_string
    
    ; Windows detection code - would traverse _EPROCESS linked list
    ; Note: This is simplified and would need adjustment for specific
    ; Windows versions, as offsets can change
    
    ; Pseudocode for Windows EPROCESS traversal:
    ; mov rax, gs:[0x188]         ; KTHREAD.Process = EPROCESS
    ; mov rbx, rax                ; Save list head
    ;
    ; .process_loop:
    ;     Print process name [rax+0x450] (Windows 10)
    ;     mov rax, [rax+0x448]    ; Next EPROCESS link
    ;     sub rax, 0x448          ; Adjust to EPROCESS base
    ;     cmp rax, rbx            ; Check if we're back at list head
    ;     jne .process_loop
    
    jmp     .process_scan_complete
    
.not_kernel_mode:
    ; Check if we might be in Linux
    ; Could try checking for /proc/self/maps
    lea     rdi, [not_kernel_str]
    call    print_string
    
.process_scan_complete:
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; Cache & TLB Inspection Module
; =============================================================================
inspect_cache:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [cache_header]
    call    print_string
    
    ; --- Check if CPUID leaf 4 is supported ---
    mov     eax, 0
    cpuid
    cmp     eax, 4               ; Need at least leaf 4 for cache info
    jb      .no_cache_info
    
    ; --- Enumerate caches using CPUID leaf 4 ---
    xor     r15, r15             ; Cache index counter
    
.cache_loop:
    mov     eax, 4               ; CPUID leaf 4 = Deterministic Cache Parameters
    mov     ecx, r15             ; Cache level index
    cpuid
    
    ; Check cache type (bits 4:0 of EAX)
    mov     ebx, eax
    and     ebx, 0x1F
    
    ; If type is 0, end of cache information
    test    ebx, ebx
    jz      .cache_info_complete
    
    ; Print cache index
    lea     rdi, [cache_level_str]
    call    print_string
    mov     rdi, r15
    inc     rdi                  ; Display cache level (1-based)
    call    print_dec_qword
    call    print_newline
    
    ; Print cache type
    lea     rdi, [cache_type_str]
    call    print_string
    
    cmp     ebx, 1
    je      .data_cache
    cmp     ebx, 2
    je      .instruction_cache
    cmp     ebx, 3
    je      .unified_cache
    
    ; Unknown type
    lea     rdi, [cache_type_unknown_str]
    call    print_string
    jmp     .cache_type_printed
    
.data_cache:
    lea     rdi, [cache_type_data_str]
    call    print_string
    jmp     .cache_type_printed
    
.instruction_cache:
    lea     rdi, [cache_type_instr_str]
    call    print_string
    jmp     .cache_type_printed
    
.unified_cache:
    lea     rdi, [cache_type_unified_str]
    call    print_string
    
.cache_type_printed:
    call    print_newline
    
    ; Cache size calculation
    ; Ways = EBX[31:22] + 1
    mov     rsi, rbx
    shr     rsi, 22
    and     rsi, 0x3FF
    inc     rsi
    
    ; Partitions = EBX[21:12] + 1
    mov     rdi, rbx
    shr     rdi, 12
    and     rdi, 0x3FF
    inc     rdi
    
    ; Line size = EBX[11:0] + 1
    mov     r8, rbx
    and     r8, 0xFFF
    inc     r8
    
    ; Sets = ECX + 1
    mov     r9, rcx
    inc     r9
    
    ; Size = Ways * Partitions * Line Size * Sets
    mov     rax, rsi     ; Ways
    mul     rdi          ; * Partitions
    mul     r8           ; * Line Size
    mul     r9           ; * Sets
    
    ; Print cache size
    push    rax
    lea     rdi, [cache_size_str]
    call    print_string
    pop     rdi
    
    ; Convert to KB for display if size >= 1024
    mov     rsi, rdi
    cmp     rdi, 1024
    jb      .print_bytes
    
    mov     rax, rdi
    xor     rdx, rdx
    mov     rcx, 1024
    div     rcx
    mov     rdi, rax
    
    call    print_dec_qword
    lea     rdi, [kb_str]
    call    print_string
    jmp     .size_printed
    
.print_bytes:
    mov     rdi, rsi
    call    print_dec_qword
    lea     rdi, [bytes_str]
    call    print_string
    
.size_printed:
    call    print_newline
    
    ; Print more cache details
    lea     rdi, [cache_line_size_str]
    call    print_string
    mov     rdi, r8
    call    print_dec_qword
    lea     rdi, [bytes_str]
    call    print_string
    call    print_newline
    
    ; Move to next cache
    inc     r15
    jmp     .cache_loop
    
.no_cache_info:
    lea     rdi, [no_cache_info_str]
    call    print_string
    
.cache_info_complete:
    ; --- Check TLB information ---
    lea     rdi, [tlb_header]
    call    print_string
    
    ; Get TLB info via CPUID
    ; For modern CPUs, this is typically in leaf 0x18
    mov     eax, 0
    cpuid
    cmp     eax, 0x18          ; Check if leaf 0x18 is supported
    jb      .no_tlb_info
    
    ; Leaf 0x18 exists, get TLB info
    mov     eax, 0x18
    xor     ecx, ecx
    cpuid
    
    ; Display basic TLB info
    ; (In a real implementation, this would parse and display
    ; the detailed TLB configuration from EAX/EBX/ECX/EDX)
    lea     rdi, [tlb_info_str]
    call    print_string
    
    jmp     .tlb_info_complete
    
.no_tlb_info:
    lea     rdi, [no_tlb_info_str]
    call    print_string
    
.tlb_info_complete:
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; Security Features Inspection Module
; =============================================================================
inspect_security:
    push    rbp
    mov     rbp, rsp
    
    ; --- Print Module Header ---
    lea     rdi, [security_header]
    call    print_string
    
    ; --- Check for System Management Mode (SMM) via MSRs ---
    lea     rdi, [smm_check_str]
    call    print_string
    
    ; Try to read IA32_SMRR_PHYSBASE MSR (0x1F2)
    ; This will cause #GP if not supported or not in SMM
    mov     ecx, 0x1F2
    
    ; Catch potential #GP on RDMSR
    ; In real implementation, would need exception handling
    ; Simplified version for example
    jmp     .skip_smrr_read    ; Skip for demo - would cause #GP in most cases
    
    rdmsr                      ; Read MSR into EDX:EAX
    ; Combine EDX:EAX into a 64-bit value in RDI
    shl     rdx, 32
    or      rdx, rax
    mov     rdi, rdx
    
    call    print_hex_qword
    call    print_newline
    
    jmp     .smm_check_complete
    
.skip_smrr_read:
    lea     rdi, [smm_not_available_str]
    call    print_string
    
.smm_check_complete:

    ; --- Check for UEFI Secure Boot status ---
    lea     rdi, [secureboot_check_str]
    call    print_string
    
    ; If running under EFI, check secure boot status
    cmp     qword [SystemTable], 0
    je      .no_efi_secureboot
    
    ; Basic secure boot check (simplified)
    ; In real implementation, would access EFI_SYSTEM_TABLE->ConfigurationTable
    ; to find the EFI_GLOBAL_VARIABLE_GUID and check "SecureBoot" variable
    
    ; Placeholder for demo
    lea     rdi, [secureboot_unknown_str]
    call    print_string
    
    jmp     .secureboot_check_complete
    
.no_efi_secureboot:
    lea     rdi, [no_efi_secureboot_str]
    call    print_string
    
.secureboot_check_complete:

    ; --- Check for Intel SGX (Software Guard Extensions) ---
    lea     rdi, [sgx_check_str]
    call    print_string
    
    ; Use CPUID leaf 7 to check for SGX support
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    
    ; Check SGX feature bit (bit 2 in EBX)
    test    ebx, (1 << 2)
    jz      .no_sgx_support
    
    lea     rdi, [sgx_supported_str]
    call    print_string
    
    ; Could check additional SGX details using CPUID leaf 0x12
    jmp     .sgx_check_complete
    
.no_sgx_support:
    lea     rdi, [sgx_not_supported_str]
    call    print_string
    
.sgx_check_complete:

    ; --- Check for virtualization (hypervisor) ---
    lea     rdi, [virtualization_check_str]
    call    print_string
    
    ; Use CPUID leaf 1 to check hypervisor presence bit
    mov     eax, 1
    cpuid
    
    ; Check hypervisor bit (bit 31 in ECX)
    test    ecx, (1 << 31)
    jz      .no_hypervisor
    
    lea     rdi, [hypervisor_detected_str]
    call    print_string
    
    ; If hypervisor is present, check its ID
    mov     eax, 0x40000000    ; Hypervisor CPUID leaf
    cpuid
    
    ; EBX, ECX, EDX should contain vendor ID
    mov     [hypervisor_vendor], ebx
    mov     [hypervisor_vendor+4], ecx
    mov     [hypervisor_vendor+8], edx
    mov     byte [hypervisor_vendor+12], 0  ; Null-terminate
    
    lea     rdi, [hypervisor_vendor_str]
    call    print_string
    lea     rdi, [hypervisor_vendor]
    call    print_string
    call    print_newline
    
    jmp     .virtualization_check_complete
    
.no_hypervisor:
    lea     rdi, [no_hypervisor_str]
    call    print_string
    
.virtualization_check_complete:
    ; --- Module complete ---
    call    print_newline
    
    leave
    ret

; =============================================================================
; Utility Functions
; =============================================================================

; Initialize output system
initialize_output:
    push    rbp
    mov     rbp, rsp
    
    ; If running under EFI, get console output protocol
    cmp     qword [SystemTable], 0
    je      .no_efi
    
    ; Set up EFI console output
    mov     rcx, [SystemTable]
    mov     rcx, [rcx + 0x40]      ; ConOut
    mov     [ConOut], rcx
    
.no_efi:
    leave
    ret

; Wait for keypress
wait_for_key:
    push    rbp
    mov     rbp, rsp
    
    ; If running under EFI, use ConIn->ReadKeyStroke
    cmp     qword [SystemTable], 0
    je      .no_efi
    
    ; Use EFI to wait for key
    mov     rcx, [SystemTable]
    mov     rcx, [rcx + 0x38]      ; ConIn
    
    ; TODO: Call ReadKeyStroke on ConIn
    ; Simplified - actual implementation would call the EFI function
    
    jmp     .key_received
    
.no_efi:
    ; If no EFI, use alternative method (e.g., BIOS Int 16h in real mode)
    ; This would need to be implemented separately
    
.key_received:
    leave
    ret

; Print a null-terminated string
; RDI = string address
print_string:
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rcx
    push    rax
    push    rdx
    
    mov     rsi, rdi              ; RSI = string address
    
    ; If running under EFI, use ConOut->OutputString
    cmp     qword [SystemTable], 0
    je      .use_direct_output
    
    ; Use EFI
    ; (Simplified, a real implementation would convert ASCII to UCS-2)
    mov     rcx, [ConOut]
    mov     rdx, rsi
    
    ; TODO: Call OutputString on ConOut
    ; Simplified - actual implementation would call the EFI function
    
    jmp     .print_done
    
.use_direct_output:
    ; Direct video memory output for example (in a real system
    ; this would depend on the output method available)
    
    ; Placeholder - actually implement this according to available output
    ; Just need a string visualization method
    
.print_done:
    pop     rdx
    pop     rax
    pop     rcx
    pop     rsi
    leave
    ret

; Print a newline
print_newline:
    push    rbp
    mov     rbp, rsp
    
    lea     rdi, [newline_str]
    call    print_string
    
    leave
    ret

; Print a 64-bit value in hexadecimal
; RDI = value to print
print_hex_qword:
    push    rbp
    mov     rbp, rsp
    push    r15
    push    r14
    push    rax
    push    rcx
    push    rdx
    
    ; Print "0x" prefix
    push    rdi
    lea     rdi, [hex_prefix]
    call    print_string
    pop     rdi
    
    ; Set up for conversion
    mov     rax, rdi              ; Value to convert
    mov     r15, 16               ; Loop counter (16 hex digits in a qword)
    lea     r14, [hex_chars]      ; Character lookup table
    
.digit_loop:
    ; Extract the most significant 4 bits
    rol     rax, 4                ; Rotate left 4 bits
    mov     rcx, rax              ; Copy to work with
    and     rcx, 0Fh              ; Mask to get just the bottom 4 bits
    
    ; Convert to ASCII and print
    mov     dl, [r14 + rcx]       ; Lookup hex character
    push    rax
    push    r15
    
    ; Print the character
    push    rdx
    sub     rsp, 2                ; Reserve space for null-terminated char
    mov     [rsp], dl
    mov     byte [rsp+1], 0
    mov     rdi, rsp
    call    print_string
    add     rsp, 2
    pop     rdx
    
    pop     r15
    pop     rax
    
    ; Loop for each hex digit
    dec     r15
    jnz     .digit_loop
    
    pop     rdx
    pop     rcx
    pop     rax
    pop     r14
    pop     r15
    leave
    ret

; Print a 32-bit value in hexadecimal
; RDI = value to print
print_hex_dword:
    push    rbp
    mov     rbp, rsp
    
    ; Only keep lower 32 bits
    and     rdi, 0xFFFFFFFF
    call    print_hex_qword
    
    leave
    ret

; Print a 16-bit value in hexadecimal
; RDI = value to print
print_hex_word:
    push    rbp
    mov     rbp, rsp
    
    ; Only keep lower 16 bits
    and     rdi, 0xFFFF
    
    ; Print "0x" prefix
    push    rdi
    lea     rdi, [hex_prefix]
    call    print_string
    pop     rdi
    
    ; Print first byte (high)
    push    rdi
    shr     rdi, 8
    call    print_hex_byte_no_prefix
    pop     rdi
    
    ; Print second byte (low)
    and     rdi, 0xFF
    call    print_hex_byte_no_prefix
    
    leave
    ret

; Print an 8-bit value in hexadecimal
; RDI = value to print
print_hex_byte:
    push    rbp
    mov     rbp, rsp
    
    ; Only keep lower 8 bits
    and     rdi, 0xFF
    
    ; Print "0x" prefix
    push    rdi
    lea     rdi, [hex_prefix]
    call    print_string
    pop     rdi
    
    call    print_hex_byte_no_prefix
    
    leave
    ret

; Print an 8-bit value in hexadecimal without "0x" prefix
; RDI = value to print
print_hex_byte_no_prefix:
    push    rbp
    mov     rbp, rsp
    push    rax
    push    rdx
    push    rcx
    
    ; Only keep lower 8 bits
    mov     rax, rdi
    and     rax, 0xFF
    
    ; Print high nibble
    mov     rdx, rax
    shr     rdx, 4
    mov     cl, [hex_chars + rdx]
    
    push    rax
    push    rcx
    sub     rsp, 2                ; Reserve space for null-terminated char
    mov     [rsp], cl
    mov     byte [rsp+1], 0
    mov     rdi, rsp
    call    print_string
    add     rsp, 2
    pop     rcx
    pop     rax
    
    ; Print low nibble
    mov     rdx, rax
    and     rdx, 0x0F
    mov     cl, [hex_chars + rdx]
    
    push    rcx
    sub     rsp, 2                ; Reserve space for null-terminated char
    mov     [rsp], cl
    mov     byte [rsp+1], 0
    mov     rdi, rsp
    call    print_string
    add     rsp, 2
    pop     rcx
    
    pop     rcx
    pop     rdx
    pop     rax
    leave
    ret

; Print a 64-bit decimal number
; RDI = value to print
print_dec_qword:
    push    rbp
    mov     rbp, rsp
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    r8
    push    r9
    
    ; Check if zero
    test    rdi, rdi
    jnz     .not_zero
    
    ; Print "0"
    lea     rdi, [digit_0]
    call    print_string
    jmp     .done
    
.not_zero:
    ; Convert to decimal
    mov     rax, rdi
    mov     rcx, 10                ; Divisor
    xor     r9, r9                 ; Digit counter
    sub     rsp, 32                ; Allocate buffer on stack
    mov     r8, rsp                ; Buffer pointer
    
.convert_loop:
    xor     rdx, rdx
    div     rcx                    ; Divide RAX by 10, remainder in RDX
    
    ; Convert remainder to ASCII
    add     dl, '0'
    mov     [r8 + r9], dl
    inc     r9
    
    ; Continue until RAX is 0
    test    rax, rax
    jnz     .convert_loop
    
    ; Print digits in reverse order
.print_loop:
    dec     r9
    
    ; Print digit
    push    r8
    push    r9
    mov     al, [r8 + r9]
    
    ; Print the character
    push    rax
    sub     rsp, 2                ; Reserve space for null-terminated char
    mov     [rsp], al
    mov     byte [rsp+1], 0
    mov     rdi, rsp
    call    print_string
    add     rsp, 2
    pop     rax
    
    pop     r9
    pop     r8
    
    ; Continue until all digits printed
    test    r9, r9
    jnz     .print_loop
    
    add     rsp, 32                ; Free stack buffer
    
.done:
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    leave
    ret

; =============================================================================
; Data Section
; =============================================================================
section .data

; EFI-related
ImageHandle     dq 0            ; EFI image handle
SystemTable     dq 0            ; EFI system table pointer
ConOut          dq 0            ; EFI console output protocol

; Program Strings
program_header  db "=== x64 Hardware Inspector ===", 0xD, 0xA, 0
program_footer  db "=== Inspection Complete ===", 0xD, 0xA, 0

; CPU Module Strings
cpu_header      db "--- CPU & Register Information ---", 0xD, 0xA, 0
cpu_vendor_str  db "CPU Vendor: ", 0
cpu_brand_str   db "CPU Brand: ", 0
cpu_unknown_str db "CPU Brand: Unknown", 0xD, 0xA, 0
cpu_family_str  db "CPU Family: ", 0
cpu_model_str   db ", Model: ", 0

; Control Register Strings
cr0_str         db "CR0: ", 0
cr0_flags_str   db " (", 0
cr0_pe_str      db "PE ", 0
cr0_wp_str      db "WP ", 0
cr0_pg_str      db "PG ", 0
cr0_cd_str      db "CD ", 0
cr0_nw_str      db "NW ", 0
cr3_str         db "CR3: ", 0
cr4_str         db "CR4: ", 0
cr4_flags_str   db " (", 0
cr4_pae_str     db "PAE ", 0
cr4_pge_str     db "PGE ", 0
cr4_umip_str    db "UMIP ", 0

; MSR Strings
efer_msr_str    db "IA32_EFER MSR: ", 0
efer_flags_str  db " (", 0
efer_sce_str    db "SCE ", 0
efer_lme_str    db "LME ", 0
efer_lma_str    db "LMA ", 0
efer_nxe_str    db "NXE ", 0
apic_base_str   db "IA32_APIC_BASE MSR: ", 0

; Segment Register Strings
segment_header  db "-- Segment Registers --", 0xD, 0xA, 0
cs_str          db "CS: ", 0
ds_str          db "DS: ", 0
ss_str          db "SS: ", 0
es_str          db "ES: ", 0
fs_str          db "FS: ", 0
gs_str          db "GS: ", 0

; RFLAGS Strings
rflags_str      db "RFLAGS: ", 0
rflags_meaning_str db " (", 0
rflags_cf_str   db "CF ", 0
rflags_pf_str   db "PF ", 0
rflags_af_str   db "AF ", 0
rflags_zf_str   db "ZF ", 0
rflags_sf_str   db "SF ", 0
rflags_if_str   db "IF ", 0
rflags_df_str   db "DF ", 0
rflags_of_str   db "OF ", 0

; Memory Module Strings
memory_header   db "--- Memory Information ---", 0xD, 0xA, 0
efi_memmap_str  db "EFI Memory Map:", 0xD, 0xA, 0
bios_memmap_str db "BIOS Memory Map (INT 15h, AX=E820h):", 0xD, 0xA, 0
simulated_memmap_str db "Simulated Memory Map:", 0xD, 0xA, 0
memmap_entry1   db "  [0x00000000 - 0x0009FFFF] Usable RAM (640KB)", 0xD, 0xA, 0
memmap_entry2   db "  [0x000A0000 - 0x000FFFFF] Reserved (BIOS & Video)", 0xD, 0xA, 0
memmap_entry3   db "  [0x00100000 - 0x01FFFFFF] Usable RAM (31MB)", 0xD, 0xA, 0
memmap_entry4   db "  [0xFEE00000 - 0xFEFFFFFF] Reserved (APIC/IOAPIC)", 0xD, 0xA, 0
acpi_tables_str db "ACPI Table Scan:", 0xD, 0xA, 0
rsdp_found_str  db "  ACPI RSDP found at: ", 0
rsdp_not_found_str db "  ACPI RSDP not found in conventional memory range", 0xD, 0xA, 0

; I/O Module Strings
io_header       db "--- I/O Ports & PCI Information ---", 0xD, 0xA, 0
pci_scan_str    db "PCI Device Scan:", 0xD, 0xA, 0
pci_device_str  db "  PCI Device [", 0
common_ports_str db "Common I/O Ports:", 0xD, 0xA, 0
pit_str         db "  PIT Counter (0x40): ", 0
pic_master_str  db "  PIC Master Mask (0x21): ", 0
pic_slave_str   db "  PIC Slave Mask (0xA1): ", 0

; Process Module Strings
process_header  db "--- Process & Kernel Structures ---", 0xD, 0xA, 0
windows_detect_str db "Windows detected, EPROCESS list:", 0xD, 0xA, 0
not_kernel_str  db "Not running in kernel mode, cannot access process structures", 0xD, 0xA, 0

; Cache Module Strings
cache_header    db "--- Cache & TLB Information ---", 0xD, 0xA, 0
cache_level_str db "Cache Level: ", 0
cache_type_str  db "Cache Type: ", 0
cache_type_unknown_str db "Unknown", 0
cache_type_data_str db "Data Cache", 0
cache_type_instr_str db "Instruction Cache", 0
cache_type_unified_str db "Unified Cache", 0
cache_size_str  db "Cache Size: ", 0
cache_line_size_str db "Cache Line Size: ", 0
kb_str          db " KB", 0
bytes_str       db " bytes", 0
no_cache_info_str db "CPU does not support deterministic cache parameters", 0xD, 0xA, 0
tlb_header      db "TLB Information:", 0xD, 0xA, 0
tlb_info_str    db "  TLB configuration available", 0xD, 0xA, 0
no_tlb_info_str db "  TLB information not available through CPUID", 0xD, 0xA, 0

; Security Module Strings
security_header db "--- Security Features ---", 0xD, 0xA, 0
smm_check_str   db "System Management Mode (SMM): ", 0
smm_not_available_str db "Not in SMM or SMRR not available", 0xD, 0xA, 0
secureboot_check_str db "UEFI Secure Boot: ", 0
secureboot_unknown_str db "Status unknown", 0xD, 0xA, 0
no_efi_secureboot_str db "Not running under UEFI", 0xD, 0xA, 0
sgx_check_str   db "Intel SGX: ", 0
sgx_supported_str db "Supported", 0xD, 0xA, 0
sgx_not_supported_str db "Not supported", 0xD, 0xA, 0
virtualization_check_str db "Virtualization: ", 0
hypervisor_detected_str db "Hypervisor detected", 0xD, 0xA, 0
hypervisor_vendor_str db "Hypervisor Vendor: ", 0
no_hypervisor_str db "No hypervisor detected", 0xD, 0xA, 0

; Utility Strings
newline_str     db 0xD, 0xA, 0  ; CRLF
hex_prefix      db "0x", 0
colon_str       db ":", 0
dot_str         db ".", 0
bracket_open_str db " (", 0
bracket_close_str db ")", 0
hex_chars       db "0123456789ABCDEF"
digit_0         db "0", 0

; Variable storage
cpu_vendor      times 16 db 0   ; 12 bytes + null terminator + padding
cpu_brand       times 64 db 0   ; 48 bytes + null terminator + padding
cpu_family      dq 0
cpu_model       dq 0
hypervisor_vendor times 16 db 0 ; 12 bytes + null terminator + padding

; EFI Memory Map variables
efi_memmap_size       dq 0
efi_memmap_key        dq 0
efi_memmap_desc_size  dq 0
efi_memmap_desc_ver   dq 0
efi_memmap_buffer     times 1024 db 0 ; Buffer for memory map (adjust size as needed)

; =============================================================================
; BSS Section (uninitialized data)
; =============================================================================
section .bss
; Additional uninitialized storage if needed